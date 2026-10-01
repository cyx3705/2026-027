using System.Diagnostics;
using System.Text.Json;
using HistoryVulcan.Core.Logging;

namespace HistoryPortunus;

/// <summary>Portunus 自己的扁平设置读写口（mcp.* / web.*）。</summary>
/// <remarks>
/// 1.1.0 之前借用宿主的 <c>ISettingsService</c>；宿主 6.0.0 起那是宿主内部类型，
/// 模块只能用契约程序集白名单里的类型，于是接口搬回本仓，形状不变。
/// </remarks>
public interface ISettingsService
{
    string? Get(string key);

    int GetInt(string key, int fallback);

    void Set(string key, string value);

    IReadOnlyList<KeyValuePair<string, string>> All();
}

/// <summary>网关对外自报的宿主身份：serverInfo 与默认端口派生用。</summary>
public sealed record HostIdentity(string Name, string Version);

/// <summary>模块自持的运行态：数据目录下的设置、治理库、审计与日志。</summary>
/// <remarks>
/// 1.1.0 起数据目录由宿主给（宿主 6.0.0 统一契约，<c>IModuleContext.Environment.DataDirectory</c>）。
/// 1.0.x 写在宿主数据根 <c>state\</c> 与 <c>service\</c> 下的旧文件已在宿主 6.0.0 切换时一次性搬过来，模块不再认旧布局。
/// </remarks>
internal static class PortunusRuntime
{
    /// <summary>宿主产品名。默认端口由 <c>&lt;名&gt;.service</c> 稳定派生，改一个字符端口就整体漂移。</summary>
    internal const string HostName = "HistoryVulcan";

    private static readonly object Gate = new();
    private static string? _root;
    private static ISettingsService? _settings;

    internal static string DataRoot => _root ?? throw new InvalidOperationException("Portunus 尚未接入宿主，数据目录未知。");

    internal static ISettingsService Settings
        => _settings ?? throw new InvalidOperationException("Portunus 尚未接入宿主，设置库未打开。");

    internal static IModuleLog Log { get; } = new FileLog();

    /// <summary>接入时由宿主给数据目录；同一目录重复接入（热重载）沿用已打开的设置库。</summary>
    internal static void Use(string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        var root = Path.GetFullPath(dataDirectory);
        lock (Gate)
        {
            if (string.Equals(_root, root, StringComparison.OrdinalIgnoreCase) && _settings != null)
                return;
            Directory.CreateDirectory(root);
            _root = root;
            _settings = new FileSettingsService(Path.Combine(root, "state", "portunus-settings.json"));
        }
    }

    private sealed class FileSettingsService(string path) : ISettingsService
    {
        private readonly object _gate = new();
        private Dictionary<string, string> _values = Load(path);

        public string? Get(string key)
        {
            lock (_gate)
                return _values.GetValueOrDefault(key);
        }

        public int GetInt(string key, int fallback)
            => int.TryParse(Get(key), out var value) ? value : fallback;

        public void Set(string key, string value)
        {
            lock (_gate)
            {
                _values[key] = value;
                var directory = Path.GetDirectoryName(path)!;
                Directory.CreateDirectory(directory);
                var temporary = path + ".tmp";
                File.WriteAllText(temporary, JsonSerializer.Serialize(_values));
                File.Move(temporary, path, overwrite: true);
            }
        }

        public IReadOnlyList<KeyValuePair<string, string>> All()
        {
            lock (_gate)
                return _values.ToList();
        }

        private static Dictionary<string, string> Load(string path)
        {
            var defaults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["mcp.autostart"] = "true",
                ["mcp.port"] = "8777",
                ["mcp.portretries"] = "0",
                ["mcp.policy"] = "standard",
                ["web.autostart"] = "true",
                ["web.port"] = "8938",
                ["web.portretries"] = "0",
            };
            try
            {
                if (!File.Exists(path))
                    return defaults;

                var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path));
                if (loaded == null)
                    return defaults;
                foreach (var pair in defaults)
                    loaded.TryAdd(pair.Key, pair.Value);
                return new Dictionary<string, string>(loaded, StringComparer.OrdinalIgnoreCase);
            }
            catch (JsonException)
            {
                return new(StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>写 Trace 与数据目录 <c>logs\</c> 的轻量日志；接入前只写 Trace。</summary>
    private sealed class FileLog : IModuleLog
    {
        public void Log(ShellLogLevel level, string category, string message)
        {
            Trace.WriteLine($"[HistoryPortunus:{category}] {message}");
            var root = _root;
            if (root == null)
                return;
            try
            {
                var directory = Path.Combine(root, "logs");
                Directory.CreateDirectory(directory);
                var line = $"{DateTime.Now:HH:mm:ss.fff} [{level}] [{category}] {message}{Environment.NewLine}";
                File.AppendAllText(Path.Combine(directory, $"portunus-{DateTime.Now:yyyyMMdd}.log"), line);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
