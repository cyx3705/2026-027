using System.Diagnostics;
using System.Text.Json;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Storage;

namespace HistoryPortunus;

/// <summary>Owns the transport state that HistoryVulcan 5.1 intentionally no longer exposes to modules.</summary>
internal static class PortunusRuntime
{
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HistoryVulcan");

    internal static string ApplicationRoot => Root;
    internal static ISettingsService Settings { get; } = new FileSettingsService(Path.Combine(Root, "state", "portunus-settings.json"));
    internal static IShellLog Log { get; } = new TraceShellLog();

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

    private sealed class TraceShellLog : IShellLog
    {
        private readonly List<ShellLogEntry> _entries = [];

        public event EventHandler<ShellLogEntry>? EntryAdded;

        public void Log(ShellLogLevel level, string category, string message)
        {
            var entry = new ShellLogEntry(DateTime.UtcNow, level, category, message);
            lock (_entries)
                _entries.Add(entry);
            Trace.WriteLine($"[HistoryPortunus:{category}] {message}");
            EntryAdded?.Invoke(this, entry);
        }

        public IReadOnlyList<ShellLogEntry> Snapshot()
        {
            lock (_entries)
                return _entries.ToList();
        }
    }
}
