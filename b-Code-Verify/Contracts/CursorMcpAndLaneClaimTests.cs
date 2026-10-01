using System.Text.Json.Nodes;
using HistoryPortunus.Mcp;
using HistoryPortunus.Web;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Modules;
using Xunit;

namespace HistoryPortunus.Contracts;

public sealed class CursorMcpAndLaneClaimTests
{
    [Fact]
    public void CursorConfigKeepsOtherServersAndStripsAuthorization()
    {
        var file = Path.Combine(Path.GetTempPath(), "portunus-cursor-mcp-" + Guid.NewGuid().ToString("N"), "mcp.json");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, """
            {
              "mcpServers": {
                "history-vulcan": {
                  "url": "http://127.0.0.1:59095/mcp",
                  "headers": { "Authorization": "Bearer leftover" }
                },
                "other": { "url": "http://127.0.0.1:9/mcp" }
              }
            }
            """);

        try
        {
            var log = new CaptureLog();
            CursorMcpConfig.Sync(8777, log, file);
            var root = JsonNode.Parse(File.ReadAllText(file))!.AsObject();
            var vulcan = root["mcpServers"]!["history-vulcan"]!.AsObject();
            Assert.Equal("http://127.0.0.1:8777/mcp", vulcan["url"]!.GetValue<string>());
            Assert.Null(vulcan["headers"]);
            Assert.Equal(
                "http://127.0.0.1:9/mcp",
                root["mcpServers"]!["other"]!["url"]!.GetValue<string>());
            Assert.Contains(log.Entries, entry => entry.Message.Contains("无鉴权头", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(file)!, recursive: true);
        }
    }

    // 1.1.0：按宿主给的运行方式判断，不再读进程名与进程参数（宿主 6.0.0 统一契约）。
    [Theory]
    [InlineData(HostRunMode.Service, true)]
    [InlineData(HostRunMode.OfflineCli, false)]
    [InlineData(HostRunMode.Probe, false)]
    public void OnlyTheServiceHostOpensListeners(HostRunMode runMode, bool expected)
        => Assert.Equal(expected, HostLaneClaim.ShouldOpenListeners(runMode));

    [Fact]
    public void UnsetPolicyIsStandard()
    {
        var settings = new MemorySettings();
        Assert.Equal("standard", McpSettingKeys.ResolvePolicy(settings));
        settings.Set(McpSettingKeys.Policy, "readonly");
        Assert.Equal("readonly", McpSettingKeys.ResolvePolicy(settings));
    }

    private sealed class CaptureLog : IModuleLog
    {
        public List<ShellLogEntry> Entries { get; } = [];
        public void Log(ShellLogLevel level, string category, string message)
            => Entries.Add(new ShellLogEntry(DateTime.Now, level, category, message));
        public IReadOnlyList<ShellLogEntry> Snapshot() => Entries;
    }

    private sealed class MemorySettings : ISettingsService
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
        public string? Get(string key) => _values.GetValueOrDefault(key);
        public int GetInt(string key, int fallback) => int.TryParse(Get(key), out var value) ? value : fallback;
        public void Set(string key, string value) => _values[key] = value;
        public IReadOnlyList<KeyValuePair<string, string>> All() => _values.ToList();
    }
}
