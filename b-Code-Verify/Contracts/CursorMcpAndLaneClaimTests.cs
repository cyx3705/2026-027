using System.Text.Json.Nodes;
using HistoryPortunus.Mcp;
using HistoryPortunus.Web;
using HistoryVulcan.Core.Logging;
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

    [Theory]
    [InlineData("HistoryVulcan.Cli", new string[] { }, false)]
    [InlineData("HistoryVulcan", new[] { "--cli" }, false)]
    [InlineData("HistoryVulcan", new[] { "--export-command-manual" }, false)]
    [InlineData("HistoryVulcan", new string[] { }, true)]
    [InlineData("testhost", new string[] { }, true)]
    public void OnlyTheServiceHostOpensListeners(string processName, string[] arguments, bool expected)
        => Assert.Equal(expected, HostLaneClaim.ShouldOpenListeners(processName, arguments));

    [Fact]
    public void UnsetPolicyIsStandard()
    {
        var settings = new MemorySettings();
        Assert.Equal("standard", McpSettingKeys.ResolvePolicy(settings));
        settings.Set(McpSettingKeys.Policy, "readonly");
        Assert.Equal("readonly", McpSettingKeys.ResolvePolicy(settings));
    }

    private sealed class CaptureLog : IShellLog
    {
        public List<ShellLogEntry> Entries { get; } = [];
        public void Log(ShellLogLevel level, string category, string message)
            => Entries.Add(new ShellLogEntry(DateTime.Now, level, category, message));
        public event EventHandler<ShellLogEntry>? EntryAdded { add { } remove { } }
        public IReadOnlyList<ShellLogEntry> Snapshot() => Entries;
    }

    private sealed class MemorySettings : HistoryVulcan.Core.Storage.ISettingsService
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
        public string? Get(string key) => _values.GetValueOrDefault(key);
        public int GetInt(string key, int fallback) => int.TryParse(Get(key), out var value) ? value : fallback;
        public void Set(string key, string value) => _values[key] = value;
        public IReadOnlyList<KeyValuePair<string, string>> All() => _values.ToList();
    }
}
