using HistoryVulcan.Core;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Storage;
using HistoryPortunus.Mcp;
using Xunit;
using System.Net;
using System.Net.Sockets;

namespace HistoryPortunus.Contracts;

[Collection(TestCollections.Gateway)]
public sealed class McpGatewayPortTests
{
    [Fact]
    public void AutostartIsOffUntilExplicitlyEnabled()
    {
        using var fixture = Fixture.Create("AutostartDefault");

        // 装配网关不等于监听：没有显式开关时不得自动开端口。
        Assert.False(fixture.Gateway.AutostartEnabled);
        var (success, message) = fixture.Gateway.TryAutostart();
        Assert.True(success);
        Assert.False(fixture.Gateway.IsRunning);
        Assert.Contains("mcp.autostart=false", message, StringComparison.Ordinal);

        // 显式打开后才随宿主监听。
        fixture.Settings.Set(McpSettingKeys.Autostart, "true");
        Assert.True(fixture.Gateway.AutostartEnabled);
        Assert.True(fixture.Gateway.TryAutostart().Success);
        Assert.True(fixture.Gateway.IsRunning);
    }

    [Fact]
    public void ExplicitStartOpensThePortWithoutTouchingAutostart()
    {
        using var fixture = Fixture.Create("AutostartExplicitStart");

        Assert.True(fixture.Gateway.Start(null).Success);
        Assert.True(fixture.Gateway.IsRunning);
        // start 是本次会话的开关，不得偷偷把持久自启动也打开。
        Assert.False(fixture.Gateway.AutostartEnabled);
        Assert.Null(fixture.Settings.Get(McpSettingKeys.Autostart));
    }

    [Fact]
    public void DefaultPortIsDerivedPerApplication()
    {
        using var first = Fixture.Create("PortAppAlpha");
        using var second = Fixture.Create("PortAppBeta");

        Assert.True(first.Gateway.Start(null).Success);
        Assert.True(second.Gateway.Start(null).Success);
        Assert.NotEqual(first.Gateway.Port, second.Gateway.Port);
    }

    [Fact]
    public void UnconfiguredStartPersistsDerivedPort()
    {
        using var fixture = Fixture.Create("PersistDerivedPortApp");
        Assert.True(fixture.Gateway.Start(null).Success);
        Assert.Equal(
            fixture.Gateway.Port.ToString(),
            fixture.Settings.Get(McpSettingKeys.Port));
    }

    [Fact]
    public void OccupiedDerivedPortFailsWithoutWalking()
    {
        using var first = Fixture.Create("SamePortApp");
        using var second = Fixture.Create("SamePortApp");

        Assert.True(first.Gateway.Start(null).Success);
        var (success, message) = second.Gateway.Start(null);
        Assert.False(success);
        Assert.Contains("已固定", message, StringComparison.Ordinal);
        Assert.False(second.Gateway.IsRunning);
    }

    [Fact]
    public void ExplicitPortHasPriority()
    {
        using var fixture = Fixture.Create("ExplicitPortApp");
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        Assert.True(fixture.Gateway.Start(port).Success);
        Assert.Equal(port, fixture.Gateway.Port);
        Assert.Equal(port.ToString(), fixture.Settings.Get(McpSettingKeys.Port));
    }

    // 真实端口绑定：被占用时是快速失败而不是挂起，因此无需 Timeout
    // （xUnit 的 Timeout 只对 async 用例生效）。整轮卡住的可见性由
    // xunit.runner.json 的 longRunningTestSeconds 诊断承担。
    [Fact]
    public void OccupiedExplicitPortFailsWithoutRewritingSettings()
    {
        using var first = Fixture.Create("RetryPortOwner");
        using var second = Fixture.Create("RetryPortCandidate");
        var port = FreePort();
        Assert.True(first.Gateway.Start(port).Success);

        var (success, message) = second.Gateway.Start(port);
        Assert.False(success);
        Assert.Contains("已固定", message, StringComparison.Ordinal);
        Assert.Null(second.Settings.Get(McpSettingKeys.Port));
        Assert.Equal(0, second.Gateway.Port);
        Assert.True(first.Gateway.Stop().Success);
        Assert.Equal(0, first.Gateway.Port);
    }

    private sealed class Fixture : IDisposable
    {
        private Fixture(string root, MemorySettings settings, McpGateway gateway)
        {
            Root = root;
            Settings = settings;
            Gateway = gateway;
        }

        public string Root { get; }
        public MemorySettings Settings { get; }
        public McpGateway Gateway { get; }

        public static Fixture Create(string appName)
        {
            var root = Path.Combine(Path.GetTempPath(), "HistoryVulcan.Tests", Guid.NewGuid().ToString("N"));
            var settings = new MemorySettings();
            var log = new NullLog();
            var gateway = new McpGateway(
                () => null,
                settings,
                log,
                new NullAudit(),
                new PromptGovernanceStore(root, log),
                new HistoryVulcan.Core.ApplicationIdentity(appName, "3.0.0", "3.0.0", "3.0.0.0"));
            return new Fixture(root, settings, gateway);
        }

        public void Dispose()
        {
            Gateway.Dispose();
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class MemorySettings : ISettingsService
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

        public string? Get(string key) => _values.GetValueOrDefault(key);
        public int GetInt(string key, int fallback) => int.TryParse(Get(key), out var value) ? value : fallback;
        public void Set(string key, string value) => _values[key] = value;
        public IReadOnlyList<KeyValuePair<string, string>> All() => _values.ToList();
    }

    private sealed class NullAudit : IMcpAuditLog
    {
        public void RecordMcp(string client, string tool, string arguments, string result, long elapsedMs) { }
    }

    private sealed class NullLog : IShellLog
    {
        public void Log(ShellLogLevel level, string category, string message) { }
        public event EventHandler<ShellLogEntry>? EntryAdded { add { } remove { } }
        public IReadOnlyList<ShellLogEntry> Snapshot() => [];
    }
}
