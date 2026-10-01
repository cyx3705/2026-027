using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryPortunus.Mcp;
using Xunit;

namespace HistoryPortunus.Contracts;

/// <summary>
/// DEC-PORT-006：mcp.policy / mcp.confirm 只存在于 Portunus 自己的设置库，
/// 唯一写口是 <c>portunus.mcp.config</c>；所有提示语都必须指向它，且照做即生效。
/// </summary>
[Collection(TestCollections.Gateway)]
public sealed class McpConfigCommandTests
{
    [Fact]
    public void ConfigCommandIsAskLevelAndHiddenFromMcp()
    {
        using var fixture = new Fixture();
        Assert.True(fixture.Registry.TryGet("portunus.mcp.config", out var descriptor));
        Assert.Equal(CommandLevel.Ask, descriptor.Level);
        Assert.False(descriptor.Readonly);
        Assert.Equal("portunus", descriptor.Domain);
        Assert.Equal("mcp", descriptor.CommandClass);
        Assert.False(string.IsNullOrWhiteSpace(descriptor.HiddenReason));
        Assert.Null(new CommandSchemaExporter(fixture.Catalog).Find("portunus.mcp.config"));
    }

    [Fact]
    public async Task ViewingDoesNotAskAndReportsCurrentValues()
    {
        using var fixture = new Fixture(confirm: null);
        var all = await fixture.Bus.ExecuteAsync("portunus.mcp.config", "test");
        Assert.True(all.Success, all.Message);
        Assert.Contains("mcp.policy = standard", all.Message, StringComparison.Ordinal);
        Assert.Contains("mcp.confirm = deny", all.Message, StringComparison.Ordinal);

        var one = await fixture.Bus.ExecuteAsync("portunus.mcp.config key=confirm", "test");
        Assert.True(one.Success, one.Message);
        Assert.StartsWith("mcp.confirm = deny", one.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WritingWithoutConfirmationChannelIsRefusedAndLeavesSettingsUntouched()
    {
        using var fixture = new Fixture(confirm: null);
        var result = await fixture.Bus.ExecuteAsync("portunus.mcp.config key=policy value=readonly", "test");
        Assert.False(result.Success);
        Assert.Null(fixture.Settings.Get(McpSettingKeys.Policy));
        Assert.Equal("standard", fixture.Gateway.Policy);
    }

    [Fact]
    public async Task WritingAfterConfirmationPersistsToModuleSettingsAndTakesEffect()
    {
        var prompts = new List<string>();
        using var fixture = new Fixture(confirm: prompt =>
        {
            prompts.Add(prompt);
            return true;
        });

        var policy = await fixture.Bus.ExecuteAsync("portunus.mcp.config key=policy value=READONLY", "test");
        Assert.True(policy.Success, policy.Message);
        Assert.Equal("readonly", fixture.Settings.Get(McpSettingKeys.Policy));
        Assert.Equal("readonly", fixture.Gateway.Policy);

        var confirm = await fixture.Bus.ExecuteAsync("portunus.mcp.config confirm host", "test");
        Assert.True(confirm.Success, confirm.Message);
        Assert.Equal("host", fixture.Settings.Get(McpSettingKeys.Confirm));
        Assert.Equal("host", fixture.Gateway.ConfirmMode);

        Assert.Equal(2, prompts.Count);
        Assert.Contains("mcp.policy", prompts[0], StringComparison.Ordinal);
        Assert.Contains("mcp.confirm", prompts[1], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("portunus.mcp.config key=policy value=open")]
    [InlineData("portunus.mcp.config key=confirm value=standard")]
    [InlineData("portunus.mcp.config key=token value=x")]
    [InlineData("portunus.mcp.config value=readonly")]
    public async Task InvalidKeyOrValueIsRejectedWithoutWriting(string command)
    {
        using var fixture = new Fixture(confirm: _ => true);
        var result = await fixture.Bus.ExecuteAsync(command, "test");
        Assert.False(result.Success);
        Assert.Empty(fixture.Settings.All());
    }

    [Fact]
    public async Task StatusHintsNameTheModuleCommandAndAreExecutable()
    {
        using var fixture = new Fixture(confirm: _ => true);
        var status = await fixture.Bus.ExecuteAsync("portunus.mcp.status", "test");
        Assert.True(status.Success, status.Message);
        Assert.DoesNotContain("vulcan.app.set", status.Message, StringComparison.Ordinal);

        var hints = Hints(status.Message);
        Assert.Contains("portunus.mcp.config key=policy value=readonly", hints);
        Assert.Contains("portunus.mcp.config key=confirm value=host", hints);
        foreach (var hint in hints)
            Assert.True((await fixture.Bus.ExecuteAsync(hint, "test")).Success, hint);
        Assert.Equal("readonly", fixture.Gateway.Policy);
        Assert.Equal("host", fixture.Gateway.ConfirmMode);
    }

    [Fact]
    public async Task ReadonlyRejectionOverMcpCarriesAnExecutableHint()
    {
        using var fixture = new Fixture(confirm: _ => true);
        fixture.Registry.Register(new CommandDescriptor
        {
            Name = "probe.write",
            Domain = "probe",
            Summary = "write",
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("written")),
        });
        fixture.Settings.Set(McpSettingKeys.Policy, "readonly");

        Assert.True(fixture.Gateway.Start(FreePort()).Success);
        using var client = CreateClient(fixture.Gateway.Port);
        string text;
        using (var rejected = await CallToolAsync(client, 1, "probe_write"))
        {
            var result = rejected.RootElement.GetProperty("result");
            Assert.True(result.GetProperty("isError").GetBoolean());
            text = result.GetProperty("content")[0].GetProperty("text").GetString()!;
        }

        Assert.DoesNotContain("vulcan.app.set", text, StringComparison.Ordinal);
        var hint = Assert.Single(Hints(text));
        Assert.Equal("portunus.mcp.config key=policy value=standard", hint);
        Assert.True((await fixture.Bus.ExecuteAsync(hint, "test")).Success);

        using var allowed = await CallToolAsync(client, 2, "probe_write");
        Assert.False(allowed.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
    }

    [Fact]
    public async Task DangerousRejectionDoesNotAdvertiseTheAlwaysRefusingRelay()
    {
        using var fixture = new Fixture(confirm: _ => true);
        fixture.Registry.Register(new CommandDescriptor
        {
            Name = "probe.danger",
            Domain = "probe",
            Summary = "danger",
            Level = CommandLevel.Ask,
            ConfirmPrompt = _ => "confirm",
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("unused")),
        });

        Assert.True(fixture.Gateway.Start(FreePort()).Success);
        using var client = CreateClient(fixture.Gateway.Port);
        using var rejected = await CallToolAsync(client, 1, "probe_danger");
        var result = rejected.RootElement.GetProperty("result");
        Assert.True(result.GetProperty("isError").GetBoolean());
        var text = result.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.DoesNotContain("vulcan.app.set", text, StringComparison.Ordinal);
        Assert.Empty(Hints(text));
    }

    private static IReadOnlyList<string> Hints(string text)
        => Regex.Matches(text, @"portunus\.mcp\.config key=[a-z]+ value=[a-z]+")
            .Select(match => match.Value)
            .ToList();

    private static HttpClient CreateClient(int port)
    {
        var client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/") };
        client.DefaultRequestHeaders.TryAddWithoutValidation(
            "MCP-Protocol-Version", McpGateway.SupportedProtocols[0]);
        return client;
    }

    private static async Task<JsonDocument> CallToolAsync(HttpClient client, int id, string name)
    {
        var json = JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id,
            method = "tools/call",
            @params = new { name, arguments = new { } },
        });
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await client.PostAsync("mcp", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(), "HistoryPortunus.McpConfig", Guid.NewGuid().ToString("N"));

        public Fixture(Func<string, bool>? confirm = null)
        {
            Directory.CreateDirectory(_root);
            Registry = new TestRegistrar();
            Catalog = new TestCatalog(Registry);
            Bus = new TestCommandBus(Registry, confirm);
            var log = new NullLog();
            var prompts = new PromptGovernanceStore(_root, log);
            Gateway = new McpGateway(
                () => Bus, Catalog, Settings, log, new NullAudit(), prompts, new HostIdentity("Test", "6.0.0"));
            McpCommands.RegisterAll(Registry, () => Bus, Catalog, () => Gateway, Settings, prompts);
        }

        public TestRegistrar Registry { get; }

        public TestCatalog Catalog { get; }

        public TestCommandBus Bus { get; }

        public MemorySettings Settings { get; } = new();

        public McpGateway Gateway { get; }

        public void Dispose()
        {
            Gateway.Dispose();
            Directory.Delete(_root, recursive: true);
        }
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

    private sealed class NullLog : IModuleLog
    {
        public void Log(ShellLogLevel level, string category, string message) { }
        public IReadOnlyList<ShellLogEntry> Snapshot() => [];
    }
}
