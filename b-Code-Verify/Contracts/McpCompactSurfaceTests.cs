using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryPortunus.Mcp;
using Xunit;

namespace HistoryPortunus.Contracts;

/// <summary>
/// mcp.surface=compact：tools/list 只列 find / call 两个元工具，客户端常驻上下文与指令数无关。
/// 这里守住两件事：列法变了，能调什么没变（call 与直调同一套策略、确认判断）。
/// </summary>
[Collection(TestCollections.Gateway)]
public sealed class McpCompactSurfaceTests
{
    [Fact]
    public async Task FullListsEveryCommandAndCompactListsOnlyTheTwoMetaTools()
    {
        using var fixture = new Fixture();
        using (var full = await fixture.RpcAsync("tools/list", new { }))
        {
            var names = ToolNames(full);
            Assert.Contains("probe_echo", names);
            Assert.Contains("probe_write", names);
            Assert.DoesNotContain(McpGateway.FindToolName, names);
        }

        fixture.Settings.Set(McpSettingKeys.Surface, "compact");
        using var compact = await fixture.RpcAsync("tools/list", new { });
        Assert.Equal([McpGateway.FindToolName, McpGateway.CallToolName], ToolNames(compact));
        Assert.Contains("probe(2)", compact.RootElement.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task FindReturnsSchemaForMatchesAndOnlyNamesWithoutQuery()
    {
        using var fixture = new Fixture(surface: "compact");

        var hit = await fixture.CallTextAsync(McpGateway.FindToolName, new { query = "echo" });
        Assert.Equal(1, hit.GetProperty("total").GetInt32());
        var tool = hit.GetProperty("tools")[0];
        Assert.Equal("probe.echo", tool.GetProperty("name").GetString());
        Assert.True(tool.GetProperty("inputSchema").GetProperty("properties").TryGetProperty("text", out _));

        // 多词须全部命中
        var none = await fixture.CallTextAsync(McpGateway.FindToolName, new { query = "echo write" });
        Assert.Equal(0, none.GetProperty("total").GetInt32());

        var overview = await fixture.CallTextAsync(McpGateway.FindToolName, new { });
        Assert.False(overview.TryGetProperty("tools", out _));
        Assert.Equal(2, overview.GetProperty("domains").GetProperty("probe").GetArrayLength());

        var limited = await fixture.CallTextAsync(McpGateway.FindToolName, new { query = "probe", limit = 1 });
        Assert.Equal(1, limited.GetProperty("tools").GetArrayLength());
        Assert.Equal(1, limited.GetProperty("more").GetArrayLength());
    }

    [Fact]
    public async Task CallExecutesByCommandOrToolNameWithArguments()
    {
        using var fixture = new Fixture(surface: "compact");
        foreach (var name in new[] { "probe.echo", "probe_echo" })
        {
            using var called = await fixture.RpcAsync("tools/call", new
            {
                name = McpGateway.CallToolName,
                arguments = new { name, arguments = new { text = "中文 x=1" } },
            });
            var result = called.RootElement.GetProperty("result");
            Assert.False(result.GetProperty("isError").GetBoolean(), result.ToString());
            Assert.Equal("中文 x=1", result.GetProperty("structuredContent").GetProperty("data").GetString());
        }
    }

    [Fact]
    public async Task CallObeysTheSamePolicyAsDirectCalls()
    {
        using var fixture = new Fixture(surface: "compact");
        fixture.Settings.Set(McpSettingKeys.Policy, "readonly");

        using var write = await fixture.RpcAsync("tools/call", new
        {
            name = McpGateway.CallToolName,
            arguments = new { name = "probe.write" },
        });
        var result = write.RootElement.GetProperty("result");
        Assert.True(result.GetProperty("isError").GetBoolean());
        Assert.Equal(0, fixture.Writes);

        // Ask 级与硬排除的指令经 call 也够不着
        using (var ask = await fixture.RpcAsync("tools/call", new
               {
                   name = McpGateway.CallToolName,
                   arguments = new { name = "probe.ask" },
               }))
        {
            Assert.True(ask.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        }

        using var hidden = await fixture.RpcAsync("tools/call", new
        {
            name = McpGateway.CallToolName,
            arguments = new { name = "portunus.mcp.config" },
        });
        Assert.True(hidden.RootElement.TryGetProperty("error", out _), hidden.RootElement.ToString());
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"name\":\"portunus_call\"}")]
    [InlineData("{\"name\":\"portunus_find\"}")]
    [InlineData("{\"name\":\"probe.echo\",\"arguments\":\"text=1\"}")]
    public async Task MalformedOrNestedCallIsRejected(string arguments)
    {
        using var fixture = new Fixture(surface: "compact");
        using var args = JsonDocument.Parse(arguments);
        using var response = await fixture.RpcAsync("tools/call", new
        {
            name = McpGateway.CallToolName,
            arguments = args.RootElement,
        });
        Assert.Equal(-32602, response.RootElement.GetProperty("error").GetProperty("code").GetInt32());
    }

    [Fact]
    public async Task ConfigCommandWritesSurface()
    {
        using var fixture = new Fixture();
        var set = await fixture.Bus.ExecuteAsync("portunus.mcp.config key=surface value=COMPACT", "test");
        Assert.True(set.Success, set.Message);
        Assert.Equal("compact", fixture.Settings.Get(McpSettingKeys.Surface));
        Assert.Equal("compact", fixture.Gateway.Surface);

        var bad = await fixture.Bus.ExecuteAsync("portunus.mcp.config key=surface value=domain", "test");
        Assert.False(bad.Success);
        Assert.Equal("compact", fixture.Gateway.Surface);
    }

    private static IReadOnlyList<string?> ToolNames(JsonDocument response)
        => response.RootElement.GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString())
            .ToList();

    private sealed class Fixture : IDisposable
    {
        private readonly string _root;
        private readonly HttpClient _client;
        private int _id;

        public Fixture(string? surface = null)
        {
            _root = Path.Combine(Path.GetTempPath(), "HistoryPortunus.Compact", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_root);
            Registry = new TestRegistrar();
            Catalog = new TestCatalog(Registry);
            Bus = new TestCommandBus(Registry, _ => true);
            if (surface != null)
                Settings.Set(McpSettingKeys.Surface, surface);

            Registry.Register(new CommandDescriptor
            {
                Name = "probe.echo",
                Domain = "probe",
                Summary = "回显文本",
                Readonly = true,
                Parameters = [new ParameterSpec { Name = "text", Description = "要回显的文本", Required = true }],
                Handler = CommandDescriptor.Sync(ctx => CommandResult.Ok("echo", ctx.GetString("text"))),
            });
            Registry.Register(new CommandDescriptor
            {
                Name = "probe.write",
                Domain = "probe",
                Summary = "写入",
                Handler = CommandDescriptor.Sync(_ =>
                {
                    Writes++;
                    return CommandResult.Ok("written");
                }),
            });
            Registry.Register(new CommandDescriptor
            {
                Name = "probe.ask",
                Domain = "probe",
                Summary = "危险",
                Level = CommandLevel.Ask,
                Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("asked")),
            });

            var log = new NullLog();
            var prompts = new PromptGovernanceStore(_root, log);
            McpGateway? gateway = null;
            gateway = new McpGateway(
                () => Bus, Catalog, Settings, log, new NullAudit(), prompts, new HostIdentity("Test", "6.0.0"));
            Gateway = gateway;
            McpCommands.RegisterAll(Registry, () => Bus, Catalog, () => gateway, Settings, prompts);
            Assert.True(Gateway.Start(FreePort()).Success);
            _client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{Gateway.Port}/") };
            _client.DefaultRequestHeaders.TryAddWithoutValidation(
                "MCP-Protocol-Version", McpGateway.SupportedProtocols[0]);
        }

        public TestRegistrar Registry { get; }
        public TestCatalog Catalog { get; }
        public TestCommandBus Bus { get; }
        public MemorySettings Settings { get; } = new();
        public McpGateway Gateway { get; }
        public int Writes { get; private set; }

        public async Task<JsonDocument> RpcAsync(string method, object parameters)
        {
            var json = JsonSerializer.Serialize(new { jsonrpc = "2.0", id = ++_id, method, @params = parameters });
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = await _client.PostAsync("mcp", content);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        }

        /// <summary>调一个返回 JSON 文本的工具，解析第一段文本。</summary>
        public async Task<JsonElement> CallTextAsync(string tool, object arguments)
        {
            using var response = await RpcAsync("tools/call", new { name = tool, arguments });
            var result = response.RootElement.GetProperty("result");
            Assert.False(result.GetProperty("isError").GetBoolean(), result.ToString());
            var text = result.GetProperty("content")[0].GetProperty("text").GetString()!;
            return JsonDocument.Parse(text).RootElement.Clone();
        }

        public void Dispose()
        {
            _client.Dispose();
            Gateway.Dispose();
            Directory.Delete(_root, recursive: true);
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

    private sealed class NullLog : IModuleLog
    {
        public void Log(ShellLogLevel level, string category, string message) { }
        public IReadOnlyList<ShellLogEntry> Snapshot() => [];
    }
}
