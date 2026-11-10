using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryPortunus.Mcp;
using Xunit;

namespace HistoryPortunus.Contracts;

// REQ-DIANA-RELAY-001：精简只影响展示，发现和统一调用归 Diana。
[Collection(TestCollections.Gateway)]
public sealed class McpCompactSurfaceTests
{
    [Fact]
    public async Task CompactNeverAddsPortunusToolsAndRetiredCallsAreRejected()
    {
        using var f = new Fixture();
        using (var full = await f.RpcAsync("tools/list", new { }))
            Assert.Equal(new[] { "probe_echo", "probe_write" }, ToolNames(full));
        f.SetSurface("compact");
        using (var compact = await f.RpcAsync("tools/list", new { }))
            Assert.Empty(ToolNames(compact));
        foreach (var name in new[] { "portunus_find", "portunus_call" })
        {
            using var retired = await f.RpcAsync("tools/call", new { name, arguments = new { name = "probe_echo" } });
            Assert.Equal(-32602, retired.RootElement.GetProperty("error").GetProperty("code").GetInt32());
        }
    }

    [Fact]
    public async Task FullCatalogIgnoresDisplayButPreservesPolicyAndDangerFiltering()
    {
        using var f = new Fixture("compact");
        using (var all = await f.RpcAsync("tools/list", FullCatalog()))
        {
            Assert.True(all.RootElement.GetProperty("result").GetProperty("_meta").GetProperty("historyvulcan/fullCatalog").GetBoolean());
            Assert.Equal(new[] { "probe_echo", "probe_write" }, ToolNames(all));
        }
        f.Settings.Set(McpSettingKeys.Policy, "readonly");
        using (var read = await f.RpcAsync("tools/list", FullCatalog()))
            Assert.Equal(new[] { "probe_echo" }, ToolNames(read));
        using var denied = await f.RpcAsync("tools/call", new { name = "probe_write" });
        Assert.True(denied.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Equal(0, f.Writes);
        using var ask = await f.RpcAsync("tools/call", new { name = "probe_ask" });
        Assert.True(ask.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
    }

    [Fact]
    public async Task ModuleOverrideAndModuleDefaultOnlyChangeDisplay()
    {
        using var f = new Fixture();
        AddOtherModule(f);
        f.Catalog.SetSource("probe.echo", "module:Probe");
        f.Catalog.SetSource("probe.write", "module:Probe");
        f.SetSurface("full", ("Probe", "compact"));
        using (var listed = await f.RpcAsync("tools/list", new { }))
            Assert.Equal(new[] { "other_ping" }, ToolNames(listed));
        using (var all = await f.RpcAsync("tools/list", FullCatalog()))
            Assert.Contains("probe_echo", ToolNames(all));
        using (var call = await f.RpcAsync("tools/call", new { name = "probe_echo", arguments = new { text = "中文 x=1" } }))
        {
            var result = call.RootElement.GetProperty("result");
            Assert.False(result.GetProperty("isError").GetBoolean());
            Assert.Equal("中文 x=1", result.GetProperty("structuredContent").GetProperty("data").GetString());
        }
        f.SetSurface("compact", ("Other", "full"));
        using (var expanded = await f.RpcAsync("tools/list", new { }))
            Assert.Equal(new[] { "other_ping" }, ToolNames(expanded));
        f.SetSurface("full");
        f.SetModuleDefault("compact");
        using var defaults = await f.RpcAsync("tools/list", new { });
        Assert.Empty(ToolNames(defaults));
    }

    [Fact]
    public async Task DianaRemainsVisibleAndCachedPlanSurvivesReload()
    {
        using var f = new Fixture("compact");
        foreach (var name in new[] { "diana.relay.find", "diana.relay.call" })
        {
            f.Registry.Register(new CommandDescriptor { Name = name, Domain = "diana", Summary = "Diana 统一入口",
                Readonly = true, Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("ok")) });
            f.Catalog.SetSource(name, "module:HistoryDiana");
        }
        using (var before = await f.RpcAsync("tools/list", new { }))
            Assert.Equal(new[] { "diana_relay_call", "diana_relay_find" }, ToolNames(before));
        f.SetSurfaceAvailable(false);
        using var during = await f.RpcAsync("tools/list", new { });
        Assert.Equal(new[] { "diana_relay_call", "diana_relay_find" }, ToolNames(during));
        Assert.Equal("缓存", f.Gateway.SurfaceSource);
    }

    [Fact]
    public async Task ReadonlyKeepsDianaRelayCallableButStillRejectsInnerWrites()
    {
        using var f = new Fixture("compact");
        f.Registry.Register(new CommandDescriptor
        {
            Name = "diana.relay.call", Domain = "diana", Summary = "Diana 统一调用入口",
            Parameters = [new ParameterSpec { Name = "name", Required = true, Description = "目标工具名" }],
            Handler = async ctx =>
            {
                using var inner = await f.RpcAsync("tools/call", new { name = ctx.RequireString("name"), arguments = new { text = "read" } });
                var result = inner.RootElement.GetProperty("result");
                return result.GetProperty("isError").GetBoolean() ? CommandResult.Fail("denied") : CommandResult.Ok("read");
            },
        });
        f.Catalog.SetSource("diana.relay.call", "module:HistoryDiana");
        f.Settings.Set(McpSettingKeys.Policy, "readonly");
        using (var listed = await f.RpcAsync("tools/list", new { }))
            Assert.Contains("diana_relay_call", ToolNames(listed));
        foreach (var target in new[] { "probe_echo", "probe_write" })
        {
            using var call = await f.RpcAsync("tools/call", new { name = "diana_relay_call", arguments = new { name = target } });
            Assert.Equal(target == "probe_write", call.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        }
        Assert.Equal(0, f.Writes);
    }

    [Fact]
    public async Task SurfaceIsOwnedByDianaSoConfigRejectsIt()
    {
        using var f = new Fixture();
        Assert.False((await f.Bus.ExecuteAsync("portunus.mcp.config key=surface value=compact", "test")).Success);
    }

    private static object FullCatalog() => new { _meta = new Dictionary<string, bool> { ["historyvulcan/fullCatalog"] = true } };

    private static void AddOtherModule(Fixture fixture)
    {
        fixture.Registry.Register(new CommandDescriptor
        {
            Name = "other.ping",
            Domain = "other",
            Summary = "另一个模块的只读指令",
            Readonly = true,
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("pong")),
        });
        fixture.Catalog.SetSource("other.ping", "module:Other");
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
            SetSurface(surface ?? "full");

            Registry.Register(new CommandDescriptor
            {
                Name = "diana.surface.plan",
                HiddenReason = "Portunus 内部取计划，不对远端暴露",
                Domain = "diana",
                Summary = "测试用列法计划",
                Readonly = true,
                Handler = CommandDescriptor.Sync(_ => _surfaceAvailable
                    ? CommandResult.Ok(
                        "plan",
                        JsonSerializer.SerializeToElement(new
                        {
                            global = _surfaceGlobal,
                            moduleDefault = _surfaceDefault,
                            modules = _surfaceModules.Select(pair => new { module = pair.Key, mode = pair.Value }).ToList(),
                            alwaysFull = new[] { "HistoryDiana" },
                        }))
                    : CommandResult.Fail("Diana 暂不可用")),
            });

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

        private string _surfaceGlobal = "full";
        private string? _surfaceDefault;
        private bool _surfaceAvailable = true;
        private readonly Dictionary<string, string> _surfaceModules = new(StringComparer.OrdinalIgnoreCase);

        public void SetSurface(string global, params (string Module, string Mode)[] modules)
        {
            _surfaceGlobal = global;
            _surfaceModules.Clear();
            foreach (var (module, mode) in modules)
                _surfaceModules[module] = mode;
        }

        public void SetModuleDefault(string? mode) => _surfaceDefault = mode;

        /// <summary>模拟 Diana 热重载：指令还在目录里，但调用失败。</summary>
        public void SetSurfaceAvailable(bool available) => _surfaceAvailable = available;

        public async Task<JsonDocument> RpcAsync(string method, object parameters)
        {
            var json = JsonSerializer.Serialize(new { jsonrpc = "2.0", id = ++_id, method, @params = parameters });
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = await _client.PostAsync("mcp", content);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
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
