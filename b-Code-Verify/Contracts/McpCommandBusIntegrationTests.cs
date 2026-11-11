using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryPortunus.Mcp;
using Xunit;

namespace HistoryPortunus.Contracts;

[Collection(TestCollections.Gateway)]
public sealed class McpCommandBusIntegrationTests
{
    [Theory]
    [InlineData("中文")]
    [InlineData(@"\u4E2D\u6587")]
    [InlineData("引号\"与\\反斜杠\r\n下一行\t制表😀")]
    [InlineData("")]
    [InlineData("x=1 other=2")]
    public async Task JsonStringArgumentsReachHandlerUnchanged(string input)
    {
        var registry = new TestRegistrar();
        registry.Register(new CommandDescriptor
        {
            Name = "probe.echo",
            Domain = "probe",
            Summary = "echo",
            Readonly = true,
            Parameters = [new ParameterSpec { Name = "text", Description = "input", Required = true }],
            Handler = CommandDescriptor.Sync(ctx => CommandResult.Ok("echo", ctx.GetString("text"))),
        });
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(new { text = input }));
        var command = CommandSchemaExporter.BuildCommandText("probe.echo", json.RootElement);
        var result = await new TestCommandBus(registry).ExecuteAsync(command, "test");
        Assert.True(result.Success, result.Message);
        Assert.Equal(input, result.Data);
    }

    [Fact]
    public async Task ModuleToolsListCallAndReloadUseTheSameLiveBackendRegistry()
    {
        var root = Path.Combine(Path.GetTempPath(), "HistoryVulcan.McpBus", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var previousModule = McpExposurePolicy.ModuleOfCommand;
        var previousExposure = McpExposurePolicy.ModuleExposure;
        try
        {
            var registry = new TestRegistrar();
            var catalog = new TestCatalog(registry);
            RegisterModuleProbe(registry, catalog, "HistoryDiana", "diana.health", "diana-ok");
            RegisterModuleProbe(registry, catalog, "HistoryJanus", "janus.health", "janus-ok");
            RegisterModuleProbe(registry, catalog, "HistoryMercury", "mercury.health", "mercury-ok");
            RegisterModuleProbe(registry, catalog, "HistoryMinerva", "minerva.health", "minerva-ok");
            var settings = new MemorySettings();
            settings.Set(McpSettingKeys.Policy, "standard");
            var log = new NullLog();
            var bus = new TestCommandBus(registry);
            var prompts = new PromptGovernanceStore(root, log);
            McpGateway? gateway = null;
            gateway = new McpGateway(
                () => bus,
                catalog,
                settings,
                log,
                new NullAudit(),
                prompts,
                new HostIdentity("Test", "3.5.0"));
            using (gateway)
            {
                McpCommands.RegisterAll(
                    registry, () => bus, catalog, () => gateway, settings, prompts);
                var exposure = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["HistoryDiana"] = "standard",
                    ["HistoryJanus"] = "standard",
                    ["HistoryMercury"] = "standard",
                    ["HistoryMinerva"] = "standard",
                };
                McpExposurePolicy.ModuleOfCommand = command =>
                {
                    var source = catalog.SourceOf(command);
                    return source.StartsWith("module:", StringComparison.OrdinalIgnoreCase)
                        ? source["module:".Length..]
                        : null;
                };
                McpExposurePolicy.ModuleExposure = module => exposure.GetValueOrDefault(module);

                Assert.True(gateway.Start(FreePort()).Success);
                var originalPort = gateway.Port;
                using var client = CreateClient(gateway.Port);
                using (var listed = await PostRpcAsync(client, 1, "tools/list", new { }))
                {
                    var names = ToolNames(listed);
                    Assert.Contains("diana_health", names);
                    Assert.Contains("janus_health", names);
                    Assert.Contains("mercury_health", names);
                    Assert.Contains("minerva_health", names);
                }

                using (var called = await PostRpcAsync(
                           client,
                           2,
                           "tools/call",
                           new
                           {
                               name = "janus_health",
                               arguments = new { },
                           }))
                {
                    var result = called.RootElement.GetProperty("result");
                    Assert.False(result.GetProperty("isError").GetBoolean());
                    Assert.Contains("janus-ok", result.ToString(), StringComparison.Ordinal);
                }

                registry.Unregister("janus.health");
                RegisterModuleProbe(registry, catalog, "HistoryJanus", "janus.fresh", "fresh-ok");
                exposure["HistoryMercury"] = "hidden";
                using (var reloaded = await PostRpcAsync(client, 3, "tools/list", new { }))
                {
                    var names = ToolNames(reloaded);
                    Assert.DoesNotContain("janus_health", names);
                    Assert.Contains("janus_fresh", names);
                    Assert.DoesNotContain("mercury_health", names);
                }
                Assert.True(gateway.IsRunning);
                Assert.Equal(originalPort, gateway.Port);
            }
        }
        finally
        {
            McpExposurePolicy.ModuleOfCommand = previousModule;
            McpExposurePolicy.ModuleExposure = previousExposure;
            Directory.Delete(root, recursive: true);
        }
    }

    // REQ-PORTUNUS-CATALOG-001：同名同域，只调整 MCP 的描述和返回；内层总线完整目录仍可用。
    [Fact]
    public async Task CommandListProjectsOneShortTableAndLiveCapabilityOverview()
    {
        var root = Path.Combine(Path.GetTempPath(), "CompactCatalog", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var registry = new TestRegistrar();
            var catalog = new TestCatalog(registry);
            string? filter = null;
            var summary = new string('中', 29) + "😀更多内容|下一行\n结束";
            var fullRows = JsonSerializer.SerializeToElement(new[] {
                new { commandName = "probe.data.read", summary, parameters = new[] { "private-details" }, source = "module" },
            });
            registry.Register(new CommandDescriptor
            {
                Name = "vulcan.command.list", Summary = "完整注册表", Readonly = true,
                Parameters = [new ParameterSpec { Name = "filter", Description = "筛选" }],
                Handler = CommandDescriptor.Sync(ctx =>
                {
                    filter = ctx.GetString("filter");
                    return CommandResult.Ok("旧长正文 private-details", fullRows);
                }),
            });
            registry.Register(new CommandDescriptor
            {
                Name = "probe.data.read", Summary = "读取项目资料", Readonly = true,
                Handler = CommandDescriptor.Sync(_ => CommandResult.Ok()),
            });
            var settings = new MemorySettings();
            settings.Set(McpSettingKeys.Policy, "standard");
            var bus = new TestCommandBus(registry);
            using var gateway = new McpGateway(() => bus, catalog, settings, new NullLog(),
                new NullAudit(), new PromptGovernanceStore(root, new NullLog()), new HostIdentity("test", "1"));
            Assert.True(gateway.Start(FreePort()).Success);
            using var client = CreateClient(gateway.Port);
            using var tools = await PostRpcAsync(client, 1, "tools/list", new { });
            var description = tools.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray()
                .Single(tool => tool.GetProperty("name").GetString() == "vulcan_command_list")
                .GetProperty("description").GetString()!;
            Assert.Contains("probe=读取项目资料", description, StringComparison.Ordinal);
            using var response = await PostRpcAsync(client, 2, "tools/call",
                new { name = "vulcan_command_list", arguments = new { filter = "probe" } });
            var result = response.RootElement.GetProperty("result");
            Assert.False(result.GetProperty("isError").GetBoolean());
            Assert.Equal("probe", filter);
            var block = Assert.Single(result.GetProperty("content").EnumerateArray());
            var table = block.GetProperty("text").GetString()!;
            Assert.Contains("| probe.data.read | " + new string('中', 29) + "… |", table, StringComparison.Ordinal);
            Assert.DoesNotContain("private-details", table, StringComparison.Ordinal);
            Assert.False(result.TryGetProperty("structuredContent", out _));
            var direct = await bus.InvokeAsync("vulcan.command.list", "module:catalog");
            Assert.Equal(fullRows.GetRawText(), Assert.IsType<JsonElement>(direct.Data).GetRawText());
            registry.Register(new CommandDescriptor
            {
                Name = "fresh.work.open", Summary = "打开工作区", Readonly = true,
                Handler = CommandDescriptor.Sync(_ => CommandResult.Ok()),
            });
            using var refreshed = await PostRpcAsync(client, 3, "tools/list", new { });
            var freshDescription = refreshed.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray()
                .Single(tool => tool.GetProperty("name").GetString() == "vulcan_command_list")
                .GetProperty("description").GetString()!;
            Assert.Contains("fresh=打开工作区", freshDescription, StringComparison.Ordinal);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void RegisterModuleProbe(
        TestRegistrar registry,
        TestCatalog catalog,
        string owner,
        string name,
        string result)
    {
        registry.Register(new CommandDescriptor
        {
            Name = name,
            Domain = name.Split('.')[0],
            Summary = name,
            Readonly = true,
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok(result)),
        });
        catalog.SetSource(name, $"module:{owner}");
    }

    private static HttpClient CreateClient(int port)
    {
        var client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/") };
        client.DefaultRequestHeaders.TryAddWithoutValidation(
            "MCP-Protocol-Version", McpGateway.SupportedProtocols[0]);
        return client;
    }

    private static IReadOnlyList<string?> ToolNames(JsonDocument response)
        => response.RootElement.GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString())
            .ToList();

    private static async Task<JsonDocument> PostRpcAsync(
        HttpClient client,
        int id,
        string method,
        object parameters)
    {
        var json = JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id,
            method,
            @params = parameters,
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
