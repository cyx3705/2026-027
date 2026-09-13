using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HistoryVulcan.Core;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Storage;
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
        var registry = new CommandRegistry();
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
        var result = await new CommandBus(registry, new NullLog()).ExecuteAsync(command, "test");
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
            var registry = new CommandRegistry();
            RegisterModuleProbe(registry, "HistoryDiana", "diana.health", "diana-ok");
            RegisterModuleProbe(registry, "HistoryJanus", "janus.health", "janus-ok");
            RegisterModuleProbe(registry, "HistoryMercury", "mercury.health", "mercury-ok");
            RegisterModuleProbe(registry, "HistoryMinerva", "minerva.health", "minerva-ok");
            var settings = new MemorySettings();
            settings.Set(McpSettingKeys.Policy, "standard");
            var log = new NullLog();
            var bus = new CommandBus(registry, log);
            var prompts = new PromptGovernanceStore(root, log);
            McpGateway? gateway = null;
            gateway = new McpGateway(
                () => bus,
                settings,
                log,
                new NullAudit(),
                prompts,
                new HistoryVulcan.Core.ApplicationIdentity(
                    "Test", "3.5.0", "3.5.0", "3.5.0.0"));
            using (gateway)
            {
                McpCommands.RegisterAll(
                    registry, () => bus, () => gateway, settings, prompts, "framework:service");
                var exposure = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["HistoryDiana"] = "standard",
                    ["HistoryJanus"] = "standard",
                    ["HistoryMercury"] = "standard",
                    ["HistoryMinerva"] = "standard",
                };
                McpExposurePolicy.ModuleOfCommand = command =>
                {
                    var source = registry.GetSource(command);
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
                RegisterModuleProbe(registry, "HistoryJanus", "janus.fresh", "fresh-ok");
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

    private static void RegisterModuleProbe(
        CommandRegistry registry,
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
        }, $"module:{owner}");
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

    private sealed class NullLog : IShellLog
    {
        public void Log(ShellLogLevel level, string category, string message) { }
        public event EventHandler<ShellLogEntry>? EntryAdded { add { } remove { } }
        public IReadOnlyList<ShellLogEntry> Snapshot() => [];
    }
}
