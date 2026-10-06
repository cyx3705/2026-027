using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using HistoryPortunus.Mcp;
using HistoryPortunus.Web;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using Xunit;

namespace HistoryPortunus.Contracts;

/// <summary>
/// 文档改造后，原来写在技术合同里、别的模块要靠的那两面：MCP 怎么投影、Web 航线长什么样。
/// </summary>
/// <remarks>
/// 已删的 REQ-PORT-006 把默认策略写成「只有只读且没有 HiddenReason 才投影」。
/// 代码里的 standard 更宽：非只读也会投影，硬排除与 Ask 另算。
/// 这里守的是代码里的真规则。把那句简化写回现行约定，或放宽硬排除，这些断言会先失败。
/// </remarks>
[Collection(TestCollections.Gateway)]
public sealed class TransportSurfaceContractTests
{
    [Fact]
    public void LongLivedOfficeIsOnlyTheConventionsFile()
    {
        var root = RepoRoot();
        var office = Path.Combine(root, "b-Office");
        var current = Path.Combine(office, "current");

        Assert.True(Directory.Exists(current));
        Assert.False(Directory.Exists(Path.Combine(office, "history")));
        Assert.False(File.Exists(Path.Combine(office, "文档中心.md")));
        Assert.Equal(
            new[] { "现行约定.md" },
            Directory.EnumerateFiles(current, "*.md").Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray());

        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "project.manifest.json")));
        var documents = manifest.RootElement.GetProperty("documents");
        var keys = documents.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Equal(new[] { "conventions" }, keys);
        Assert.Equal("b-Office/current/现行约定.md", documents.GetProperty("conventions").GetString());
        foreach (var archive in manifest.RootElement.GetProperty("paths").GetProperty("archiveRoots").EnumerateArray())
            Assert.DoesNotContain("b-Office/history", archive.GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ToolNameAndParameterDescriptionAreTheAuthorFacingProjection()
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Assert.Equal("minerva_plan_package", CommandSchemaExporter.MakeToolName("minerva.plan.package", used));

        var registrar = new TestRegistrar();
        registrar.Register(new CommandDescriptor
        {
            Name = "minerva.plan.package",
            Summary = "打包",
            Example = "minerva.plan.package",
            Readonly = true,
            Parameters =
            [
                new ParameterSpec
                {
                    Name = "out",
                    Type = ParamType.String,
                    Required = true,
                    Description = "输出目录，例如 z-Publish",
                },
            ],
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("ok")),
        });

        var tool = new CommandSchemaExporter(new TestCatalog(registrar)).Find("minerva.plan.package");
        Assert.NotNull(tool);
        Assert.Equal("minerva_plan_package", tool!.ToolName);
        Assert.Equal(
            "输出目录，例如 z-Publish",
            tool.InputSchema["properties"]!["out"]!["description"]!.GetValue<string>());
    }

    [Fact]
    public void StandardPolicyProjectsWritableCommandsAndKeepsTheHardExclusions()
    {
        Assert.True(Visible("minerva.plan.run", readOnly: false, policy: "standard"));
        Assert.True(Visible("diana.docs.read", readOnly: true, policy: "standard"));
        Assert.False(Visible("hidden.one", readOnly: true, policy: "standard", hidden: "不对远端暴露"));
        Assert.False(Visible("ask.one", readOnly: false, policy: "standard", ask: true));
        Assert.False(Visible("portunus.mcp.status", readOnly: true, policy: "standard"));
        Assert.False(Visible("vulcan.mcp.start", readOnly: false, policy: "standard"));
        Assert.False(Visible("vulcan.module.reload", readOnly: false, policy: "standard"));
        Assert.False(Visible("vulcan.app.quit", readOnly: false, policy: "standard"));
        Assert.False(Visible("vulcan.app.close", readOnly: false, policy: "standard"));
    }

    [Fact]
    public void ReadonlyPolicyKeepsReadonlyCommandsAndTheThreeCatalogQueries()
    {
        Assert.True(Visible("diana.docs.read", readOnly: true, policy: "readonly"));
        Assert.False(Visible("minerva.plan.run", readOnly: false, policy: "readonly"));
        Assert.True(Visible("vulcan.command.list", readOnly: false, policy: "readonly"));
        Assert.True(Visible("vulcan.command.show", readOnly: false, policy: "readonly"));
        Assert.True(Visible("vulcan.command.domains", readOnly: false, policy: "readonly"));
        Assert.False(Visible("vulcan.command.validate", readOnly: false, policy: "readonly"));
    }

    [Fact]
    public void ModuleMarkedHiddenDropsEveryCommandOfThatModule()
    {
        var previousModule = McpExposurePolicy.ModuleOfCommand;
        var previousExposure = McpExposurePolicy.ModuleExposure;
        try
        {
            McpExposurePolicy.ModuleOfCommand = name =>
                name.StartsWith("janus.", StringComparison.OrdinalIgnoreCase) ? "HistoryJanus" : null;
            McpExposurePolicy.ModuleExposure = module =>
                module == "HistoryJanus" ? "hidden" : "standard";

            Assert.False(Visible("janus.proj.list", readOnly: true, policy: "standard"));
            Assert.True(Visible("diana.docs.read", readOnly: true, policy: "standard"));
        }
        finally
        {
            McpExposurePolicy.ModuleOfCommand = previousModule;
            McpExposurePolicy.ModuleExposure = previousExposure;
        }
    }

    [Fact]
    public void EndpointFileKeepsTheFieldsClientsRereadBeforeEveryCall()
    {
        var directory = Path.Combine(Path.GetTempPath(), "portunus-endpoint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, EndpointDescriptor.FileName);
            EndpointDescriptor.Write(path, 8938, "server-1", "token-1", new NullLog());
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var names = document.RootElement.EnumerateObject().Select(property => property.Name)
                .Order(StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(new[] { "accessToken", "port", "processId", "serverId" }, names);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task WebSurfaceIsThreeApiRoutesAndRootIsNotHealth()
    {
        using var gateway = new WebGateway(
            () => new TestCommandBus(new TestRegistrar()),
            new TestCatalog(() => null),
            new HostIdentity("HistoryVulcan", "6.0.0"),
            new MemorySettings(),
            new NullLog());
        Assert.True(gateway.Start(FreePort()).Success);

        using var client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{gateway.Port}/") };
        client.DefaultRequestHeaders.Add("X-HistoryVulcan-Client", "Shell");
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", gateway.AccessToken);

        using var root = await client.GetAsync("");
        Assert.Equal(HttpStatusCode.NotFound, root.StatusCode);

        using var health = await client.GetAsync("api/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        using var healthJson = JsonDocument.Parse(await health.Content.ReadAsStringAsync());
        Assert.Equal("ok", healthJson.RootElement.GetProperty("status").GetString());

        using var commands = await client.GetAsync("api/commands");
        Assert.Equal(HttpStatusCode.OK, commands.StatusCode);
    }

    private static bool Visible(string name, bool readOnly, string policy, bool ask = false, string? hidden = null)
        => McpExposurePolicy.IsVisible(
            new CatalogCommand(name, "s", null, "module:Fixture", ask, readOnly, hidden, false, []),
            policy);

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var manifest = Path.Combine(dir.FullName, "project.manifest.json");
            if (File.Exists(manifest)
                && File.ReadAllText(manifest).Contains("\"name\": \"HistoryPortunus\"", StringComparison.Ordinal))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new InvalidOperationException("找不到 HistoryPortunus 仓库根。");
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

    private sealed class NullLog : IModuleLog
    {
        public void Log(ShellLogLevel level, string category, string message)
        {
        }
    }
}
