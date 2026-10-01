using System.Text.Json;
using HistoryPortunus.Mcp;
using HistoryVulcan.Core.Commands;
using Xunit;

namespace HistoryPortunus.Contracts;

/// <summary>
/// 1.1.0：网关的目录经总线读宿主（<c>vulcan.command.revision</c> + <c>vulcan.command.list</c>），
/// 按宿主模块API写明的 JSON 字段名解析，版本号不变不重拉。
/// </summary>
public sealed class BusCommandCatalogTests
{
    private const string Row = """
        {"commandName":"janus.proj.drop","domain":"janus","summary":"删项目","example":"janus.proj.drop name=x",
         "parameterCount":1,"source":"module","sourceDetail":"HistoryJanus","dangerous":true,"requiresUiThread":false,
         "readonly":false,"hiddenReason":null,"commandClass":"proj","method":"drop","requiresConfirmation":true,
         "allowUnspecifiedParameters":false,
         "parameters":[{"name":"name","type":"string","required":true,"default":null,"position":0,
                        "allowedValues":[],"description":"项目名"}],
         "annotations":{}}
        """;

    [Fact]
    public void ReadsTheHostCatalogShapeAndRefetchesOnlyWhenTheRevisionMoves()
    {
        var bus = new FakeHostBus { Revision = 7, Rows = $"[{Row}]" };
        var catalog = new BusCommandCatalog(() => bus);

        var command = Assert.Single(catalog.All());
        Assert.Equal("janus.proj.drop", command.Name);
        Assert.Equal("module:HistoryJanus", command.Source);
        Assert.True(command.Ask);
        Assert.False(command.Readonly);
        var parameter = Assert.Single(command.Parameters);
        Assert.Equal(("name", "string", true, 0), (parameter.Name, parameter.Type, parameter.Required, parameter.Position));
        Assert.True(catalog.TryGet("JANUS.PROJ.DROP", out _));
        Assert.Equal(1, bus.ListCalls);

        catalog.All();
        Assert.Equal(1, bus.ListCalls);

        bus.Revision = 8;
        bus.Rows = "[]";
        Assert.Empty(catalog.All());
        Assert.Equal(2, bus.ListCalls);
    }

    [Fact]
    public void ToolSchemaComesFromTheCatalogParameters()
    {
        var bus = new FakeHostBus { Revision = 1, Rows = $"[{Row}]" };
        var tool = Assert.Single(new CommandSchemaExporter(new BusCommandCatalog(() => bus)).ExportTools());
        Assert.Equal("janus_proj_drop", tool.ToolName);
        Assert.True(tool.Dangerous);
        Assert.Equal("string", tool.InputSchema["properties"]!["name"]!["type"]!.GetValue<string>());
        Assert.Equal("name", tool.InputSchema["required"]![0]!.GetValue<string>());
    }

    /// <summary>只答两条目录指令的宿主替身，Data 与宿主一样是 JsonElement。</summary>
    private sealed class FakeHostBus : ICommandBus
    {
        public long Revision { get; set; }

        public string Rows { get; set; } = "[]";

        public int ListCalls { get; private set; }

        public Task<CommandResult> ExecuteAsync(string text, string source, CancellationToken cancellation = default)
            => InvokeAsync(text, source, cancellation);

        public Task<CommandResult> InvokeAsync(string text, string source, CancellationToken cancellation = default)
        {
            if (text == "vulcan.command.revision")
                return Task.FromResult(CommandResult.Ok("rev", JsonSerializer.SerializeToElement(new { revision = Revision })));
            if (text == "vulcan.command.list")
            {
                ListCalls++;
                using var document = JsonDocument.Parse(Rows);
                return Task.FromResult(CommandResult.Ok("list", document.RootElement.Clone()));
            }

            return Task.FromResult(CommandResult.Fail("未知指令: " + text));
        }

        public bool RequestConfirmation(string prompt) => false;
    }
}
