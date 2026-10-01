using System.Text.Json;
using HistoryVulcan.Core.Commands;

namespace HistoryPortunus.Mcp;

/// <summary>目录里一条指令的参数（<c>vulcan.command.list</c> 行里 <c>parameters[]</c> 的一项）。</summary>
public sealed record CatalogParameter(
    string Name,
    string Type,
    bool Required,
    string? Default,
    int? Position,
    IReadOnlyList<string> AllowedValues,
    string Description);

/// <summary>
/// 目录里的一条指令：网关投影 MCP 工具、判定可见性所需的全部事实。
/// </summary>
/// <remarks>
/// 1.1.0 起按宿主 6.0.0 统一契约从 <c>vulcan.command.list</c> 的 JSON 读出（字段名以宿主模块开发手册「宿主指令的 Data」为准），
/// 不再持有宿主注册表里的 <c>CommandDescriptor</c>。宿主内部类怎么改都不影响这里。
/// </remarks>
public sealed record CatalogCommand(
    string Name,
    string Summary,
    string? Example,
    string Source,
    bool Ask,
    bool Readonly,
    string? HiddenReason,
    bool AllowUnspecifiedParameters,
    IReadOnlyList<CatalogParameter> Parameters)
{
    /// <summary>按 C7 形状读一行；读不出名字时返回 null。</summary>
    public static CatalogCommand? FromJson(JsonElement row)
    {
        var name = Text(row, "commandName");
        if (string.IsNullOrWhiteSpace(name))
            return null;
        var source = Text(row, "source") ?? "";
        var detail = Text(row, "sourceDetail");
        var parameters = new List<CatalogParameter>();
        if (row.TryGetProperty("parameters", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in list.EnumerateArray())
            {
                var parameterName = Text(item, "name");
                if (string.IsNullOrWhiteSpace(parameterName))
                    continue;
                var allowed = item.TryGetProperty("allowedValues", out var values) && values.ValueKind == JsonValueKind.Array
                    ? values.EnumerateArray().Select(value => value.GetString() ?? "").ToArray()
                    : [];
                parameters.Add(new CatalogParameter(
                    parameterName,
                    Text(item, "type") ?? "string",
                    Flag(item, "required"),
                    Text(item, "default"),
                    item.TryGetProperty("position", out var position) && position.ValueKind == JsonValueKind.Number
                        ? position.GetInt32()
                        : null,
                    allowed,
                    Text(item, "description") ?? ""));
            }
        }

        return new CatalogCommand(
            name,
            Text(row, "summary") ?? "",
            Text(row, "example"),
            detail is { Length: > 0 } ? $"{source}:{detail}" : source,
            Flag(row, "dangerous"),
            Flag(row, "readonly"),
            Text(row, "hiddenReason"),
            Flag(row, "allowUnspecifiedParameters"),
            parameters);
    }

    private static string? Text(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool Flag(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
}

/// <summary>网关看得到的指令目录。</summary>
public interface ICommandCatalog
{
    /// <summary>当前全部指令，按名称排序。</summary>
    IReadOnlyList<CatalogCommand> All();

    /// <summary>按名称取一条。</summary>
    bool TryGet(string name, out CatalogCommand command);
}

/// <summary>
/// 经总线读宿主目录：<c>vulcan.command.revision</c> 不变就用缓存，变了才重拉 <c>vulcan.command.list</c>。
/// </summary>
/// <remarks>
/// 两条都是只读、同步完成的宿主指令，走安静执行（不回显、不进控制台）。
/// 每次取目录先问一次版本号——模块热重载后下一次 tools/list 就看得到新指令，不必等事件。
/// </remarks>
public sealed class BusCommandCatalog(Func<ICommandBus?> busAccessor) : ICommandCatalog
{
    private readonly object _gate = new();
    private long _revision = -1;
    private IReadOnlyList<CatalogCommand> _commands = [];
    private Dictionary<string, CatalogCommand> _byName = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<CatalogCommand> All()
    {
        Refresh();
        lock (_gate)
            return _commands;
    }

    public bool TryGet(string name, out CatalogCommand command)
    {
        Refresh();
        lock (_gate)
            return _byName.TryGetValue(name, out command!);
    }

    private void Refresh()
    {
        var bus = busAccessor();
        if (bus == null)
            return;

        var revisionResult = bus.InvokeAsync("vulcan.command.revision", "").GetAwaiter().GetResult();
        var revision = revisionResult.Success && revisionResult.Data is JsonElement data
                       && data.TryGetProperty("revision", out var value) && value.TryGetInt64(out var parsed)
            ? parsed
            : -2;
        lock (_gate)
        {
            if (revision >= 0 && revision == _revision)
                return;
        }

        var listed = bus.InvokeAsync("vulcan.command.list", "").GetAwaiter().GetResult();
        if (!listed.Success || listed.Data is not JsonElement { ValueKind: JsonValueKind.Array } rows)
            return;
        var commands = rows.EnumerateArray()
            .Select(CatalogCommand.FromJson)
            .OfType<CatalogCommand>()
            .OrderBy(command => command.Name, StringComparer.Ordinal)
            .ToList();
        lock (_gate)
        {
            _commands = commands;
            _byName = commands.ToDictionary(command => command.Name, StringComparer.OrdinalIgnoreCase);
            _revision = revision;
        }
    }
}
