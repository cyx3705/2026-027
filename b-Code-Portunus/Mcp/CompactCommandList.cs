using System.Text;
using System.Text.Json;

namespace HistoryPortunus.Mcp;

// REQ-PORTUNUS-CATALOG-001：只精简这条指令的 MCP 投影，宿主总线的目录仍供各模块消费。
internal static class CompactCommandList
{
    internal const string Name = "vulcan.command.list";

    internal static bool Is(string name) => name.Equals(Name, StringComparison.OrdinalIgnoreCase);

    internal static string Describe(IReadOnlyList<CatalogCommand> commands)
    {
        const int budget = 2048;
        var text = new StringBuilder("列出指令名和短简介，可按域筛选。模块速览：");
        var domains = commands.GroupBy(command => command.Name.Split('.')[0], StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase);
        foreach (var domain in domains)
        {
            var classes = domain.GroupBy(command => command.Name.Split('.') is { Length: >= 3 } parts ? parts[1] : "",
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(group => group.Count()).ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .Take(3).Select(group => Shorten(Cell(group.OrderBy(command => command.Name, StringComparer.Ordinal)
                    .First().Summary), 12));
            var categories = string.Join("/", classes);
            var entry = domain.Key + (categories.Length == 0 ? "" : "=" + categories) + "；";
            if (text.Length + entry.Length >= budget)
            {
                text.Append('…');
                break;
            }
            text.Append(entry);
        }
        return text.ToString().TrimEnd('；');
    }

    internal static string? Render(object? data)
    {
        if (data is not JsonElement { ValueKind: JsonValueKind.Array } rows)
            return null;
        var text = new StringBuilder("| 指令 | 简介 |\n| --- | --- |");
        foreach (var row in rows.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty("commandName", out var name)
                || name.ValueKind != JsonValueKind.String)
                return null;
            var summary = row.TryGetProperty("summary", out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()! : "";
            text.Append("\n| ").Append(Cell(name.GetString()!)).Append(" | ")
                .Append(Shorten(Cell(summary))).Append(" |");
        }
        return text.ToString();
    }

    private static string Cell(string value)
        => string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).Replace('|', '｜');

    private static string Shorten(string value, int limit = 30)
    {
        var runes = value.EnumerateRunes().Take(limit + 1).ToArray();
        return runes.Length <= limit ? value
            : string.Concat(runes.Take(limit - 1).Select(rune => rune.ToString())) + "…";
    }
}
