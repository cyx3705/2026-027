using System.Text.Json;
using System.Text.Json.Nodes;

namespace HistoryPortunus.Mcp;

/// <summary>
/// 精简形态(mcp.surface=compact):tools/list 只列 find 与 call 两个元工具。
/// 客户端常驻上下文从「每条指令一份 Schema」降到两份，与指令总数无关；
/// 要用哪条再 find 取它的 Schema，按需付费。可见范围与 full 完全相同(都出自 VisibleTools)。
/// </summary>
public sealed partial class McpGateway
{
    /// <summary>精简形态的搜索元工具名。</summary>
    public const string FindToolName = "portunus_find";

    /// <summary>精简形态的调用元工具名。</summary>
    public const string CallToolName = "portunus_call";

    private const int DefaultFindLimit = 8;
    private const int MaxFindLimit = 30;

    private JsonArray CompactTools()
    {
        var visible = VisibleTools();
        var domains = string.Join("、", visible
            .GroupBy(t => DomainOf(t.CommandName), StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => $"{g.Key}({g.Count()})"));

        return
        [
            new JsonObject
            {
                ["name"] = FindToolName,
                ["description"] =
                    $"搜索 HistoryVulcan 的指令，返回匹配指令的说明与参数 JSON Schema(调用前先搜)。当前可用 {visible.Count} 条，按域: {domains}。" +
                    "\n示例: query=\"aurora.ui\" 取一个命令类；query=\"提交 项目\" 多词须全部命中(名称或说明)。",
                ["inputSchema"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["query"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["description"] = "空格分隔的关键词，匹配指令名或说明；省略则只列各域指令名",
                        },
                        ["limit"] = new JsonObject
                        {
                            ["type"] = "integer",
                            ["description"] = $"最多返回几条完整 Schema(缺省 {DefaultFindLimit},上限 {MaxFindLimit});其余只列名",
                        },
                    },
                    ["additionalProperties"] = false,
                },
            },
            new JsonObject
            {
                ["name"] = CallToolName,
                ["description"] =
                    $"执行一条 HistoryVulcan 指令。name 用 {FindToolName} 返回的指令名，arguments 按其 inputSchema 填写。" +
                    "策略、危险指令处置与留痕和逐条直调完全相同。",
                ["inputSchema"] = new JsonObject
                {
                    ["type"] = "object",
                    ["properties"] = new JsonObject
                    {
                        ["name"] = new JsonObject
                        {
                            ["type"] = "string",
                            ["description"] = "指令名(如 janus.proj.list)或工具名(如 janus_proj_list)",
                        },
                        ["arguments"] = new JsonObject
                        {
                            ["type"] = "object",
                            ["description"] = "指令参数对象；无参指令可省略",
                        },
                    },
                    ["required"] = new JsonArray { "name" },
                    ["additionalProperties"] = false,
                },
            },
        ];
    }

    /// <summary>
    /// 关键词全部命中(指令名、工具名或说明，忽略大小写)才算匹配；名称命中的排前。
    /// 不带 query 时只给各域指令名——194 条全量 Schema 正是精简形态要省掉的东西。
    /// </summary>
    private JsonObject HandleFind(JsonElement? arguments)
    {
        string? query = null;
        var limit = DefaultFindLimit;
        if (arguments is { ValueKind: JsonValueKind.Object } a)
        {
            if (a.TryGetProperty("query", out var q) && q.ValueKind == JsonValueKind.String)
                query = q.GetString();
            if (a.TryGetProperty("limit", out var l) && l.ValueKind == JsonValueKind.Number && l.TryGetInt32(out var n))
                limit = Math.Clamp(n, 1, MaxFindLimit);
        }

        var visible = VisibleTools();
        var terms = (query ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        JsonObject payload;
        if (terms.Length == 0)
        {
            var domains = new JsonObject();
            foreach (var g in visible
                         .GroupBy(t => DomainOf(t.CommandName), StringComparer.OrdinalIgnoreCase)
                         .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
                domains[g.Key] = new JsonArray(g.Select(t => (JsonNode?)JsonValue.Create(t.CommandName)).ToArray());
            payload = new JsonObject
            {
                ["total"] = visible.Count,
                ["hint"] = "带 query 取完整说明与 Schema",
                ["domains"] = domains,
            };
        }
        else
        {
            var matches = visible
                .Select(t => (Tool: t, Score: Score(t, terms)))
                .Where(m => m.Score >= 0)
                .OrderByDescending(m => m.Score)
                .ThenBy(m => m.Tool.CommandName, StringComparer.OrdinalIgnoreCase)
                .Select(m => m.Tool)
                .ToList();

            var shown = new JsonArray();
            foreach (var t in matches.Take(limit))
            {
                var item = new JsonObject
                {
                    ["name"] = t.CommandName,
                    ["description"] = t.Description,
                    ["inputSchema"] = JsonNode.Parse(t.InputSchema.ToJsonString()),
                };
                if (t.Dangerous)
                    item["dangerous"] = true;
                shown.Add(item);
            }

            payload = new JsonObject
            {
                ["total"] = matches.Count,
                ["tools"] = shown,
            };
            if (matches.Count > limit)
            {
                payload["more"] = new JsonArray(matches.Skip(limit)
                    .Select(t => (JsonNode?)JsonValue.Create(t.CommandName)).ToArray());
            }
        }

        return ToolText(payload.ToJsonString(DataJson), isError: false);
    }

    /// <summary>-1 = 不匹配；否则名称命中的词数加权，便于把「名字里就有」的排在前面。</summary>
    private static int Score(McpToolInfo tool, string[] terms)
    {
        var score = 0;
        foreach (var term in terms)
        {
            var inName = tool.CommandName.Contains(term, StringComparison.OrdinalIgnoreCase)
                         || tool.ToolName.Contains(term, StringComparison.OrdinalIgnoreCase);
            if (inName)
                score += 2;
            else if (tool.Description.Contains(term, StringComparison.OrdinalIgnoreCase))
                score += 1;
            else
                return -1;
        }
        return score;
    }

    private static bool TryUnwrapCall(JsonElement? arguments, out string name, out JsonElement? inner)
    {
        name = "";
        inner = null;
        if (arguments is not { ValueKind: JsonValueKind.Object } a
            || !a.TryGetProperty("name", out var n)
            || n.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(n.GetString()))
            return false;

        if (a.TryGetProperty("arguments", out var args))
        {
            if (args.ValueKind == JsonValueKind.Null)
                args = default;
            else if (args.ValueKind != JsonValueKind.Object)
                return false;
        }

        name = n.GetString()!.Trim();
        // 不允许嵌套:call 套 call/find 没有意义，只会让留痕看不清真正执行了什么
        if (name.Equals(CallToolName, StringComparison.Ordinal) || name.Equals(FindToolName, StringComparison.Ordinal))
            return false;
        inner = args.ValueKind == JsonValueKind.Object ? args.Clone() : null;
        return true;
    }

    private static string DomainOf(string commandName)
    {
        var dot = commandName.IndexOf('.');
        return dot > 0 ? commandName[..dot] : commandName;
    }
}
