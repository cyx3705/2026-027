using HistoryVulcan.Core.Mcp;
using HistoryVulcan.Extensibility.Mcp;
using System.Text;
using System.Text.Json;
using HistoryVulcan.Core.Commands;

namespace HistoryPortunus.Mcp;

/// <summary>
/// mcp.* 指令域：Schema、网关生命周期与命令目录入口。
/// </summary>
public static class McpCommands
{
    private static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>把 MCP 服务管理指令注册进指定注册表。</summary>
    public static void RegisterAll(
        CommandRegistry registry, Func<CommandBus?> busAccessor,
        Func<McpGateway?> gateway, HistoryVulcan.Core.Storage.ISettingsService settings,
        PromptGovernanceStore prompts, string source = "app")
    {
        var exporter = new CommandSchemaExporter(registry)
        {
            DescriptionsProvider = prompts.AllEffectiveDescriptions,
        };
        registry.Register(BuildSchema(exporter, registry), source);
        registry.Register(BuildParse(busAccessor), source);
        registry.Register(BuildStart(gateway), source);
        registry.Register(BuildStop(gateway), source);
        registry.Register(BuildStatus(gateway, settings), source);
        registry.Register(BuildAutostart(gateway, settings), source);

        // vulcan.command.list / show / domains / manual 不在这里注册：
        // 它们是宿主的指令自省面，随宿主装配，不随本模块来去。
        // 本模块只经 CommandBus.McpGovernance 把治理那几列交给它们。
    }

    // ---------------------------------------------------------------- portunus.mcp.start / stop / status(MG-05)

    private static CommandDescriptor BuildStart(Func<McpGateway?> gateway) => new()
    {
        Name = "portunus.mcp.start",
        HiddenReason = "防止远程递归管理或关闭 MCP 服务",
        Domain = "portunus",
        CommandClass = "mcp",
        Summary = "启动 MCP 服务(仅 127.0.0.1;策略/令牌经 vulcan.app.set mcp.policy / mcp.token 配置)",
        Example = "portunus.mcp.start port=8737",
        Parameters =
        [
            new ParameterSpec
            {
                Name = "port",
                Description = "监听端口(缺省读 mcp.port;未设置则派生并写入。占用时失败,不改绑)",
                Type = ParamType.Int,
                Position = 0,
            },
        ],
        Handler = CommandDescriptor.Sync(ctx =>
        {
            var g = gateway();
            if (g == null)
                return CommandResult.Fail("网关未装配");
            int? port = ctx.Has("port") ? ctx.GetInt("port") : null;
            var (success, message) = g.Start(port);
            return success ? CommandResult.Ok(message) : CommandResult.Fail(message);
        }),
    };

    private static CommandDescriptor BuildStop(Func<McpGateway?> gateway) => new()
    {
        Name = "portunus.mcp.stop",
        HiddenReason = "防止远程递归管理或关闭 MCP 服务",
        Domain = "portunus",
        CommandClass = "mcp",
        Summary = "停止 MCP 服务并释放端口",
        Example = "portunus.mcp.stop",
        Handler = CommandDescriptor.Sync(_ =>
        {
            var g = gateway();
            if (g == null)
                return CommandResult.Fail("网关未装配");
            var (success, message) = g.Stop();
            return success ? CommandResult.Ok(message) : CommandResult.Fail(message);
        }),
    };

    private static CommandDescriptor BuildStatus(
        Func<McpGateway?> gateway, HistoryVulcan.Core.Storage.ISettingsService settings) => new()
        {
            Name = "portunus.mcp.status",
            HiddenReason = "防止远程递归管理或关闭 MCP 服务",
            Domain = "portunus",
            CommandClass = "mcp",
            Summary = "查看 MCP 服务状态(运行/端口/策略/暴露工具数/累计调用/最近一次调用)",
            Example = "portunus.mcp.status",
            Handler = CommandDescriptor.Sync(_ =>
            {
                var g = gateway();
                if (g == null)
                    return CommandResult.Fail("网关未装配");

                var sb = new StringBuilder();
                sb.Append($"MCP 服务: {(g.IsRunning ? $"运行中 http://127.0.0.1:{g.Port}/mcp" : "未启动(portunus.mcp.start 开启)")}");
                sb.Append($"\n  策略   : {g.Policy}(vulcan.app.set key=mcp.policy value=readonly|standard)");
                sb.Append($"\n  暴露   : {g.VisibleTools().Count} 个工具(portunus.mcp.schema 看全量形态)");
                sb.Append($"\n  令牌   : {(string.IsNullOrEmpty(settings.Get(McpSettingKeys.Token)) ? "未设置(本机回环可信)" : "已设置(Bearer 必需)")}");
                sb.Append($"\n  自启动 : mcp.autostart = {(g.AutostartEnabled ? "true" : "false")}");
                sb.Append($"\n  危险指令: mcp.confirm = {g.ConfirmMode}" +
                          $"{(g.ConfirmMode == "host" ? $"(远程请求宿主弹框确认,{g.ConfirmTimeout}s 超时拒绝)" : "(一律拒绝;host 档开启中继确认)")}");
                sb.Append($"\n  调用   : 累计 {g.CallCount} 次,最近 {g.LastCall}");
                return CommandResult.Ok(sb.ToString());
            }),
        };

    /// <summary>
    /// 持久开关：是否随宿主启动自动监听。与 start/stop 的区别是本命令写设置、跨会话生效。
    /// </summary>
    private static CommandDescriptor BuildAutostart(
        Func<McpGateway?> gateway, HistoryVulcan.Core.Storage.ISettingsService settings) => new()
        {
            Name = "portunus.mcp.autostart",
            HiddenReason = "防止远程递归管理或关闭 MCP 服务",
            Domain = "portunus",
            CommandClass = "mcp",
            Summary = "查看或设置 MCP 随宿主自动监听(持久;省略 enabled 只查看)",
            Example = "portunus.mcp.autostart enabled=true",
            Parameters =
            [
                new ParameterSpec
                {
                    Name = "enabled",
                    Description = "true 随宿主自动监听；false 只能手动 portunus.mcp.start。省略则只报告当前值。",
                    Type = ParamType.Bool,
                    Position = 0,
                },
            ],
            Handler = CommandDescriptor.Sync(ctx =>
            {
                var g = gateway();
                if (g == null)
                    return CommandResult.Fail("网关未装配");

                if (!ctx.Has("enabled"))
                {
                    return CommandResult.Ok(
                        $"mcp.autostart = {(g.AutostartEnabled ? "true" : "false")}"
                        + $"；当前{(g.IsRunning ? $"运行中 http://127.0.0.1:{g.Port}/mcp" : "未监听")}");
                }

                var enabled = ctx.GetBool("enabled", false);
                settings.Set(McpSettingKeys.Autostart, enabled ? "true" : "false");
                return CommandResult.Ok(
                    enabled
                        ? "已开启 MCP 自动监听；下次启动宿主即监听，本次可用 portunus.mcp.start 立即开启。"
                        : "已关闭 MCP 自动监听；本次若在运行用 portunus.mcp.stop 释放端口。");
            }),
        };

    // ---------------------------------------------------------------- portunus.mcp.schema(MC-05)

    private static CommandDescriptor BuildSchema(CommandSchemaExporter exporter, CommandRegistry registry) => new()
    {
        Name = "portunus.mcp.schema",
        HiddenReason = "防止远程递归管理或关闭 MCP 服务",
        Domain = "portunus",
        CommandClass = "mcp",
        Summary = "查看指令的 MCP 工具形态(不带参列全部;带 name 输出单条完整 JSON Schema)",
        Example = "portunus.mcp.schema name=vulcan.command.list",
        Parameters =
        [
            new ParameterSpec
            {
                Name = "name",
                Description = "指令名或工具名(如 vulcan.command.list / command_list);省略列出全部",
                Position = 0,
            },
        ],
        Handler = CommandDescriptor.Sync(ctx =>
        {
            var name = ctx.GetString("name");

            if (!string.IsNullOrWhiteSpace(name))
            {
                var tool = exporter.Find(name.Trim());
                if (tool == null)
                    return CommandResult.Fail($"未找到指令/工具: {name}(或被硬排除,见 portunus.mcp.schema 全量清单)");

                var json = JsonSerializer.Serialize(new
                {
                    name = tool.ToolName,
                    command = tool.CommandName,
                    dangerous = tool.Dangerous,
                    description = tool.Description,
                    inputSchema = tool.InputSchema,
                }, Pretty);
                return CommandResult.Ok(json, tool);
            }

            var tools = exporter.ExportTools();
            var total = registry.All().Count;
            var sb = new StringBuilder();
            sb.Append($"MCP 工具清单: {tools.Count} 个(注册表 {total} 条指令,硬排除 {total - tools.Count} 条):");
            foreach (var t in tools)
            {
                var paramCount = ((System.Text.Json.Nodes.JsonObject?)t.InputSchema["properties"])?.Count ?? 0;
                sb.Append($"\n  {t.ToolName,-28} ← {t.CommandName}");
                if (paramCount > 0)
                    sb.Append($"  [{paramCount} 参数]");
                if (t.Dangerous)
                    sb.Append("  ⚠危险(MCP 拒绝执行)");
            }

            sb.Append("\nportunus.mcp.schema name=<指令名> 查看单条完整 JSON Schema");
            return CommandResult.Ok(sb.ToString(), tools);
        }),
    };

    // ---------------------------------------------------------------- portunus.mcp.parse(MC-06 验收入口)

    private static CommandDescriptor BuildParse(Func<CommandBus?> busAccessor) => new()
    {
        Name = "portunus.mcp.parse",
        HiddenReason = "防止远程递归管理或关闭 MCP 服务",
        Domain = "portunus",
        CommandClass = "mcp",
        Summary = "调试:模拟 tools/call 反向解析——JSON arguments 组装为指令文本,exec=true 随即经总线执行",
        Example = "portunus.mcp.parse command=vulcan.command.list args=\"{}\" exec=true",
        Parameters =
        [
            new ParameterSpec
            {
                Name = "command",
                Description = "目标指令名",
                Required = true,
                Position = 0,
            },
            new ParameterSpec
            {
                Name = "args",
                Description = "JSON 对象文本(工具调用的 arguments)",
                Position = 1,
            },
            new ParameterSpec
            {
                Name = "argsfile",
                Description = "从文件读 JSON(替代 args,规避命令行转义;自动化验收用)",
            },
            new ParameterSpec
            {
                Name = "exec",
                Description = "true 时组装后立即经总线执行(来源 MCP:parse)",
                Type = ParamType.Bool,
                Default = "false",
            },
        ],
        Handler = async ctx =>
        {
            var command = ctx.RequireString("command").Trim();
            var argsText = ctx.GetString("args");
            var argsFile = ctx.GetString("argsfile");
            if (string.IsNullOrWhiteSpace(argsText) && !string.IsNullOrWhiteSpace(argsFile))
            {
                if (!System.IO.File.Exists(argsFile))
                    return CommandResult.Fail($"argsfile 不存在: {argsFile}");
                argsText = await System.IO.File.ReadAllTextAsync(argsFile);
            }

            JsonElement args;
            try
            {
                args = JsonDocument.Parse(string.IsNullOrWhiteSpace(argsText) ? "{}" : argsText)
                    .RootElement.Clone();
            }
            catch (JsonException ex)
            {
                return CommandResult.Fail($"args 不是合法 JSON: {ex.Message}");
            }

            var text = CommandSchemaExporter.BuildCommandText(command, args);
            if (!ctx.GetBool("exec"))
                return CommandResult.Ok($"组装结果: {text}", text);

            var bus = busAccessor();
            if (bus == null)
                return CommandResult.Fail("总线未就绪");

            // 与网关 tools/call 同轨:组装文本经总线执行,回显/留痕走既有通道(铁律 2)
            var result = await bus.ExecuteAsync(text, "MCP:parse");
            return result.Success
                ? CommandResult.Ok($"组装结果: {text}\n执行成功(结果见上一条回显)", text)
                : CommandResult.Fail($"组装结果: {text}\n执行失败(详见上一条回显)");
        },
    };
}
