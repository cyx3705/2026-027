using System.IO;
using System.Net;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core;
using HistoryVulcan.Core.Clients;
using HistoryVulcan.Core.Mcp;
using HistoryVulcan.Extensibility.Mcp;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Storage;

using HistoryPortunus.Web;

namespace HistoryPortunus.Mcp;

/// <summary>
/// MCP 网关(V2.1 §4/§6):HttpListener + JSON-RPC 2.0(Streamable HTTP 无状态子集),
/// 仅监听 127.0.0.1。铁律 1:唯一上游是指令总线——本类只认识
/// CommandSchemaExporter / CommandBus,不 import ModuleHost、不反射模块类型。
/// 消费方显式装配网关后可调用 TryAutostart；mcp.autostart=false 可关闭自动监听，vulcan.mcp.start 仍可手动恢复。
/// 每次调用/拒绝均追加写入 state/mcp-history.jsonl(铁律 2 / MS-05)。
/// </summary>
public sealed partial class McpGateway : IDisposable
{
    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public static readonly IReadOnlyList<string> SupportedProtocols = ["2025-06-18", "2025-03-26"];

    private const int DefaultPortBase = 8737;
    private const int DefaultPortSpan = 200;
    private const int DefaultSessionLimit = 1024;
    private const int MaxClientNameLength = 100;
    private const int MaxProtocolVersionLength = 64;
    private const int MaxToolNameLength = 64;
    private readonly Func<CommandBus?> _busAccessor;
    private readonly ISettingsService _settings;
    private readonly IShellLog _log;
    private readonly IMcpAuditLog _history;
    private readonly PromptGovernanceStore _prompts;
    private readonly ApplicationIdentity _identity;

    /// <summary>宿主确认中继对话框(client, 完整提示, 超时秒) → true/false/null;host 档需要。</summary>
    private readonly Func<string, string, int, bool?>? _remoteConfirm;

    /// <summary>CX-02 §9-4:同一时刻只弹一个中继确认框,多个远程请求按序处理。</summary>
    private readonly SemaphoreSlim _confirmGate = new(1, 1);

    private enum RelayConfirmDecision
    {
        Approved,
        Rejected,
        TimedOut,
        QueueTimedOut,
    }

    private readonly object _lifecycleLock = new();

    private CommandSchemaExporter? _exporter;
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<string, ClientSession> _sessions = new(StringComparer.Ordinal);
    private long _callCount;
    private string _lastCall = "(无)";

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public McpGateway(
        Func<CommandBus?> busAccessor, ISettingsService settings, IShellLog log, IMcpAuditLog history,
        PromptGovernanceStore prompts, ApplicationIdentity identity,
        Func<string, string, int, bool?>? remoteConfirm = null)
    {
        _busAccessor = busAccessor;
        _settings = settings;
        _log = log;
        _history = history;
        _prompts = prompts;
        _identity = identity;
        _remoteConfirm = remoteConfirm;
    }

    /// <summary>确认中继模式(CX-02):deny=危险指令一律拒绝(默认);host=宿主弹框人工裁决。</summary>
    public string ConfirmMode
    {
        get
        {
            var m = _settings.Get(McpSettingKeys.Confirm);
            return m != null && m.Equals("host", StringComparison.OrdinalIgnoreCase) ? "host" : "deny";
        }
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public int ConfirmTimeout
        => int.TryParse(
            _settings.Get(McpSettingKeys.ConfirmTimeout), System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out var t)
            ? Math.Clamp(t, 10, 600)
            : 60;

    /// <summary>缺省启用；仅显式配置 false 时关闭宿主启动自动监听。</summary>
    /// <summary>
    /// 是否随宿主启动自动监听。**缺省为 false**：网关会对外开一个回环端口，
    /// 开不开必须由人显式决定，不能因为装配了就默默监听。
    /// 用 <c>vulcan.mcp.autostart enabled=true</c> 打开持久自启动。
    /// </summary>
    public bool AutostartEnabled
        => bool.TryParse(_settings.Get(McpSettingKeys.Autostart), out var enabled) && enabled;

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public bool IsRunning => _listener is { IsListening: true };

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public int Port { get; private set; }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public string Policy
    {
        get
        {
            // 归一化只有一份，在 Core：宿主的 vulcan.command.list 也要按同一规则
            // 判断指令对远端是否可见，两处各写一份迟早会分叉。
            return McpSettingKeys.ResolvePolicy(_settings);
        }
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public long CallCount => Interlocked.Read(ref _callCount);

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public string LastCall => _lastCall;

    /// <summary>
    /// 当前策略下 tools/list 会暴露的工具(每次现算,与模块热重载天然同步)。
    /// 危险指令(带确认闸口)默认不暴露;仅当 mcp.confirm=host 且策略=standard 时暴露,
    /// 供 Codex 发现"可请求、由人把关"的操作(V2.2 CX-02)。
    /// </summary>
    public IReadOnlyList<McpToolInfo> VisibleTools()
    {
        var exporter = GetExporter();
        if (exporter == null)
            return Array.Empty<McpToolInfo>();
        var policy = Policy;
        var relayOn = ConfirmMode == "host" && policy == "standard";
        var registry = _busAccessor()?.Registry;
        if (registry == null)
            return Array.Empty<McpToolInfo>();

        return exporter.ExportTools()
            .Where(t => IsToolCallable(t, registry, policy, relayOn))
            .ToList();
    }

    private static bool IsToolCallable(
        McpToolInfo tool,
        CommandRegistry registry,
        string policy,
        bool relayOn)
    {
        if (!registry.TryGet(tool.CommandName, out var descriptor))
            return false;
        if (descriptor.ExecutionSite == CommandExecutionSite.Frontend
            && !descriptor.AllowMcpExecution)
            return false;
        if (descriptor.IsDangerous)
            return relayOn && McpExposurePolicy.HardExclusionReason(tool.CommandName) == null;
        return McpExposurePolicy.IsVisible(descriptor, policy);
    }

    private CommandSchemaExporter? GetExporter()
    {
        if (_exporter != null)
            return _exporter;
        var bus = _busAccessor();
        if (bus == null)
            return null;
        return _exporter = new CommandSchemaExporter(bus.Registry)
        {
            DescriptionsProvider = _prompts.AllEffectiveDescriptions,
        };
    }

    // ---------------------------------------------------------------- 生命周期(MG-05)

    /// <summary>宿主完成全部指令和模块装配后调用；禁用时不监听但仍视为正常配置。</summary>
    public (bool Success, string Message) TryAutostart()
    {
        if (!AutostartEnabled)
            return (true, "MCP 自动启动已关闭(mcp.autostart=false)");

        var (success, message) = Start(null);
        return (success, success ? $"自启动: {message}" : $"自启动失败: {message}");
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public (bool Success, string Message) Start(int? port)
    {
        lock (_lifecycleLock)
        {
            if (IsRunning)
                return (false, $"MCP 服务已在运行(端口 {Port}),先 vulcan.mcp.stop");

            var configured = int.TryParse(
                _settings.Get(McpSettingKeys.Port), System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var configuredPort)
                ? configuredPort
                : (int?)null;
            var requestedPort = port ?? configured ?? DeriveDefaultPort(_identity.Name);
            if (requestedPort is < 1024 or > 65535)
                return (false, $"端口无效: {requestedPort}(允许 1024~65535)");

            try
            {
                // 只挂根前缀再自行校验路径:HttpListener 前缀须以 / 结尾,
                // 挂 /mcp/ 会漏接不带尾斜杠的 /mcp 请求
                var listener = new HttpListener();
                listener.Prefixes.Add($"http://127.0.0.1:{requestedPort}/");
                listener.Start();
                _listener = listener;
                Port = requestedPort;
            }
            catch (Exception ex)
            {
                _listener?.Close();
                _listener = null;
                return (false,
                    $"监听失败: 端口 {requestedPort} 不可用: {ex.Message}。mcp.port 已固定，不会改绑其他端口。");
            }

            _settings.Set(McpSettingKeys.Port, Port.ToString(System.Globalization.CultureInfo.InvariantCulture));

            _cts = new CancellationTokenSource();
            _ = AcceptLoopAsync(_listener, _cts.Token);
            _log.Info("mcp", $"MCP 服务已启动: http://127.0.0.1:{Port}/mcp(策略 {Policy})");
            return (true, $"MCP 服务已启动: http://127.0.0.1:{Port}/mcp\n策略 {Policy},当前暴露 {VisibleTools().Count} 个工具");
        }
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public (bool Success, string Message) Stop()
    {
        lock (_lifecycleLock)
        {
            if (!IsRunning)
                return (false, "MCP 服务未在运行");

            var releasedPort = Port;
            _cts?.Cancel();
            _listener?.Stop();
            _listener?.Close();
            _listener = null;
            _cts?.Dispose();
            _cts = null;
            _sessions.Clear();
            Port = 0;
            _log.Info("mcp", "MCP 服务已停止");
            return (true, $"MCP 服务已停止(端口 {releasedPort} 已释放)");
        }
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public void Dispose()
    {
        if (IsRunning)
            Stop();
    }

    private static int DeriveDefaultPort(string appName)
        => LoopbackHttpTransport.DerivePort(appName, DefaultPortBase, DefaultPortSpan);

    // ---------------------------------------------------------------- 请求处理

    private Task AcceptLoopAsync(HttpListener listener, CancellationToken ct)
        => LoopbackHttpTransport.AcceptLoopAsync(
            listener,
            ct,
            HandleRequestAsync,
            failure => _log.Warn("mcp", $"接收请求失败: {failure}"),
            (context, ex) =>
            {
                _log.Error("mcp", $"请求处理异常: {ex.GetType().Name}");
                TryClose(context, 500);
            });

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var path = request.Url?.AbsolutePath.TrimEnd('/') ?? "";
        var session = ResolveSession(request);

        if (!path.Equals("/mcp", StringComparison.OrdinalIgnoreCase))
        {
            TryClose(context, 404);
            return;
        }

        if (request.HttpMethod != "POST")
        {
            TryClose(context, 405);
            return;
        }

        // MS-02:可选共享密钥
        var token = _settings.Get(McpSettingKeys.Token);
        if (!string.IsNullOrEmpty(token))
        {
            var suppliedToken = ReadBearer(request);
            if (suppliedToken == null || !FixedEquals(suppliedToken, token))
            {
                RecordMcpSafely(session, "(auth)", "", "拒绝", 0);
                _log.Warn("mcp", "拒绝一次请求: Authorization 缺失或 token 不匹配(MS-02)");
                TryClose(context, 401);
                return;
            }
        }

        string body;
        try
        {
            body = await HttpRequestBodyReader.ReadUtf8Async(request).ConfigureAwait(false);
        }
        catch (DecoderFallbackException)
        {
            await WriteJsonAsync(
                context, RpcError(null, -32700, "请求体不是有效的 UTF-8 JSON"), 400).ConfigureAwait(false);
            return;
        }
        catch (InvalidDataException)
        {
            await WriteJsonAsync(context, RpcError(null, -32600, "请求体过大"), 400).ConfigureAwait(false);
            return;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            await WriteJsonAsync(context, RpcError(null, -32700, "JSON 解析失败"), 200).ConfigureAwait(false);
            return;
        }

        using (doc)
        {
            var root = doc.RootElement;
            var method = root.TryGetProperty("method", out var m) ? m.GetString() ?? "" : "";
            JsonNode? id = root.TryGetProperty("id", out var idEl)
                ? JsonNode.Parse(idEl.GetRawText())
                : null;
            var hasParams = root.TryGetProperty("params", out var prms);

            if (!method.Equals("initialize", StringComparison.Ordinal))
            {
                var requestedProtocol = NormalizeProtocolVersion(
                    request.Headers["MCP-Protocol-Version"], out var validProtocolHeader);
                var effectiveProtocol = string.IsNullOrWhiteSpace(requestedProtocol)
                    ? "2025-03-26"
                    : requestedProtocol;
                if (!validProtocolHeader
                    || !SupportedProtocols.Contains(effectiveProtocol, StringComparer.Ordinal))
                {
                    if (method.Equals("tools/call", StringComparison.Ordinal))
                    {
                        RecordMcpSafely(
                            session,
                            "<invalid>",
                            RedactUnknownAuditArguments(hasParams ? prms : null),
                            "拒绝·协议版本",
                            0);
                    }
                    await WriteJsonAsync(
                        context,
                        RpcError(id, -32600, $"不支持的 MCP-Protocol-Version: {effectiveProtocol}"),
                        400).ConfigureAwait(false);
                    return;
                }

                session = session with { ProtocolVersion = effectiveProtocol };
                _sessions[session.Id] = session;
                TrimSessions(session.Id);
            }

            // 通知(无 id)只确认收到,不回 JSON-RPC 响应体
            if (id == null && method.StartsWith("notifications/", StringComparison.Ordinal))
            {
                TryClose(context, 202);
                return;
            }

            var response = method switch
            {
                "initialize" => HandleInitialize(context.Response, session, id, hasParams ? prms : null),
                "ping" => RpcResult(id, new JsonObject()),
                "tools/list" => HandleToolsList(id),
                "tools/call" => await HandleToolsCallAsync(session, id, hasParams ? prms : null).ConfigureAwait(false),
                _ => RpcError(id, -32601, $"method not found: {method}"),
            };

            await WriteJsonAsync(context, response, 200).ConfigureAwait(false);
        }
    }

    // ---------------------------------------------------------------- JSON-RPC 方法

    private JsonObject HandleInitialize(
        HttpListenerResponse response,
        ClientSession session,
        JsonNode? id,
        JsonElement? prms)
    {
        var clientName = session.Name;
        if (prms is { ValueKind: JsonValueKind.Object } p
            && p.TryGetProperty("clientInfo", out var ci)
            && ci.ValueKind == JsonValueKind.Object
            && ci.TryGetProperty("name", out var cn)
            && cn.ValueKind == JsonValueKind.String)
        {
            clientName = NormalizeClientName(cn.GetString(), session.Name);
        }

        var rawProtocol = prms is { ValueKind: JsonValueKind.Object } pv
                          && pv.TryGetProperty("protocolVersion", out var ver)
                          && ver.ValueKind == JsonValueKind.String
            ? ver.GetString()
            : null;
        var requestedProtocol = NormalizeProtocolVersion(rawProtocol, out var validProtocol);
        if (string.IsNullOrWhiteSpace(requestedProtocol))
            requestedProtocol = "2025-03-26";
        var protocolVersion = validProtocol
                              && SupportedProtocols.Contains(requestedProtocol, StringComparer.Ordinal)
            ? requestedProtocol
            : SupportedProtocols[0];
        if (!requestedProtocol.Equals(protocolVersion, StringComparison.Ordinal))
            _log.Warn("mcp", $"客户端请求未知协议 {requestedProtocol},已协商为 {protocolVersion}");

        session = session with { Name = clientName, ProtocolVersion = protocolVersion };
        _sessions[session.Id] = session;
        TrimSessions(session.Id);
        response.Headers["Mcp-Session-Id"] = session.Id;
        _log.Info("mcp", $"客户端握手: {session.Name}({session.Id}) 协议 {protocolVersion}");
        return RpcResult(id, new JsonObject
        {
            ["protocolVersion"] = protocolVersion,
            ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
            ["serverInfo"] = new JsonObject
            {
                ["name"] = _identity.Name,
                ["version"] = _identity.Version,
            },
        });
    }

    private JsonObject HandleToolsList(JsonNode? id)
    {
        var tools = new JsonArray();
        foreach (var t in VisibleTools())
        {
            var description = t.Dangerous
                ? t.Description + "\n⚠ 危险操作:调用会请求宿主端人工确认(mcp.confirm=host),批准后才执行。"
                : t.Description;
            tools.Add(new JsonObject
            {
                ["name"] = t.ToolName,
                ["description"] = description,
                ["inputSchema"] = JsonNode.Parse(t.InputSchema.ToJsonString()),
            });
        }

        return RpcResult(id, new JsonObject { ["tools"] = tools });
    }

    private async Task<JsonObject> HandleToolsCallAsync(
        ClientSession session,
        JsonNode? id,
        JsonElement? prms)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var audited = false;
        var auditTool = "<invalid>";
        var auditArguments = RedactUnknownAuditArguments(prms);

        void Audit(string tool, string arguments, string result)
        {
            if (audited)
                return;
            audited = true;
            RecordMcpSafely(session, tool, arguments, result, sw.ElapsedMilliseconds);
        }

        try
        {
            if (prms is not { ValueKind: JsonValueKind.Object } p)
            {
                Audit("<missing>", RedactUnknownAuditArguments(prms), "拒绝");
                return RpcError(id, -32602, "缺少工具名 params.name");
            }

            JsonElement? arguments = p.TryGetProperty("arguments", out var args) ? args.Clone() : null;
            auditArguments = RedactUnknownAuditArguments(arguments);
            if (!p.TryGetProperty("name", out var nameEl)
                || nameEl.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(nameEl.GetString()))
            {
                Audit("<missing>", auditArguments, "拒绝");
                return RpcError(id, -32602, "缺少工具名 params.name");
            }

            var toolName = nameEl.GetString()!;
            if (!IsValidToolName(toolName))
            {
                Audit("<invalid>", auditArguments, "拒绝");
                return RpcError(id, -32602, "工具名无效");
            }
            auditTool = "<unknown>";

            var exporter = GetExporter();
            if (exporter == null)
            {
                Audit("<unavailable>", auditArguments, "拒绝");
                return RpcError(id, -32603, "宿主总线未就绪");
            }
            var tool = exporter?.Find(toolName);
            if (tool == null)
            {
                Audit(auditTool, auditArguments, "拒绝");
                return RpcError(id, -32602, $"未知工具: {toolName}");
            }

            var argsText = RedactAuditArguments(tool.CommandName, arguments);
            auditTool = tool.ToolName;
            auditArguments = argsText;
            var bus = _busAccessor();
            if (bus == null)
            {
                Audit(tool.ToolName, argsText, "拒绝");
                return RpcError(id, -32603, "宿主总线未就绪");
            }

            var policy = Policy;
            var relayOn = ConfirmMode == "host" && policy == "standard";
            if (!IsToolCallable(tool, bus.Registry, policy, relayOn))
            {
                Audit(tool.ToolName, argsText, "拒绝");
                _log.Warn("mcp", $"拒绝调用(工具未对 MCP 开放): {tool.ToolName}");
                return RpcResult(id, ToolText(
                    $"已拒绝: {tool.CommandName} 未在当前 MCP 策略下开放执行。",
                    isError: true));
            }

            var commandText = CommandSchemaExporter.BuildCommandText(tool.CommandName, arguments);

            // 危险指令(总线确认闸口类):按 mcp.confirm 处置(CX-02 / MS-04)
            if (tool.Dangerous)
            {
                if (ConfirmMode != "host")
                {
                    Audit(tool.ToolName, argsText, "拒绝");
                    _log.Warn("mcp", $"拒绝危险工具调用: {tool.ToolName}(mcp.confirm=deny)");
                    return RpcResult(id, ToolText(
                        $"已拒绝: {tool.CommandName} 是需二次确认的危险指令。当前 mcp.confirm=deny;" +
                        "宿主执行 vulcan.app.set key=mcp.confirm value=host 后,远程请求将弹框由人工裁决。",
                        isError: true));
                }

                if (Policy == "readonly")
                {
                    Audit(tool.ToolName, argsText, "拒绝");
                    return RpcResult(id, ToolText(
                        $"已拒绝: 当前策略为 readonly,不受理危险指令;宿主切 standard 后方可经中继确认执行。",
                        isError: true));
                }

                var decision = await RelayConfirmAsync(session, bus, tool.CommandName, arguments, commandText)
                    .ConfigureAwait(false);
                if (decision == RelayConfirmDecision.Rejected)
                {
                    Audit(tool.ToolName, argsText, "远程拒绝");
                    _log.Warn("mcp", $"中继确认:宿主拒绝 {tool.ToolName}");
                    return RpcResult(id, ToolText("宿主已拒绝该远程请求(人工点否)。", isError: true));
                }

                if (decision == RelayConfirmDecision.TimedOut)
                {
                    Audit(tool.ToolName, argsText, "确认超时");
                    _log.Warn("mcp", $"中继确认:超时拒绝 {tool.ToolName}");
                    return RpcResult(id, ToolText(
                        $"确认超时({ConfirmTimeout}s 内无人操作),已按拒绝处理。", isError: true));
                }

                if (decision == RelayConfirmDecision.QueueTimedOut)
                {
                    Audit(tool.ToolName, argsText, "确认排队超时");
                    _log.Warn("mcp", $"中继确认:排队超时拒绝 {tool.ToolName}");
                    return RpcResult(id, ToolText(
                        $"确认排队超时({ConfirmTimeout}s),已按拒绝处理。", isError: true));
                }

                _log.Info("mcp", $"中继确认:宿主批准 {tool.ToolName},执行中");
                return await ExecuteToolAsync(session, id, bus, tool, commandText, argsText,
                    preApproved: true, relayNote: "远程确认通过", audit: Audit).ConfigureAwait(false);
            }

            // §6.2:readonly 档优先读取命令自描述；名称白名单仅为迁移兼容层。
            if (Policy == "readonly"
                && (!bus.Registry.TryGet(tool.CommandName, out var descriptor)
                    || (!descriptor.Readonly && !McpExposurePolicy.IsReadonlyAllowed(tool.CommandName))))
            {
                Audit(tool.ToolName, argsText, "拒绝");
                _log.Warn("mcp", $"拒绝调用(策略 readonly 未暴露): {tool.ToolName}");
                return RpcResult(id, ToolText(
                    $"已拒绝: 当前暴露策略为 readonly,{tool.CommandName} 未开放;宿主执行 vulcan.app.set key=mcp.policy value=standard 可放开动作类指令",
                    isError: true));
            }

            return await ExecuteToolAsync(session, id, bus, tool, commandText, argsText,
                preApproved: false, relayNote: null, audit: Audit).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Audit(auditTool, auditArguments, "异常");
            var error = ex.GetType().Name;
            _log.Error("mcp", $"工具调用异常: {error}");
            return RpcError(id, -32603, $"工具调用失败: {error}");
        }
    }

    private static string RedactAuditArguments(string commandName, JsonElement? arguments)
    {
        try
        {
            if (arguments == null)
                return "{}";
            if (arguments.Value.ValueKind != JsonValueKind.Object)
                return JsonSerializer.Serialize("[REDACTED]");

            var node = JsonNode.Parse(arguments.Value.GetRawText());

            var tokenCommand = commandName.Equals("vulcan.web.token", StringComparison.OrdinalIgnoreCase)
                               || commandName.Equals("vulcan.mcp.token", StringComparison.OrdinalIgnoreCase);
            var settingCommand = commandName.Equals("vulcan.app.set", StringComparison.OrdinalIgnoreCase);
            string? settingKey = null;
            var hasUniqueSettingKey = settingCommand
                                      && TryGetUniqueStringProperty(arguments.Value, "key", out settingKey);
            var redactRootValues = tokenCommand
                                   || settingCommand
                                   && (!hasUniqueSettingKey || IsSensitiveSettingKey(settingKey!));
            RedactNode(node, redactRootValues, preserveRootKey: settingCommand && hasUniqueSettingKey);
            return node?.ToJsonString() ?? "null";
        }
        catch (Exception)
        {
            return JsonSerializer.Serialize("[REDACTED]");
        }
    }

    private static string RedactUnknownAuditArguments(JsonElement? arguments)
        => arguments == null ? "{}" : JsonSerializer.Serialize("[REDACTED]");

    private static void RedactNode(
        JsonNode? node,
        bool redactRootValues = false,
        bool preserveRootKey = false,
        bool isRoot = true)
    {
        if (node is JsonObject obj)
        {
            foreach (var property in obj.ToList())
            {
                if (IsSensitiveArgument(property.Key)
                    || isRoot && redactRootValues
                    && !(preserveRootKey && property.Key.Equals("key", StringComparison.OrdinalIgnoreCase)))
                {
                    obj[property.Key] = "[REDACTED]";
                }
                else
                {
                    RedactNode(property.Value, isRoot: false);
                }
            }
            return;
        }

        if (node is JsonArray array)
        {
            foreach (var item in array)
                RedactNode(item, isRoot: false);
        }
    }

    private static bool TryGetUniqueStringProperty(JsonElement element, string name, out string? value)
    {
        value = null;
        if (element.ValueKind != JsonValueKind.Object)
            return false;
        var found = false;
        foreach (var property in element.EnumerateObject())
        {
            if (!property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                continue;
            if (found || property.Value.ValueKind != JsonValueKind.String)
            {
                value = null;
                return false;
            }
            found = true;
            value = property.Value.GetString();
        }
        return found && value != null;
    }

    private static bool IsSensitiveArgument(string name)
    {
        var normalized = NormalizeSensitiveName(name);
        return normalized.Equals("code", StringComparison.OrdinalIgnoreCase)
               || normalized.EndsWith("token", StringComparison.OrdinalIgnoreCase)
               || normalized.EndsWith("password", StringComparison.OrdinalIgnoreCase)
               || normalized.EndsWith("passwd", StringComparison.OrdinalIgnoreCase)
               || normalized.EndsWith("secret", StringComparison.OrdinalIgnoreCase)
               || normalized.EndsWith("privatekey", StringComparison.OrdinalIgnoreCase)
               || normalized.EndsWith("connectionstring", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSensitiveSettingKey(string key)
        => IsSensitiveArgument(key);

    private static string NormalizeSensitiveName(string name)
        => name.Replace(".", "", StringComparison.Ordinal)
            .Replace("_", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal);

    private static bool IsValidToolName(string name)
        => name.Length is > 0 and <= MaxToolNameLength
           && name.All(character => char.IsAsciiLetterOrDigit(character)
                                    || character is '_' or '-' or '.');

    /// <summary>组装指令经总线执行并映射为 MCP 结果;preApproved=true 时置确认预批准域(CX-03)。</summary>
    private async Task<JsonObject> ExecuteToolAsync(
        ClientSession session, JsonNode? id, CommandBus bus, McpToolInfo tool, string commandText, string argsText,
        bool preApproved, string? relayNote, Action<string, string, string> audit)
    {
        var timeoutSeconds = int.TryParse(
            _settings.Get(McpSettingKeys.Timeout), System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out var t)
            ? Math.Clamp(t, 5, 3600)
            : 120;
        Task<CommandResult> Run() => bus.ExecuteAsync(commandText, $"MCP:{session.Name}");
        var execTask = preApproved
            ? McpConfirmationScope.RunPreApprovedAsync(Run)
            : Run();

        var finished = await Task.WhenAny(execTask, Task.Delay(TimeSpan.FromSeconds(timeoutSeconds)))
            .ConfigureAwait(false);

        Interlocked.Increment(ref _callCount);

        if (finished != execTask)
        {
            // MG-07:超时只切断响应,不撕裂总线执行——指令继续跑完并留痕
            _lastCall = $"{tool.ToolName}(超时 {timeoutSeconds}s)";
            audit(tool.ToolName, argsText, Note(relayNote, "超时"));
            return RpcResult(id, ToolText(
                $"执行超时({timeoutSeconds}s): 指令仍在宿主内继续执行并留痕,可稍后经只读指令查询结果",
                isError: true));
        }

        var result = await execTask.ConfigureAwait(false);
        _lastCall = $"{tool.ToolName} → {(result.Success ? "成功" : "失败")}";
        audit(tool.ToolName, argsText, Note(relayNote, result.Success ? "成功" : "失败"));

        // HistoryVulcan 0.5.0:保留既有文本块以兼容旧客户端,并加发 structuredContent.data。
        // 结构化字段从同一份 legacyJson 派生,确保新旧载荷语义一致。
        var content = new JsonArray
        {
            new JsonObject { ["type"] = "text", ["text"] = result.Message },
        };
        JsonNode? structuredData = null;
        if (result.Success && result.Data != null)
        {
            try
            {
                var legacyJson = JsonSerializer.Serialize(result.Data, DataJson);
                content.Add(new JsonObject { ["type"] = "text", ["text"] = legacyJson });
                structuredData = JsonNode.Parse(legacyJson);
            }
            catch (Exception)
            {
                // Data 序列化失败不影响文本结果(如含 WPF 类型的对象);结构化字段同时不发
                structuredData = null;
            }
        }

        var payload = new JsonObject
        {
            ["content"] = content,
            ["isError"] = !result.Success,
        };
        if (structuredData != null)
        {
            // 规范要求 structuredContent 为 JSON 对象;Data 有数组/对象/字符串三态,统一 data 信封
            payload["structuredContent"] = new JsonObject { ["data"] = structuredData };
        }

        return RpcResult(id, payload);

        static string Note(string? note, string outcome)
            => note == null ? outcome : $"{note}·{outcome}";
    }

    /// <summary>
    /// 宿主确认中继(CX-02):复用描述符 ConfirmPrompt 文案,标注 MCP 客户端弹框由人裁决。
    /// 返回批准、拒绝、确认超时或排队超时。ConfirmPrompt 对本次输入返回 null
    /// (如受保护分支)时直接放行,交由指令处理器按业务规则拒绝。
    /// </summary>
    private async Task<RelayConfirmDecision> RelayConfirmAsync(
        ClientSession session, CommandBus bus, string commandName, JsonElement? arguments, string commandText)
    {
        if (_remoteConfirm == null)
            return RelayConfirmDecision.Rejected; // 无对话通道 → 安全缺省拒绝

        var prompt = BuildConfirmPrompt(session, bus, commandName, arguments);
        if (prompt == null)
            return RelayConfirmDecision.Approved; // 本次输入无需人工确认(处理器自行判定)

        var full = $"【MCP 客户端 “{session.Name}” 的远程请求】\n\n{prompt}\n\n等价指令: {commandText}";
        var timeoutSeconds = ConfirmTimeout;
        var entered = await _confirmGate.WaitAsync(TimeSpan.FromSeconds(timeoutSeconds)).ConfigureAwait(false);
        if (!entered)
            return RelayConfirmDecision.QueueTimedOut;
        try
        {
            return _remoteConfirm(session.Name, full, timeoutSeconds) switch
            {
                true => RelayConfirmDecision.Approved,
                false => RelayConfirmDecision.Rejected,
                null => RelayConfirmDecision.TimedOut,
            };
        }
        finally
        {
            _confirmGate.Release();
        }
    }

    private void RecordMcpSafely(
        ClientSession session,
        string tool,
        string arguments,
        string result,
        long elapsedMs)
    {
        try
        {
            _history.RecordMcp(session, tool, arguments, result, elapsedMs);
        }
        catch (Exception ex)
        {
            _log.Error("mcp", $"MCP 留痕实现异常: {ex.GetType().Name}");
        }
    }

}
