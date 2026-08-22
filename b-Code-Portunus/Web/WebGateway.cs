using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using HistoryVulcan.Core;
using HistoryVulcan.Core.Clients;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Mcp;
using HistoryVulcan.Core.Storage;
using HistoryVulcan.Extensibility.Mcp;

namespace HistoryPortunus.Web;

/// <summary>
/// 命令总线的本机 HTTP/WS 接入点，只服务同机前端 Shell。
///
/// 3.13.0 删除局域网面（DEC-045）：绑定地址、设备鉴权/配对、令牌、CORS 与限流一并移除。
/// 那套机制两年内没有任何生产装配点——<c>IDeviceAuthenticationProvider</c> 只在测试里被赋值，
/// <c>WebCommands</c> 从未被注册，确认档甚至读的是一个没人写入的 <c>lan.confirm</c> 键。
/// 保留它只会让每次公开面评审背着一份不可达的安全边界。真要局域网访问时，
/// 基于合并后的单网关重写，而不是复活这一套。
/// </summary>
internal sealed partial class WebGateway : IDisposable
{
    /// <summary>网关线协议版本；健康检查回报，前端据此拒绝不兼容的后台。</summary>
    private const string GatewayProtocolVersion = "3.0.0";
    internal const string KeyPort = "web.port";
    internal const string KeyPortRetries = "web.portretries";
    private const int DefaultPortBase = 8938;
    private const int DefaultPortSpan = 200;
    private const int DefaultPortRetries = 20;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles,
    };

    private readonly Func<CommandBus?> _busAccessor;
    private readonly ISettingsService _settings;
    private readonly IShellLog _log;
    private readonly object _lifecycleLock = new();

    private HttpListener? _listener;
    private CancellationTokenSource? _cts;

    public WebGateway(Func<CommandBus?> busAccessor, ISettingsService settings, IShellLog log)
    {
        _busAccessor = busAccessor;
        _settings = settings;
        _log = log;
    }

    public bool IsRunning => _listener is { IsListening: true };

    public string ServerId { get; set; } = AppIdentity.Current.Name;

    public int Port { get; private set; }

    /// <summary>网关固定绑定的本机地址；3.13.0 起不可配置。</summary>
    public const string LoopbackAddress = "127.0.0.1";

    /// <summary>
    /// 本次监听的一次性凭据，由 <see cref="Start"/> 用密码学随机数生成，`Stop` 后作废。
    ///
    /// 存在的理由：回环本身不构成边界。删除局域网面前后，只要带上
    /// <c>X-HistoryVulcan-Client: Shell</c> 头，任何本机进程都能在权威总线上执行任意命令——
    /// 包括 MCP 侧硬排除的 `vulcan.app.quit`、`vulcan.module.install/remove` 和全部
    /// `vulcan.mcp.*`。也就是说 MCP 的策略、隐藏与危险确认在同机范围内可被整体绕过。
    /// 令牌把"我们自己启动的前端"和"任意本机进程"区分开：它只写进
    /// `%AppData%\HistoryVulcan\service\endpoint.json`，随进程生存，不落设置、不可配置、不回显。
    /// </summary>
    public string AccessToken { get; private set; } = "";

    public (bool Success, string Message) Start(int? port = null)
    {
        lock (_lifecycleLock)
        {
            if (IsRunning)
                return (false, $"Web 服务已在运行(端口 {Port})");

            var configured = int.TryParse(
                _settings.Get(KeyPort), System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var configuredPort)
                ? configuredPort
                : (int?)null;
            var initialPort = port ?? configured ?? DeriveDefaultPort(ServerId);
            if (initialPort is < 1024 or > 65535)
                return (false, $"端口无效: {initialPort}(允许 1024~65535)");

            var retries = Math.Clamp(
                _settings.GetInt(KeyPortRetries, DefaultPortRetries), 0, 100);
            Exception? lastError = null;
            for (var attempt = 0; attempt <= retries; attempt++)
            {
                var candidate = initialPort + attempt;
                if (candidate > 65535)
                    break;
                try
                {
                    var listener = new HttpListener();
                    listener.Prefixes.Add($"http://{LoopbackAddress}:{candidate}/");
                    listener.Start();
                    _listener = listener;
                    Port = candidate;
                    break;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    _listener?.Close();
                    _listener = null;
                }
            }

            if (_listener == null)
                return (false,
                    $"监听失败: 从端口 {initialPort} 起连续尝试 {retries + 1} 个端口均不可用: {lastError?.Message}");

            if (port.HasValue || configured.HasValue)
                _settings.Set(KeyPort, Port.ToString(System.Globalization.CultureInfo.InvariantCulture));

            // 每次监听换一枚新凭据：宿主重启后旧 endpoint.json 的残留值立即失效。
            AccessToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

            _cts = new CancellationTokenSource();
            _ = AcceptLoopAsync(_listener, _cts.Token);
            var endpoint = $"http://{LoopbackAddress}:{Port}/";
            _log.Info("web", $"Web 服务已启动: {endpoint}");
            return (true, $"Web 服务已启动: {endpoint}");
        }
    }

    public (bool Success, string Message) Stop()
    {
        lock (_lifecycleLock)
        {
            if (!IsRunning)
                return (false, "Web 服务未在运行");

            var releasedPort = Port;
            _cts?.Cancel();
            _listener?.Close();
            _listener = null;
            _cts?.Dispose();
            _cts = null;
            AccessToken = "";
            Port = 0;
            _log.Info("web", "Web 服务已停止");
            return (true, $"Web 服务已停止(端口 {releasedPort} 已释放)");
        }
    }

    public void Dispose()
    {
        if (IsRunning)
            Stop();
    }

    /// <summary>
    /// 共用实现后顺带获得 MCP 侧原有的健壮性：单次接受失败只记警告并继续，
    /// 不再让一个坏连接冒泡出循环、悄悄终结整条监听。
    /// </summary>
    private Task AcceptLoopAsync(HttpListener listener, CancellationToken cancellationToken)
        => LoopbackHttpTransport.AcceptLoopAsync(
            listener,
            cancellationToken,
            context => HandleAsync(context, cancellationToken),
            failure => _log.Warn("web", $"接收请求失败: {failure}"),
            (context, ex) =>
            {
                _log.Error("web", $"请求处理异常: {ex.GetType().Name}");
                TryClose(context, 500);
            });

    private async Task HandleAsync(HttpListenerContext context, CancellationToken cancellationToken)
    {
        try
        {
            var path = context.Request.Url?.AbsolutePath.TrimEnd('/') ?? "";
            var requestedSession = CreateSession(context.Request);
            var session = Authenticate(context.Request, requestedSession);
            if (session == null)
            {
                await WriteJsonAsync(context, new { error = "unauthorized" }, 401).ConfigureAwait(false);
                return;
            }

            if (path.Equals("/api/health", StringComparison.OrdinalIgnoreCase)
                && context.Request.HttpMethod == "GET")
            {
                await WriteJsonAsync(context, new
                {
                    status = "ok",
                    port = Port,
                    bind = LoopbackAddress,
                    serverId = ServerId,
                    productVersion = AppIdentity.Current.Version,
                    historyVulcanProtocolVersion = GatewayProtocolVersion,
                    minClientVersion = GatewayProtocolVersion,
                    capabilities = new[] { "session-affine-ui", "single-exe" },
                }, 200).ConfigureAwait(false);
                return;
            }

            if (path.Equals("/api/commands", StringComparison.OrdinalIgnoreCase)
                && context.Request.HttpMethod == "GET")
            {
                var bus = _busAccessor();
                if (bus == null)
                {
                    await WriteJsonAsync(context, new { error = "command bus not ready" }, 503).ConfigureAwait(false);
                    return;
                }

                var schemas = new CommandSchemaExporter(bus.Registry).ExportTools()
                    .ToDictionary(tool => tool.CommandName, StringComparer.OrdinalIgnoreCase);
                var commands = bus.Registry.All().Select(descriptor => new
                {
                    descriptor.Name,
                    descriptor.Summary,
                    descriptor.Example,
                    source = bus.Registry.GetSource(descriptor.Name),
                    descriptor.Readonly,
                    dangerous = descriptor.Level == CommandLevel.Ask,
                    // executionSite 随 ExecutionSite 字段一并去掉：它恒为 "Local"，
                    // 全仓没有任何消费方读它，序列化出去只是让接口多一个永不变化的常量。
                    mcpState = McpExposurePolicy.State(descriptor),
                    inputSchema = schemas.GetValueOrDefault(descriptor.Name)?.InputSchema,
                });
                await WriteJsonAsync(context, new { commands }, 200).ConfigureAwait(false);
                return;
            }

            if (path.Equals("/api/command", StringComparison.OrdinalIgnoreCase)
                && context.Request.HttpMethod == "POST")
            {
                var request = await ReadJsonAsync<CommandRequest>(context.Request).ConfigureAwait(false);
                if (request == null || string.IsNullOrWhiteSpace(request.Text))
                {
                    await WriteJsonAsync(context, new { error = "text is required" }, 400).ConfigureAwait(false);
                    return;
                }

                var bus = _busAccessor();
                if (bus == null)
                {
                    await WriteJsonAsync(context, new { error = "command bus not ready" }, 503).ConfigureAwait(false);
                    return;
                }

                // 3.13.0 起唯一能到达这里的会话是同机前端 Shell（见 Authenticate），
                // 它天然持有 admin。原先按 scope 逐条判断只读性的 CanExecute 因此退役。
                var result = await bus.ExecuteAsync(
                    request.Text,
                    SessionSource(session),
                    cancellationToken).ConfigureAwait(false);
                await WriteJsonAsync(context, result, 200).ConfigureAwait(false);
                return;
            }

            await WriteJsonAsync(context, new { error = "not found" }, 404).ConfigureAwait(false);
        }
        catch (InvalidDataException ex)
        {
            _log.Warn("web", $"请求体被拒绝: {ex.Message}");
            TryClose(context, 413);
        }
        catch (JsonException ex)
        {
            _log.Warn("web", $"请求 JSON 无效: {ex.Message}");
            TryClose(context, 400);
        }
        catch (Exception ex)
        {
            _log.Error("web", $"请求处理失败: {ex.Message}");
            TryClose(context, 500);
        }
    }

    /// <summary>
    /// 按请求头造一个候选会话。种类恒为 <see cref="ClientKind.Shell"/>——这是本网关
    /// 唯一会接受的种类，<see cref="Authenticate"/> 负责核对请求头是否真的这么声明。
    ///
    /// 4.2.0 之前这里会把不声明 Shell 的请求归成 <c>ClientKind.Web</c>，而鉴权紧接着
    /// 无条件拒绝它——一道从来没有人通过的门。那不是纵深防御，只是把"未实现"
    /// 写成了"已拒绝"的样子。种类枚举里的 Web 一并退役。
    /// </summary>
    private ClientSession CreateSession(HttpListenerRequest request)
    {
        const ClientKind kind = ClientKind.Shell;
        var name = request.Headers["X-Client-Name"];
        var id = request.Headers["X-Session-Id"];
        id ??= StableSessionId(kind, request.RemoteEndPoint?.Address, name);
        var address = request.RemoteEndPoint?.Address;
        return ClientSession.Create(
            kind,
            name ?? kind.ToString(),
            id: id,
            remoteAddress: address?.ToString(),
            deviceId: request.Headers["X-Device-Id"],
            isLoopback: address != null && IPAddress.IsLoopback(address));
    }

    /// <summary>
    /// 3.13.0 起唯一的接受条件：同机回环上的前端 Shell。
    ///
    /// 删除局域网面后这里不再有"部分授权"的中间态——要么是本机前端（read/operate/admin
    /// 全给），要么直接 401。<c>ClientSession.Scopes</c> 仍然填齐是因为它属于冻结的 Core
    /// 公开面，消费方仍可能读取；本网关只是不再产生任何低于 admin 的会话。
    ///
    /// 三个条件缺一不可：回环、声明为 Shell、持有本次监听的 <see cref="AccessToken"/>。
    /// 前两条只是形状检查（任何本机进程都能伪造），真正的边界是第三条。
    /// </summary>
    private ClientSession? Authenticate(HttpListenerRequest request, ClientSession requested)
    {
        if (!requested.IsLoopback
            || request.Headers["X-HistoryVulcan-Client"]?.Equals(
                "Shell", StringComparison.OrdinalIgnoreCase) != true)
            return null;

        var token = AccessToken;
        var supplied = ReadBearer(request);
        if (string.IsNullOrEmpty(token) || supplied == null || !FixedEquals(token, supplied))
            return null;

        return requested with
        {
            AuthSubject = "loopback-shell",
            Scopes = new HashSet<string>(
                ["read", "operate", "admin"], StringComparer.OrdinalIgnoreCase),
        };
    }

}
