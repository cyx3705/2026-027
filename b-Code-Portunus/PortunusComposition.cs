using HistoryPortunus.Mcp;
using HistoryPortunus.Web;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Modules;

namespace HistoryPortunus;

/// <summary>
/// 模块装配入口。两条对外航线（MCP、回环 Web）都在这里起、在这里收。
/// </summary>
/// <remarks>
/// **本模块不产生任何业务能力**，它只把宿主注册表投影给进程外的消费者。
/// 判断一段代码该不该进这个仓，用这条：它是否只是「把已有指令换一种协议说出去」。
/// 是——进来；不是——它属于别处。
///
/// 决定「哪些指令可以被外部调用」的 <c>McpExposurePolicy</c> 由本模块维护：
/// 宿主 5.1 不再提供 MCP 领域类型，传输投影的策略与网关必须一同迁出。
///
/// 装载失败不影响自救：把好包拷进模块槽，宿主的文件监视会自己重载——
/// 恢复路径是文件系统，不是传输。
/// </remarks>
public sealed class PortunusComposition : IModuleContextAware, IDisposable
{
    /// <summary>
    /// 服务标识必须逐字保持 <c>&lt;应用名&gt;.service</c>。
    ///
    /// 它不只是日志里的一个名字：默认端口由它按 FNV 稳定派生（见
    /// <c>LoopbackHttpTransport.DerivePort</c>），改动一个字符就会让端口整体漂移，
    /// 已经握着旧 endpoint.json 的客户端会连到一个没人监听的端口上。
    /// 迁出宿主前它由 <c>ServiceComposer</c> 以同样的方式拼出。
    /// </summary>
    private const string ServiceId = PortunusRuntime.HostName + ".service";

    private readonly object _gate = new();
    private IModuleContext? _context;
    private WebGateway? _web;
    private McpGateway? _mcp;
    private string? _endpointFile;

    /// <summary>宿主在装载时注入权威指令总线与命令注册器。</summary>
    public void Attach(IModuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        lock (_gate)
        {
            _context = context;
            // 1.1.0：数据目录由宿主给（宿主 6.0.0 统一契约），设置、治理、审计、日志与 endpoint.json 都在这里。
            PortunusRuntime.Use(context.Environment.DataDirectory);
            var endpointFile = Path.Combine(PortunusRuntime.DataRoot, EndpointDescriptor.FileName);
            var catalog = new BusCommandCatalog(() => context.Bus);
            var identity = new HostIdentity(PortunusRuntime.HostName, context.Environment.HostVersion);

            // 先认领本机航线，再开监听。装载本模块的进程不一定是提供服务的那个——
            // `--cli` / `--probe` / `--export-command-manual` 为了让手册忠实反映注册表也会装载全部模块。
            var claimed = HostLaneClaim.TryClaim(endpointFile, PortunusRuntime.Log, context.Environment.RunMode);
            if (claimed)
            {
                _endpointFile = endpointFile;
                StartWeb(context, catalog, identity, PortunusRuntime.Settings, PortunusRuntime.Log);
            }

            StartMcp(context, catalog, identity, PortunusRuntime.Settings, PortunusRuntime.Log, listen: claimed);
        }
    }

    /// <summary>
    /// 交还本模块占用的进程级资源。
    ///
    /// 宿主在每轮热重载的拆除阶段调用它，且**早于**新快照的 <see cref="Attach"/>，
    /// 所以端口先释放再重新绑定，不会退到下一个端口。
    /// 没有这一步，被遗弃的监听器会继续占着端口、继续持有活的指令总线引用——
    /// 每重载一次就多一个仍能执行任意指令的入口。
    ///
    /// 只删自己写下的 endpoint.json：<c>_endpointFile</c> 仅在
    /// <see cref="HostLaneClaim.TryClaim"/> 通过后才被赋值，因此未取得航线的进程
    /// 退出时不会碰活着的宿主留下的那一份。
    /// </summary>
    public void Dispose()
    {
        WebGateway? web;
        McpGateway? mcp;
        string? endpointFile;
        lock (_gate)
        {
            web = _web;
            mcp = _mcp;
            endpointFile = _endpointFile;
            _web = null;
            _mcp = null;
            _endpointFile = null;
            _context = null;
        }

        mcp?.Dispose();
        web?.Dispose();
        if (endpointFile != null)
            EndpointDescriptor.Delete(endpointFile);
    }

    /// <summary>当前生效的宿主上下文；未装载时为 null。</summary>
    internal IModuleContext? Context
    {
        get { lock (_gate) { return _context; } }
    }

    /// <summary>当前 Web 网关；未启动时为 null。</summary>
    internal WebGateway? Web
    {
        get { lock (_gate) { return _web; } }
    }

    /// <summary>当前 MCP 网关；未装配时为 null。</summary>
    internal McpGateway? Mcp
    {
        get { lock (_gate) { return _mcp; } }
    }

    private void StartWeb(
        IModuleContext context,
        ICommandCatalog catalog,
        HostIdentity identity,
        ISettingsService settings,
        IModuleLog log)
    {
        var web = new WebGateway(() => context.Bus, catalog, identity, settings, log)
        {
            ServerId = ServiceId,
        };

        var (started, message) = web.TryAutostart();
        if (!started)
        {
            // 不抛：一条航线起不来不该连累模块装载，否则连日志都读不到就整个消失了。
            log.Error("web", message);
            web.Dispose();
            _endpointFile = null;
            return;
        }

        _web = web;
        log.Info("web", message);

        // endpoint.json 是这条航线唯一的通告方式：端口与本次监听的一次性令牌都在里面。
        // 迁出宿主后由本模块独占其生命周期——写在启动成功之后，删在 Dispose。
        // 模块没装上时该文件不存在，这正确地表示「本机没有可用的 Web 入口」。
        EndpointDescriptor.Write(
            _endpointFile!, web.Port, web.ServerId, web.AccessToken, log);
    }

    /// <summary>
    /// 装配 MCP 航线：治理库、审计、网关、管理指令，并把治理视图挂上总线。
    /// </summary>
    /// <remarks>
    /// 治理与审计落在宿主给的数据目录（1.1.0 起，<c>ModuleData\HistoryPortunus\state</c>）。
    /// 这个目录独立于包槽位：装包、热重载、卸载都不动它，修订与调用历史因此不随模块的生命周期断开。
    ///
    /// 与 Web 不同，MCP **不由本方法直接开监听**：是否随宿主起听由
    /// <c>mcp.autostart</c> 决定，沿用迁出前 <c>ServiceHost</c> 的 <c>TryAutostart</c> 语义。
    /// 未取得航线的进程（离线 CLI）仍登记管理指令，但不绑定端口、不改 mcp.json。
    /// </remarks>
    private void StartMcp(
        IModuleContext context,
        ICommandCatalog catalog,
        HostIdentity identity,
        ISettingsService settings,
        IModuleLog log,
        bool listen)
    {
        var dataRoot = PortunusRuntime.DataRoot;

        var prompts = new PromptGovernanceStore(dataRoot, log);
        var audit = new McpAuditRecorder(dataRoot, log);

        var gateway = new McpGateway(
            () => context.Bus,
            catalog,
            settings,
            log,
            audit,
            prompts,
            identity,
            RefuseRemoteConfirmation(log),
            (port, mcpLog) => CursorMcpConfig.Sync(port, mcpLog))
        {
            // 端口变化告知总线（宿主 6.0.0 统一契约的模块事件）：要找 MCP 地址的模块订阅它，或执行 portunus.mcp.status。
            Announce = (running, port) => context.Publish(
                "portunus.mcp.changed",
                new { running, port, url = running ? CursorMcpConfig.UrlFor(port) : null }),
        };

        _mcp = gateway;

        context.RegisterCommands(registry => McpCommands.RegisterAll(
            registry,
            () => context.Bus,
            catalog,
            () => gateway,
            settings,
            prompts));

        if (!listen)
        {
            log.Info("mcp", "本进程不开 MCP 监听");
            return;
        }

        var (started, message) = gateway.TryAutostart();
        if (started)
            log.Info("mcp", message);
        else
            log.Error("mcp", message);
    }

    /// <summary>
    /// MCP 的远端确认通道：一律拒绝。
    /// </summary>
    /// <remarks>
    /// **这是对迁出前行为的逐字保留，不是新决定。** 迁出前 <c>ServiceComposer</c> 把
    /// <c>ShellRelayConfirmation.ConfirmRemote</c> 硬接给网关，那个实现同样一律拒绝。
    ///
    /// 因此 <c>mcp.confirm=host</c> 今天并不会真的弹框——即使 Aurora 已装载并且
    /// 把 <c>Bus.Confirmation</c> 换成了自己的窗口确认。改成读 <c>Bus.Confirmation</c>
    /// 会让远端危险指令**开始**能被人工放行，那是安全语义的变更，不该混在一次搬家里。
    /// 要不要接通，单独议。
    /// </remarks>
    private static Func<string, string, int, bool?> RefuseRemoteConfirmation(IModuleLog log)
        => (client, prompt, _) =>
        {
            log.Warn("confirm", $"远端确认请求已拒绝(来源 {client}): {prompt}");
            return false;
        };
}
