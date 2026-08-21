using HistoryPortunus.Mcp;
using HistoryPortunus.Web;
using HistoryVulcan.Core;
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
/// 决定「哪些指令可以被外部调用」的 <c>McpExposurePolicy</c> **留在宿主**：
/// 门搬走，锁留下。否则换一个模块就能给自己放权。
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
    private static string ServiceId => AppIdentity.Current.Name + ".service";

    private readonly object _gate = new();
    private IModuleContext? _context;
    private WebGateway? _web;
    private McpGateway? _mcp;
    private string? _endpointFile;

    /// <summary>宿主在装载时注入上下文：权威指令总线、设置、日志与数据根目录。</summary>
    public void Attach(IModuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        lock (_gate)
        {
            _context = context;
            var endpointFile = Path.Combine(context.DataDirectory, EndpointDescriptor.FileName);

            // 先认领本机航线，再开监听。装载本模块的进程不一定是提供服务的那个——
            // `--export-command-manual` 为了让手册忠实反映注册表也会装载全部模块。
            if (!HostLaneClaim.TryClaim(endpointFile, context.Log))
                return;

            _endpointFile = endpointFile;
            StartWeb(context);
            StartMcp(context);
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
        IModuleContext? context;
        lock (_gate)
        {
            web = _web;
            mcp = _mcp;
            endpointFile = _endpointFile;
            context = _context;
            _web = null;
            _mcp = null;
            _endpointFile = null;
            _context = null;
        }

        // 先摘挂钩再拆实现：宿主的目录指令可能正在读它，而它背后的治理库马上要停。
        // 留一个指向已拆对象的非 null 引用，调用方看不出有什么不对，却读到死数据。
        if (context != null)
            context.Bus.McpGovernance = null;

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

    private void StartWeb(IModuleContext context)
    {
        var web = new WebGateway(() => context.Bus, context.Settings, context.Log)
        {
            ServerId = ServiceId,
        };

        var (started, message) = web.Start();
        if (!started)
        {
            // 不抛：一条航线起不来不该连累模块装载，否则连日志都读不到就整个消失了。
            context.Log.Error("web", message);
            web.Dispose();
            return;
        }

        _web = web;
        context.Log.Info("web", message);

        // endpoint.json 是这条航线唯一的通告方式：端口与本次监听的一次性令牌都在里面。
        // 迁出宿主后由本模块独占其生命周期——写在启动成功之后，删在 Dispose。
        // 模块没装上时该文件不存在，这正确地表示「本机没有可用的 Web 入口」。
        EndpointDescriptor.Write(
            _endpointFile!, web.Port, web.ServerId, web.AccessToken, context.Log);
    }

    /// <summary>
    /// 装配 MCP 航线：治理库、审计、网关、管理指令，并把治理视图挂上总线。
    /// </summary>
    /// <remarks>
    /// 治理与审计的落盘位置**刻意仍在应用数据根**（<c>%AppData%\HistoryVulcan</c>），
    /// 不跟着模块走。修订与调用历史是长期资产，让它随一个可热重载的模块搬家，
    /// 等于把「谁改过工具描述、谁调用过什么」的连续性绑在模块的生命周期上。
    ///
    /// 与 Web 不同，MCP **不由本方法直接开监听**：是否随宿主起听由
    /// <c>mcp.autostart</c> 决定，沿用迁出前 <c>ServiceHost</c> 的 <c>TryAutostart</c> 语义。
    /// </remarks>
    private void StartMcp(IModuleContext context)
    {
        // 数据根：模块上下文给的是 service 子目录，而治理与审计历来落在它的父目录。
        // 迁移不搬数据——搬了就等于把既有修订与调用历史丢在原地。
        var applicationRoot = Directory.GetParent(context.DataDirectory)?.FullName
                              ?? context.DataDirectory;

        var prompts = new PromptGovernanceStore(applicationRoot, context.Log);
        var audit = new McpAuditRecorder(applicationRoot, context.Log);

        var gateway = new McpGateway(
            () => context.Bus,
            context.Settings,
            context.Log,
            audit,
            prompts,
            AppIdentity.Current,
            RefuseRemoteConfirmation(context.Log));

        _mcp = gateway;

        // 宿主的 vulcan.command.list / show 经这个挂钩取治理那几列。
        context.Bus.McpGovernance = prompts;

        context.RegisterCommands(registry => McpCommands.RegisterAll(
            registry,
            () => context.Bus,
            () => gateway,
            context.Settings,
            prompts,
            source: "module:HistoryPortunus"));

        var (started, message) = gateway.TryAutostart();
        if (started)
            context.Log.Info("mcp", message);
        else
            context.Log.Info("mcp", message);
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
    private static Func<string, string, int, bool?> RefuseRemoteConfirmation(IShellLog log)
        => (client, prompt, _) =>
        {
            log.Warn("confirm", $"远端确认请求已拒绝(来源 {client}): {prompt}");
            return false;
        };
}
