using HistoryVulcan.Core;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Modules;
using HistoryPortunus.Web;

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
    private string? _endpointFile;

    /// <summary>宿主在装载时注入上下文：权威指令总线、设置、日志与数据根目录。</summary>
    public void Attach(IModuleContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        lock (_gate)
        {
            _context = context;
            _endpointFile = Path.Combine(context.DataDirectory, EndpointDescriptor.FileName);
            StartWeb(context);
        }
    }

    /// <summary>
    /// 交还本模块占用的进程级资源。
    ///
    /// 宿主在每轮热重载的拆除阶段调用它，且**早于**新快照的 <see cref="Attach"/>，
    /// 所以端口先释放再重新绑定，不会退到下一个端口。
    /// 没有这一步，被遗弃的监听器会继续占着端口、继续持有活的指令总线引用——
    /// 每重载一次就多一个仍能执行任意指令的入口。
    /// </summary>
    public void Dispose()
    {
        WebGateway? web;
        string? endpointFile;
        lock (_gate)
        {
            web = _web;
            endpointFile = _endpointFile;
            _web = null;
            _endpointFile = null;
            _context = null;
        }

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
}
