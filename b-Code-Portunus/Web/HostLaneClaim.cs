using System.Diagnostics;
using System.Text.Json;
using HistoryVulcan.Core.Logging;

namespace HistoryPortunus.Web;

/// <summary>
/// 判断本进程是否有权在本机开对外航线。
/// </summary>
/// <remarks>
/// **这条规则的由来是一次真实事故。** 网关还在宿主里时，只有服务进程会开监听，
/// 别的入口点（`--export-command-manual`）显式跳过了这一步。网关变成模块之后，
/// 「谁开监听」不再由入口点决定，而是由「谁装载了这个模块」决定——
/// 而无头导出为了让手册忠实反映注册表，必须装载全部模块。
///
/// 于是导出进程也起了一份网关：端口被活服务占着，它退到下一个端口，
/// 把 endpoint.json 改写成自己的，退出时又按 <see cref="PortunusComposition.Dispose"/>
/// 的约定把它删掉。**活着的服务就此失联**，尽管它的监听器一直好好开着。
///
/// 结论不是「导出进程该特殊处理」，而是 endpoint.json 缺少归属定义：
/// 本机的对外航线是**独占资源**，同一时刻只能属于一个宿主进程。
///
/// 判据用 endpoint.json 自己承载的 processId，不引入新的锁文件或互斥体：
/// 它已经记录了「谁在提供服务」，只是从来没有人读过这一格。
/// </remarks>
internal static class HostLaneClaim
{
    /// <summary>
    /// 尝试取得本机对外航线的所有权。
    /// </summary>
    /// <returns>true 表示可以开监听；false 表示已有活着的宿主占用，本进程应保持静默。</returns>
    internal static bool TryClaim(string endpointFile, IShellLog log)
    {
        using var self = Process.GetCurrentProcess();
        if (!ShouldOpenListeners(self.ProcessName, Environment.GetCommandLineArgs()))
        {
            log.Info("web", "离线 CLI / 手册导出不开对外航线，也不改 endpoint.json");
            return false;
        }

        var holder = ReadLiveHolder(endpointFile);
        if (holder == null)
            return true;

        if (holder.Value == Environment.ProcessId)
            return true;

        // 保持静默而不是退到下一个端口：退让会产生一个没人知道地址的监听器，
        // 它照样持有活的指令总线和一枚有效令牌——比不开更糟。
        log.Info(
            "web",
            $"本机对外航线已由进程 {holder.Value} 持有，本进程不开监听（{Path.GetFileName(endpointFile)} 保持不动）");
        return false;
    }

    /// <summary>
    /// 读出 endpoint.json 记录的持有者，仅当它确实还活着时返回。
    ///
    /// 三种情况都判为无人持有：文件不存在、内容读不动、记录的进程已经退出
    /// （宿主非正常终止会留下这样的残留文件）。
    /// </summary>
    private static int? ReadLiveHolder(string endpointFile)
    {
        int recorded;
        try
        {
            if (!File.Exists(endpointFile))
                return null;

            using var document = JsonDocument.Parse(File.ReadAllText(endpointFile));
            if (!document.RootElement.TryGetProperty("processId", out var element)
                || !element.TryGetInt32(out recorded)
                || recorded <= 0)
            {
                return null;
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }

        try
        {
            using var process = Process.GetProcessById(recorded);

            // 进程号会被回收。同时比对进程名，避免把一个碰巧复用了该号的无关进程
            // 误判成宿主，从而让真正的宿主永远开不了航线。
            using var self = Process.GetCurrentProcess();
            return string.Equals(process.ProcessName, self.ProcessName, StringComparison.OrdinalIgnoreCase)
                ? recorded
                : null;
        }
        catch (ArgumentException)
        {
            // 进程已退出：残留文件，不构成占用。
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// 只有真正的服务宿主才开端口。<c>HistoryVulcan.Cli</c> 和带 <c>--cli</c> 的离线组合
    /// 也会装载本模块（为了手册和门禁），但它们不是航线持有者：一旦误判成功，
    /// <see cref="PortunusComposition.Dispose"/> 会把活宿主的 <c>endpoint.json</c> 删掉。
    /// </summary>
    internal static bool ShouldOpenListeners(string processName, IReadOnlyList<string> arguments)
    {
        if (processName.EndsWith(".Cli", StringComparison.OrdinalIgnoreCase)
            || processName.Contains("Cli", StringComparison.OrdinalIgnoreCase)
                && processName.Contains("HistoryVulcan", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach (var argument in arguments)
        {
            if (argument.Equals("--cli", StringComparison.OrdinalIgnoreCase)
                || argument.Equals("--export-command-manual", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }
}
