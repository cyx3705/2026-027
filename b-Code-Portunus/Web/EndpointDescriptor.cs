using System.Text.Json;
using HistoryVulcan.Core.Logging;

namespace HistoryPortunus.Web;

/// <summary>
/// <c>endpoint.json</c> 的读写。Web 航线的唯一通告方式。
/// </summary>
/// <remarks>
/// 迁出宿主前由 <c>ServiceHost.WriteEndpoint</c> 负责，随宿主进程生存；现在归本模块，
/// 随模块快照生存。含义因此变得更准确：**文件在，说明这条航线此刻真的开着**。
///
/// <c>accessToken</c> 是本次监听的一次性凭据（见 <c>WebGateway.AccessToken</c>）。
/// 它使本文件从「端口通告」变成凭据载体：文件位于用户 AppData 下，
/// 其读取权限就是这条边界的实际强度。
///
/// 每轮热重载都会换一枚新令牌并重写本文件，所以客户端**必须每次调用前重读**，
/// 不能把令牌缓存在自己的进程里。
/// </remarks>
internal static class EndpointDescriptor
{
    internal const string FileName = "endpoint.json";

    internal static void Write(
        string path, int port, string serverId, string accessToken, IShellLog log)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            // 先写临时文件再原子改名：读方要么看到上一版完整内容，要么看到新版完整内容，
            // 不会读到写了一半的 JSON。
            var temporary = path + ".tmp." + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(temporary, JsonSerializer.Serialize(new
                {
                    port,
                    serverId,
                    processId = Environment.ProcessId,
                    accessToken,
                }));
                File.Move(temporary, path, overwrite: true);
            }
            finally
            {
                try { File.Delete(temporary); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex)
        {
            // 通告失败不影响监听本身：端口已经开着，只是外面暂时不知道它在哪。
            log.Warn("web", $"写入 {FileName} 失败: {ex.Message}");
        }
    }

    internal static void Delete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
