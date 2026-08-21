using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace HistoryPortunus.Web;

/// <summary>
/// 两个本机网关共用的 HttpListener 传输层零件。
///
/// 收拢的是传输层，不是网关：两者仍各自持有自己的 <see cref="HttpListener"/> 与端口，
/// 停止一个不影响另一个。不合并监听器的完整论证见 DEC-047 与 REQ-NET-001。
///
/// **本文件在宿主里还有一份同源副本**，因为 MCP 网关尚未搬迁（迁移第 2 轮），
/// 而宿主侧它是 <c>internal</c>，模块够不着。两条出路都比现在差：
/// 提公开面等于为一个即将删除的类型永久扩大宿主契约，再在第 2 轮补 <c>*REMOVED*</c>；
/// 现在就整体搬走则会留下宿主引用模块的倒挂依赖。
/// 因此接受一轮的重复，**第 2 轮搬完 MCP 后删除宿主那一份**，此注释一并撤销。
/// </summary>
internal static class LoopbackHttpTransport
{
    /// <summary>网关只接受回环；前缀挂根路径，由各网关自行校验具体路由。</summary>
    internal const string LoopbackAddress = "127.0.0.1";

    /// <summary>
    /// 按应用名稳定派生默认端口。同一台机器上的同名应用总是落到同一个端口，
    /// 不同应用错开，避免多宿主并存时互相抢占。
    /// </summary>
    internal static int DerivePort(string appName, int portBase, int portSpan)
    {
        var hash = 2166136261u;
        foreach (var character in appName.Trim().ToUpperInvariant())
            hash = (hash ^ character) * 16777619u;
        return portBase + (int)(hash % portSpan);
    }

    /// <summary>读取 <c>Authorization: Bearer</c> 值；缺失或格式不符返回 null。</summary>
    internal static string? ReadBearer(HttpListenerRequest request)
    {
        const string prefix = "Bearer ";
        var header = request.Headers["Authorization"];
        return header?.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) == true
            ? header[prefix.Length..].Trim()
            : null;
    }

    /// <summary>定长时间比较，避免按字符提前返回泄露令牌前缀。</summary>
    internal static bool FixedEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        try { return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes); }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    /// <summary>
    /// 只置状态码并关闭响应。客户端可能已经断开，此时 <c>Close</c> 会抛
    /// <see cref="ObjectDisposedException"/> 或 <see cref="HttpListenerException"/>，
    /// 都属于正常竞态，不应冒泡成请求处理异常。
    /// </summary>
    internal static void TryClose(HttpListenerContext context, int status)
    {
        try
        {
            context.Response.StatusCode = status;
            context.Response.Close();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (HttpListenerException)
        {
        }
    }

    /// <summary>
    /// 接受循环。停机（取消或监听器关闭）静默退出；单次接受失败只记警告并继续，
    /// 不让一个坏连接终结整个循环。每个请求在独立任务上处理，处理异常由 <paramref name="handle"/>
    /// 的调用方兜底为 500。
    /// </summary>
    internal static async Task AcceptLoopAsync(
        HttpListener listener,
        CancellationToken cancellationToken,
        Func<HttpListenerContext, Task> handle,
        Action<string> onAcceptFailed,
        Action<HttpListenerContext, Exception> onHandleFailed)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception) when (cancellationToken.IsCancellationRequested || !listener.IsListening)
            {
                return;
            }
            catch (Exception ex)
            {
                onAcceptFailed(ex.GetType().Name);
                continue;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await handle(context).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    onHandleFailed(context, ex);
                }
            }, CancellationToken.None);
        }
    }
}
