using System.Net;
using System.Text;

namespace HistoryPortunus.Web;

internal static class HttpRequestBodyReader
{
    internal const int MaximumBodyBytes = 1_048_576;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static async Task<string> ReadUtf8Async(
        HttpListenerRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.ContentLength64 > MaximumBodyBytes)
            throw new InvalidDataException("请求体超过 1 MiB 上限");

        using var payload = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await request.InputStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;
            payload.Write(buffer, 0, read);
            if (payload.Length > MaximumBodyBytes)
                throw new InvalidDataException("请求体超过 1 MiB 上限");
        }

        var bytes = payload.ToArray();
        var offset = bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble) ? Encoding.UTF8.Preamble.Length : 0;
        return StrictUtf8.GetString(bytes, offset, bytes.Length - offset);
    }
}
