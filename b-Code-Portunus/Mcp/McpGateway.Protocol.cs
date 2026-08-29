using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Storage;

using HistoryPortunus.Web;

namespace HistoryPortunus.Mcp;

public sealed partial class McpGateway : IDisposable
{
    private static string NormalizeClientName(string? value, string fallback)
    {
        var normalized = NormalizeBoundedText(value, MaxClientNameLength);
        return string.IsNullOrWhiteSpace(normalized) ? fallback : normalized;
    }

    private static string NormalizeProtocolVersion(string? value, out bool validLength)
    {
        validLength = value == null || value.Length <= MaxProtocolVersionLength;
        return NormalizeBoundedText(value, MaxProtocolVersionLength);
    }

    private static string NormalizeBoundedText(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var normalized = new string(value.Where(character => !char.IsControl(character)).ToArray()).Trim();
        if (normalized.Length <= maxLength)
            return normalized;
        var length = maxLength;
        if (char.IsHighSurrogate(normalized[length - 1]))
            length--;
        return normalized[..length];
    }

    private string? BuildConfirmPrompt(
        ClientSession session,
        CommandBus bus,
        string commandName,
        JsonElement? arguments)
    {
        if (!bus.Registry.TryGet(commandName, out var descriptor) || descriptor.ConfirmPrompt == null)
            return null;

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (arguments is { ValueKind: JsonValueKind.Object } obj)
        {
            foreach (var prop in obj.EnumerateObject())
            {
                values[prop.Name] = prop.Value.ValueKind switch
                {
                    JsonValueKind.String => prop.Value.GetString() ?? "",
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => prop.Value.GetRawText(),
                };
            }
        }

        try
        {
            var ctx = new CommandContext(descriptor, values, $"MCP:{session.Name}", null, CancellationToken.None);
            return descriptor.ConfirmPrompt(ctx);
        }
        catch (Exception)
        {
            // 文案构建失败不影响中继:回落到通用提示,人工仍能裁决
            return $"远程请求执行危险指令: {commandName}\n(参数: {(arguments?.GetRawText() ?? "{}")})";
        }
    }

    private ClientSession ResolveSession(HttpListenerRequest request)
    {
        var id = request.Headers["Mcp-Session-Id"];
        if (string.IsNullOrWhiteSpace(id))
            id = $"connection:{request.RemoteEndPoint}";
        if (id.Length > 128)
            return ClientSession.Create(ClientKind.Mcp, "client");

        var session = _sessions.GetOrAdd(
            id,
            static key => ClientSession.Create(ClientKind.Mcp, "client", id: key));
        TrimSessions(session.Id);
        return session;
    }

    private void TrimSessions(string keepSessionId)
    {
        var limit = Math.Clamp(
            _settings.GetInt(McpSettingKeys.SessionLimit, DefaultSessionLimit), 16, 65_536);
        if (_sessions.Count <= limit)
            return;
        foreach (var key in _sessions.Keys
                     .Where(key => !key.Equals(keepSessionId, StringComparison.Ordinal))
                     .OrderBy(key => key, StringComparer.Ordinal)
                     .Take(Math.Max(0, _sessions.Count - limit))
                     .ToList())
            _sessions.TryRemove(key, out _);
    }

    private static readonly JsonSerializerOptions DataJson = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles,
    };

    // ---------------------------------------------------------------- JSON-RPC 编码

    private static JsonObject ToolText(string text, bool isError) => new()
    {
        ["content"] = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = text } },
        ["isError"] = isError,
    };

    private static JsonObject RpcResult(JsonNode? id, JsonNode result) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["result"] = result,
    };

    private static JsonObject RpcError(JsonNode? id, int code, string message) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message },
    };

    private static async Task WriteJsonAsync(HttpListenerContext context, JsonObject payload, int status)
    {
        var bytes = Encoding.UTF8.GetBytes(payload.ToJsonString());
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.ContentLength64 = bytes.Length;
        await context.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
        context.Response.Close();
    }

    private static void TryClose(HttpListenerContext context, int status)
        => LoopbackHttpTransport.TryClose(context, status);
}
