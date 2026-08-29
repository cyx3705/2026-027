using System.Text.Json;
using System.Text.Json.Nodes;
using HistoryVulcan.Core.Logging;

namespace HistoryPortunus.Mcp;

/// <summary>
/// 把本机 Cursor 的 <c>%USERPROFILE%\.cursor\mcp.json</c> 对齐到当前 MCP 监听地址。
/// </summary>
/// <remarks>
/// Cursor 不会自己追端口。历史上 Portunus 用过派生/漂移端口，再往配置里写入
/// <c>Authorization: Bearer</c>。Cursor 把带鉴权头的 HTTP MCP 当成需要登录的服务器，
/// 工具发现失败，只剩 <c>mcp_auth</c>。本机回环不持券：只写 <c>url</c>，去掉任何头。
/// 失败只记日志，不让监听本身跟着失败。
/// </remarks>
internal static class CursorMcpConfig
{
    internal const string ServerName = "history-vulcan";

    private static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
    };

    internal static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".cursor",
        "mcp.json");

    internal static string UrlFor(int port)
        => $"http://127.0.0.1:{port}/mcp";

    internal static void Sync(int port, IShellLog log, string? path = null)
    {
        var file = string.IsNullOrWhiteSpace(path) ? DefaultPath : path;
        try
        {
            var directory = Path.GetDirectoryName(file);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            var root = ReadRoot(file);
            var servers = root["mcpServers"] as JsonObject ?? new JsonObject();
            root["mcpServers"] = servers;
            servers[ServerName] = new JsonObject
            {
                ["url"] = UrlFor(port),
            };

            var temporary = file + ".tmp." + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(temporary, root.ToJsonString(Pretty));
                File.Move(temporary, file, overwrite: true);
            }
            finally
            {
                try { File.Delete(temporary); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            log.Info("mcp", $"已对齐 Cursor MCP {file} → {UrlFor(port)}（无鉴权头）");
        }
        catch (Exception ex)
        {
            log.Warn("mcp", $"写入 Cursor mcp.json 失败: {ex.Message}");
        }
    }

    private static JsonObject ReadRoot(string file)
    {
        if (!File.Exists(file))
            return new JsonObject();

        try
        {
            return JsonNode.Parse(File.ReadAllText(file)) as JsonObject ?? new JsonObject();
        }
        catch (JsonException)
        {
            return new JsonObject();
        }
    }
}
