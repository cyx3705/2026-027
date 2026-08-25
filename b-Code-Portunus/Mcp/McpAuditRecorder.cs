using System.Text;
using System.Text.Json;
using HistoryVulcan.Core.Logging;

namespace HistoryPortunus.Mcp;

/// <summary>MCP 调用留痕的 JSONL 实现。单条追加失败只告警，不阻断调用。</summary>
public sealed class McpAuditRecorder : IMcpAuditLog
{
    private const int MaxClientLength = 256;
    private const int MaxToolLength = 128;
    private const int MaxArgumentsLength = 500;
    private const int MaxResultLength = 100;

    private readonly string _path;
    private readonly IShellLog _log;
    private readonly object _gate = new();

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public McpAuditRecorder(string dataDirectory, IShellLog log)
    {
        _path = Path.Combine(dataDirectory, "state", "mcp-history.jsonl");
        _log = log;
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public void RecordMcp(string client, string tool, string arguments, string result, long elapsedMs)
    {
        try
        {
            var row = new AuditRow(
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                Bound(client, MaxClientLength),
                Bound(tool, MaxToolLength),
                Bound(arguments, MaxArgumentsLength),
                Bound(result, MaxResultLength),
                elapsedMs);
            var line = JsonSerializer.Serialize(row) + Environment.NewLine;
            lock (_gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                File.AppendAllText(_path, line, new UTF8Encoding(false));
            }
        }
        catch (Exception ex)
        {
            _log.Warn("mcp", $"MCP 留痕写入失败(不影响调用本身): {ex.GetType().Name}");
        }
    }

    void IMcpAuditLog.RecordMcp(
        ClientSession session,
        string tool,
        string arguments,
        string result,
        long elapsedMs)
        => RecordMcp($"{session.Id}/{session.Name}", tool, arguments, result, elapsedMs);

    private static string Bound(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        return value.Length <= maxLength ? value : value[..(maxLength - 1)] + "…";
    }

    private sealed record AuditRow(
        string Time,
        string Client,
        string Tool,
        string Arguments,
        string Result,
        long ElapsedMs);
}
