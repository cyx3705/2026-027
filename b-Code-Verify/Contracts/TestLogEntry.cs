using HistoryVulcan.Core.Logging;

namespace HistoryPortunus.Contracts;

/// <summary>测试日志替身记下的一条（宿主 6.0.0 起宿主的 ShellLogEntry 是内部类型）。</summary>
internal sealed record ShellLogEntry(DateTime Time, ShellLogLevel Level, string Category, string Message);
