namespace HistoryPortunus.Mcp;

/// <summary>
/// Provides the descriptions currently effective for MCP tools.
/// Governance writers are intentionally outside the host; the host only consumes this read-only view.
/// </summary>
public interface IEffectivePromptDescriptionReader
{
    /// <summary>Returns the applied description overrides keyed by command name.</summary>
    IReadOnlyDictionary<string, string> AllEffectiveDescriptions();
}
