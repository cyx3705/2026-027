using System.Text.Json;
using HistoryVulcan.Core.Logging;

namespace HistoryPortunus.Mcp;

/// <summary>Provides this HistoryVulcan public contract member.</summary>
public sealed record PromptRevision(
    string Id,
    string Command,
    string? Description,
    string? ParentRevision,
    string Source,
    string Reason,
    string Created,
    string CreatedBy,
    bool Applied,
    string? RevertedFrom);

/// <summary>Legacy proposal data retained for compatibility with existing governance state.</summary>
internal sealed record PromptProposal(
    string Id,
    string Command,
    string? BaseRevision,
    string OldText,
    string ProposedText,
    string Reason,
    string Evidence,
    string SourceClient,
    string Created,
    string Status,
    string? Reviewer,
    string? Reviewed,
    string? ReviewNote,
    string? AppliedRevision);

/// <summary>Legacy correction data retained for compatibility with existing governance state.</summary>
internal sealed record PromptCorrection(
    string Id,
    string Command,
    string Claim,
    string Correction,
    string Evidence,
    string SourceClient,
    string Created,
    string Status,
    string? LinkedProposal);

/// <summary>Legacy incident data retained for compatibility with existing governance state.</summary>
internal sealed record PromptIncident(
    string Id,
    string Command,
    string Symptom,
    string Expected,
    string Actual,
    string Evidence,
    string SourceClient,
    string Created,
    string? Resolution,
    string? LinkedCorrection);

/// <summary>
/// MCP 提示词治理的文件存储。所有关联状态在同一份 JSON 文档内原子替换，
/// 因而批准、应用、回滚仍保持单进程事务语义，但不再要求关系数据库。
/// </summary>
public sealed class PromptGovernanceStore : IEffectivePromptDescriptionReader, IMcpPromptGovernanceView
{
    // 仅保留常量名供旧调用方/迁移测试识别；运行时不再创建这些表。
    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public const string TableDescriptions = "mcp_descriptions";
    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public const string TableProposals = "mcp_prompt_proposals";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly string _path;
    private readonly IShellLog _log;
    private readonly object _writeGate = new();
    private State _state;

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public PromptGovernanceStore(string dataDirectory, IShellLog log)
    {
        _path = Path.Combine(dataDirectory, "state", "prompt-governance.json");
        _log = log;
        _state = Load();
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    // ---------------------------------------------------------------- IMcpPromptGovernanceView
    // 这些只读投影只供 Portunus 的 MCP schema 使用；5.1 宿主不再接收治理视图。

    IReadOnlyDictionary<string, string> IMcpPromptGovernanceView.EffectiveDescriptions()
        => AllEffectiveDescriptions();

    IReadOnlyDictionary<string, int> IMcpPromptGovernanceView.OpenProposalCounts()
        => ListProposals(openOnly: true, limit: CatalogAggregationLimit)
            .GroupBy(item => item.Command, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);

    IReadOnlyDictionary<string, int> IMcpPromptGovernanceView.IncidentCounts()
        => ListIncidents(limit: CatalogAggregationLimit)
            .GroupBy(item => item.Command, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);

    string? IMcpPromptGovernanceView.CurrentRevisionId(string commandName)
        => GetCurrentRevision(commandName)?.Id;

    /// <summary>
    /// 目录聚合时的取数上限，沿用迁出前 CommandCatalogCommands 里的取值。
    /// 目录只显示计数，超出上限会低报——这是原有行为，迁移不改变它。
    /// </summary>
    private const int CatalogAggregationLimit = 500;

    public IReadOnlyDictionary<string, string> AllEffectiveDescriptions()
    {
        lock (_writeGate)
            return _state.Revisions
                .Where(item => item.Applied && item.Description != null)
                .GroupBy(item => item.Command, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.Last().Description!,
                    StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public PromptRevision? GetCurrentRevision(string command)
    {
        lock (_writeGate)
            return CurrentRevision(command);
    }

    /// <summary>Looks up a legacy revision by identifier.</summary>
    internal PromptRevision? GetRevision(string id)
    {
        lock (_writeGate)
            return _state.Revisions.FirstOrDefault(item => item.Id == id);
    }

    /// <summary>Provides this HistoryVulcan public contract member.</summary>
    public IReadOnlyList<PromptRevision> GetRevisions(string command, int limit = 50)
    {
        lock (_writeGate)
            return _state.Revisions
                .Where(item => item.Command.Equals(command, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(item => item.Created, StringComparer.Ordinal)
                .ThenByDescending(item => item.Id, StringComparer.Ordinal)
                .Take(ClampLimit(limit))
                .ToList();
    }

    /// <summary>Applies a description directly for compatibility with internal migration paths.</summary>
    internal PromptRevision ApplyDirect(
        string command, string? description, string source, string reason,
        string? revertedFrom = null, string? createdBy = null)
    {
        if (description != null)
            description = PromptTextIntegrity.ValidateDescription(description);

        lock (_writeGate)
        {
            var current = CurrentRevision(command);
            ClearApplied(command);
            var revision = new PromptRevision(
                NewId("rev"), command, description, current?.Id, source, reason,
                Now(), createdBy ?? source, true, revertedFrom);
            _state.Revisions.Add(revision);
            Save();
            return revision;
        }
    }

    /// <summary>Creates a legacy governance proposal.</summary>
    internal PromptProposal CreateProposal(
        string command, string oldText, string proposedText, string reason,
        string evidence, string sourceClient)
    {
        proposedText = PromptTextIntegrity.ValidateDescription(proposedText);
        lock (_writeGate)
        {
            var proposal = new PromptProposal(
                NewId("proposal"), command, CurrentRevision(command)?.Id,
                oldText, proposedText, reason, evidence, sourceClient, Now(),
                "pending", null, null, null, null);
            _state.Proposals.Add(proposal);
            Save();
            return proposal;
        }
    }

    /// <summary>Looks up a legacy governance proposal.</summary>
    internal PromptProposal? GetProposal(string id)
    {
        lock (_writeGate)
            return FindProposal(id);
    }

    /// <summary>Lists legacy governance proposals.</summary>
    internal IReadOnlyList<PromptProposal> ListProposals(
        string? command = null, bool openOnly = false, int limit = 100)
    {
        lock (_writeGate)
            return _state.Proposals
                .Where(item => string.IsNullOrWhiteSpace(command)
                               || item.Command.Equals(command, StringComparison.OrdinalIgnoreCase))
                .Where(item => !openOnly || item.Status is "pending" or "approved")
                .OrderByDescending(item => item.Created, StringComparer.Ordinal)
                .ThenByDescending(item => item.Id, StringComparer.Ordinal)
                .Take(ClampLimit(limit))
                .ToList();
    }

    /// <summary>Approves a legacy governance proposal.</summary>
    internal PromptProposal ApproveProposal(string id, string reviewer)
    {
        lock (_writeGate)
        {
            var proposal = RequireProposal(id);
            if (!proposal.Status.Equals("pending", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"提案状态为 {proposal.Status}，只有 pending 可批准");
            PromptTextIntegrity.ValidateDescription(proposal.ProposedText);
            proposal = proposal with { Status = "approved", Reviewer = reviewer, Reviewed = Now() };
            ReplaceProposal(proposal);
            Save();
            return proposal;
        }
    }

    /// <summary>Rejects a legacy governance proposal.</summary>
    internal PromptProposal RejectProposal(string id, string reviewer, string reason)
    {
        lock (_writeGate)
        {
            var proposal = RequireProposal(id);
            if (proposal.Status is not ("pending" or "approved"))
                throw new InvalidOperationException($"提案状态为 {proposal.Status}，不能拒绝");
            proposal = proposal with
            {
                Status = "rejected",
                Reviewer = reviewer,
                Reviewed = Now(),
                ReviewNote = reason,
            };
            ReplaceProposal(proposal);
            Save();
            return proposal;
        }
    }

    /// <summary>Applies an approved legacy governance proposal.</summary>
    internal PromptRevision ApplyProposal(string id, string reviewer)
    {
        lock (_writeGate)
        {
            var proposal = RequireProposal(id);
            if (!proposal.Status.Equals("approved", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"提案状态为 {proposal.Status}，必须先批准再应用");
            PromptTextIntegrity.ValidateDescription(proposal.ProposedText);
            var current = CurrentRevision(proposal.Command);
            if (!string.Equals(current?.Id, proposal.BaseRevision, StringComparison.Ordinal))
                throw new InvalidOperationException(
                    $"提案基线冲突: 创建时={proposal.BaseRevision ?? "(默认)"}，当前={current?.Id ?? "(默认)"}");

            ClearApplied(proposal.Command);
            var revision = new PromptRevision(
                NewId("rev"), proposal.Command, proposal.ProposedText, current?.Id,
                "proposal", proposal.Reason, Now(), reviewer, true, null);
            _state.Revisions.Add(revision);
            ReplaceProposal(proposal with
            {
                Status = "applied",
                Reviewer = reviewer,
                Reviewed = Now(),
                AppliedRevision = revision.Id,
            });
            Save();
            return revision;
        }
    }

    /// <summary>Creates a new revision from a previous legacy revision.</summary>
    internal PromptRevision RevertToRevision(string revisionId, string reviewer, string reason)
    {
        PromptRevision target;
        lock (_writeGate)
            target = _state.Revisions.FirstOrDefault(item => item.Id == revisionId)
                     ?? throw new InvalidOperationException($"修订不存在: {revisionId}");
        return ApplyDirect(target.Command, target.Description, "revert", reason, target.Id, reviewer);
    }

    /// <summary>Creates a legacy correction record.</summary>
    internal PromptCorrection CreateCorrection(
        string command, string claim, string correction, string evidence, string sourceClient,
        string? linkedProposal = null)
    {
        lock (_writeGate)
        {
            var item = new PromptCorrection(
                NewId("correction"), command, claim, correction, evidence,
                sourceClient, Now(), "pending", linkedProposal);
            _state.Corrections.Add(item);
            Save();
            return item;
        }
    }

    /// <summary>Looks up a legacy correction record.</summary>
    internal PromptCorrection? GetCorrection(string id)
    {
        lock (_writeGate)
            return _state.Corrections.FirstOrDefault(item => item.Id == id);
    }

    /// <summary>Lists legacy correction records.</summary>
    internal IReadOnlyList<PromptCorrection> ListCorrections(string? command = null, int limit = 100)
    {
        lock (_writeGate)
            return _state.Corrections
                .Where(item => string.IsNullOrWhiteSpace(command)
                               || item.Command.Equals(command, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(item => item.Created, StringComparer.Ordinal)
                .ThenByDescending(item => item.Id, StringComparer.Ordinal)
                .Take(ClampLimit(limit))
                .ToList();
    }

    /// <summary>Creates a legacy incident record.</summary>
    internal PromptIncident CreateIncident(
        string command, string symptom, string expected, string actual, string evidence,
        string sourceClient, string? linkedCorrection = null)
    {
        lock (_writeGate)
        {
            var item = new PromptIncident(
                NewId("incident"), command, symptom, expected, actual, evidence,
                sourceClient, Now(), null, linkedCorrection);
            _state.Incidents.Add(item);
            Save();
            return item;
        }
    }

    /// <summary>Lists legacy incident records.</summary>
    internal IReadOnlyList<PromptIncident> ListIncidents(string? command = null, int limit = 100)
    {
        lock (_writeGate)
            return _state.Incidents
                .Where(item => string.IsNullOrWhiteSpace(command)
                               || item.Command.Equals(command, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(item => item.Created, StringComparer.Ordinal)
                .ThenByDescending(item => item.Id, StringComparer.Ordinal)
                .Take(ClampLimit(limit))
                .ToList();
    }

    private PromptRevision? CurrentRevision(string command)
        => _state.Revisions.LastOrDefault(item => item.Applied
            && item.Command.Equals(command, StringComparison.OrdinalIgnoreCase));

    private void ClearApplied(string command)
    {
        for (var i = 0; i < _state.Revisions.Count; i++)
            if (_state.Revisions[i].Applied
                && _state.Revisions[i].Command.Equals(command, StringComparison.OrdinalIgnoreCase))
                _state.Revisions[i] = _state.Revisions[i] with { Applied = false };
    }

    private PromptProposal? FindProposal(string id)
        => _state.Proposals.FirstOrDefault(item => item.Id == id);

    private PromptProposal RequireProposal(string id)
        => FindProposal(id) ?? throw new InvalidOperationException($"提案不存在: {id}");

    private void ReplaceProposal(PromptProposal proposal)
    {
        var index = _state.Proposals.FindIndex(item => item.Id == proposal.Id);
        if (index < 0)
            throw new InvalidOperationException($"提案不存在: {proposal.Id}");
        _state.Proposals[index] = proposal;
    }

    private State Load()
    {
        try
        {
            if (!File.Exists(_path))
                return new State();
            return JsonSerializer.Deserialize<State>(File.ReadAllText(_path), JsonOptions) ?? new State();
        }
        catch (Exception ex)
        {
            _log.Error("prompt", $"提示词治理文件读取失败，已使用空状态: {ex.Message}");
            return new State();
        }
    }

    private void Save()
    {
        var directory = Path.GetDirectoryName(_path)!;
        Directory.CreateDirectory(directory);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_state, JsonOptions));
        File.Move(temp, _path, overwrite: true);
    }

    private static int ClampLimit(int limit) => Math.Clamp(limit, 1, 1000);
    private static string Now() => DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    private static string NewId(string prefix) => $"{prefix}-{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}";

    private sealed class State
    {
        public int FormatVersion { get; set; } = 1;
        public List<PromptRevision> Revisions { get; set; } = [];
        public List<PromptProposal> Proposals { get; set; } = [];
        public List<PromptCorrection> Corrections { get; set; } = [];
        public List<PromptIncident> Incidents { get; set; } = [];
    }
}
