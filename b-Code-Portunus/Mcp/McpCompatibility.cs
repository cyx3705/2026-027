using System.Text.Json;
using System.Text.Json.Nodes;
using HistoryVulcan.Core.Commands;

namespace HistoryPortunus.Mcp;

/// <summary>Transport-local session metadata formerly supplied by the host MCP implementation.</summary>
public enum ClientKind
{
    Mcp,
    Shell,
}

/// <summary>Immutable identity for one MCP or loopback Shell caller.</summary>
public sealed record ClientSession(
    string Id,
    ClientKind Kind,
    string Name,
    string ProtocolVersion,
    DateTimeOffset ConnectedAt)
{
    public string? RemoteAddress { get; init; }
    public string? DeviceId { get; init; }
    public string? AuthSubject { get; init; }
    public IReadOnlySet<string> Scopes { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public bool IsLoopback { get; init; }

    public static ClientSession Create(
        ClientKind kind,
        string name,
        string protocolVersion = "",
        string? id = null,
        string? remoteAddress = null,
        string? deviceId = null,
        string? authSubject = null,
        IEnumerable<string>? scopes = null,
        bool isLoopback = false)
        => new(
            id ?? Guid.NewGuid().ToString("N"),
            kind,
            name,
            protocolVersion,
            DateTimeOffset.UtcNow)
        {
            RemoteAddress = remoteAddress,
            DeviceId = deviceId,
            AuthSubject = authSubject,
            Scopes = new HashSet<string>(scopes ?? [], StringComparer.OrdinalIgnoreCase),
            IsLoopback = isLoopback,
        };
}

/// <summary>Records one MCP invocation without coupling the transport to a host service.</summary>
public interface IMcpAuditLog
{
    void RecordMcp(string client, string tool, string arguments, string result, long elapsedMs);

    void RecordMcp(ClientSession session, string tool, string arguments, string result, long elapsedMs)
        => RecordMcp($"{session.Id}/{session.Name}", tool, arguments, result, elapsedMs);
}

/// <summary>Read-only description projection retained for Portunus' own schema exporter.</summary>
public interface IMcpPromptGovernanceView
{
    IReadOnlyDictionary<string, string> EffectiveDescriptions();
    IReadOnlyDictionary<string, int> OpenProposalCounts();
    IReadOnlyDictionary<string, int> IncidentCounts();
    string? CurrentRevisionId(string commandName);
}

/// <summary>Keys persisted by the Portunus transport configuration store.</summary>
public static class McpSettingKeys
{
    public const string Port = "mcp.port";
    public const string Policy = "mcp.policy";
    public const string Token = "mcp.token";
    public const string Autostart = "mcp.autostart";
    public const string Timeout = "mcp.timeout";
    public const string Confirm = "mcp.confirm";
    public const string ConfirmTimeout = "mcp.confirm.timeout";
    public const string PortRetries = "mcp.portretries";
    public const string SessionLimit = "mcp.sessionlimit";
    public const string Surface = "mcp.surface";

    /// <summary>模块级列法覆盖的设置键前缀：<c>mcp.surface.module.&lt;模块名&gt;</c>。</summary>
    public const string SurfaceModulePrefix = "mcp.surface.module.";

    /// <summary>某个模块的列法覆盖键；模块名大小写不敏感，统一存小写。</summary>
    public static string ModuleSurfaceKey(string module)
        => SurfaceModulePrefix + module.Trim().ToLowerInvariant();

    /// <summary>
    /// tools/list 的形态：full 每条指令一个工具（缺省）；compact 只列「搜索 + 调用」两个元工具，
    /// 客户端常驻上下文与指令数无关。只改列法，不改谁能调什么——调用仍走同一套策略与确认判断。
    /// </summary>
    public static string ResolveSurface(ISettingsService settings)
        => string.Equals(settings.Get(Surface)?.Trim(), "compact", StringComparison.OrdinalIgnoreCase)
            ? "compact"
            : "full";

    public static string ResolvePolicy(ISettingsService settings)
    {
        var configured = settings.Get(Policy);
        if (string.IsNullOrWhiteSpace(configured))
            return "standard";
        return configured.Equals("readonly", StringComparison.OrdinalIgnoreCase)
            ? "readonly"
            : "standard";
    }
}

/// <summary>一个模块的列法覆盖：模块名与 compact/full。</summary>
public sealed record ModuleSurface(string Module, string Mode);

/// <summary>
/// 模块级列法的解析规则：<c>mcp.surface.module.&lt;模块名&gt;</c> 覆盖全局 <c>mcp.surface</c>。
/// 只影响 tools/list 列出哪些工具；查找与调用仍以 <see cref="McpGateway.VisibleTools"/> 为准。
/// </summary>
public static class McpSurfacePolicy
{
    /// <summary>该模块最终生效的列法；没有覆盖时跟随全局。</summary>
    public static string Effective(ISettingsService settings, string? module)
    {
        if (!string.IsNullOrWhiteSpace(module))
        {
            var configured = settings.Get(McpSettingKeys.ModuleSurfaceKey(module))?.Trim();
            if (configured is not null
                && (configured.Equals("compact", StringComparison.OrdinalIgnoreCase)
                    || configured.Equals("full", StringComparison.OrdinalIgnoreCase)))
                return configured.ToLowerInvariant();
        }

        return McpSettingKeys.ResolveSurface(settings);
    }

    /// <summary>指令所属模块（目录来源形如 <c>module:Norma</c>）；宿主框架指令返回 null。</summary>
    public static string? ModuleOf(CatalogCommand command)
    {
        const string prefix = "module:";
        return command.Source.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
               && command.Source.Length > prefix.Length
            ? command.Source[prefix.Length..]
            : null;
    }

    /// <summary>当前所有 compact/full 覆盖，按模块名排序；inherit 视为没有覆盖。</summary>
    public static IReadOnlyList<ModuleSurface> Overrides(ISettingsService settings)
        => settings.All()
            .Where(pair => pair.Key.StartsWith(McpSettingKeys.SurfaceModulePrefix, StringComparison.OrdinalIgnoreCase))
            .Select(pair => new ModuleSurface(
                pair.Key[McpSettingKeys.SurfaceModulePrefix.Length..],
                Normalize(pair.Value)))
            .Where(item => item.Mode != "inherit")
            .OrderBy(item => item.Module, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>把设置值收成 compact / full / inherit 三种。</summary>
    public static string Normalize(string? value)
        => string.Equals(value?.Trim(), "compact", StringComparison.OrdinalIgnoreCase) ? "compact"
            : string.Equals(value?.Trim(), "full", StringComparison.OrdinalIgnoreCase) ? "full"
            : "inherit";
}

/// <summary>Centralized, fail-closed visibility policy for the Portunus MCP projection.</summary>
public static class McpExposurePolicy
{
    public static Func<string, string?>? ModuleOfCommand { get; set; }
    public static Func<string, string?>? ModuleExposure { get; set; }

    public static bool IsReadonlyAllowed(string commandName)
        => commandName.Equals("vulcan.command.list", StringComparison.OrdinalIgnoreCase)
           || commandName.Equals("vulcan.command.show", StringComparison.OrdinalIgnoreCase)
           || commandName.Equals("vulcan.command.domains", StringComparison.OrdinalIgnoreCase);

    public static string? HardExclusionReason(CatalogCommand descriptor)
    {
        if (!string.IsNullOrWhiteSpace(descriptor.HiddenReason))
            return descriptor.HiddenReason;

        var name = descriptor.Name;
        if (name.StartsWith("portunus.mcp.", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("vulcan.mcp.", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("vulcan.module.", StringComparison.OrdinalIgnoreCase)
            || name.Equals("vulcan.app.quit", StringComparison.OrdinalIgnoreCase)
            || name.Equals("vulcan.app.close", StringComparison.OrdinalIgnoreCase))
            return "transport-management";

        var module = ModuleOfCommand?.Invoke(name);
        return module != null && ModuleExposure?.Invoke(module)?.Equals("hidden", StringComparison.OrdinalIgnoreCase) == true
            ? "module-hidden"
            : null;
    }

    public static string State(CatalogCommand descriptor)
    {
        if (HardExclusionReason(descriptor) != null)
            return "hidden";
        return descriptor.Ask ? "ask" : descriptor.Readonly ? "readonly" : "standard";
    }

    public static bool IsVisible(CatalogCommand descriptor, string policy)
    {
        if (HardExclusionReason(descriptor) != null || descriptor.Ask)
            return false;
        return policy.Equals("standard", StringComparison.OrdinalIgnoreCase)
               || descriptor.Readonly
               || IsReadonlyAllowed(descriptor.Name);
    }
}

/// <summary>Flows a successful remote confirmation through the host's existing confirmation gate.</summary>
public static class McpConfirmationScope
{
    private static readonly AsyncLocal<int> Depth = new();

    public static bool PreApproved => Depth.Value > 0;

    public static async Task<T> RunPreApprovedAsync<T>(Func<Task<T>> action)
    {
        Depth.Value++;
        try { return await action().ConfigureAwait(false); }
        finally { Depth.Value--; }
    }
}

/// <summary>Validates persisted description text before it is projected to MCP clients.</summary>
public static class PromptTextIntegrity
{
    public static string ValidateDescription(string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        if (text.Length > 16_384 || text.Any(character => char.IsControl(character) && character is not '\r' and not '\n' and not '\t'))
            throw new ArgumentException("描述包含不允许的字符或超过长度限制", nameof(text));
        return text;
    }
}

/// <summary>Transport-owned MCP schema projection for the host command catalog.</summary>
public sealed class CommandSchemaExporter(ICommandCatalog catalog)
{
    public Func<IReadOnlyDictionary<string, string>>? DescriptionsProvider { get; init; }

    public IReadOnlyList<McpToolInfo> ExportTools()
    {
        var descriptions = DescriptionsProvider?.Invoke()
                           ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return catalog.All()
            .Where(descriptor => McpExposurePolicy.HardExclusionReason(descriptor) == null)
            .OrderBy(descriptor => descriptor.Name, StringComparer.OrdinalIgnoreCase)
            .Select(descriptor => CreateTool(descriptor, descriptions, used))
            .ToList();
    }

    public McpToolInfo? Find(string nameOrTool)
        => ExportTools().FirstOrDefault(tool => tool.ToolName.Equals(nameOrTool, StringComparison.OrdinalIgnoreCase)
                                             || tool.CommandName.Equals(nameOrTool, StringComparison.OrdinalIgnoreCase));

    public static string MakeToolName(string commandName, HashSet<string> used)
    {
        var normalized = new string(commandName.Select(character => char.IsAsciiLetterOrDigit(character) ? character : '_').ToArray());
        var candidate = normalized;
        for (var suffix = 2; !used.Add(candidate); suffix++)
            candidate = $"{normalized}_{suffix}";
        return candidate;
    }

    public static string BuildCommandText(string commandName, JsonElement? arguments)
    {
        if (arguments is not { ValueKind: JsonValueKind.Object } values)
            return commandName;

        var argumentsText = values.EnumerateObject().Select(property =>
        {
            var value = property.Value.ValueKind == JsonValueKind.String
                ? property.Value.GetString() ?? ""
                : property.Value.GetRawText();
            // Command text has its own quoting grammar, not JSON string escapes.
            value = CommandParser.QuoteArg(value);
            return $"{property.Name}={value}";
        });
        return string.Join(' ', new[] { commandName }.Concat(argumentsText));
    }

    private static McpToolInfo CreateTool(
        CatalogCommand descriptor,
        IReadOnlyDictionary<string, string> descriptions,
        HashSet<string> used)
    {
        var defaultDescription = string.IsNullOrWhiteSpace(descriptor.Example)
            ? descriptor.Summary
            : $"{descriptor.Summary}\n示例: {descriptor.Example}";
        var customized = descriptions.TryGetValue(descriptor.Name, out var description);
        var properties = new JsonObject();
        var required = new JsonArray();
        foreach (var parameter in descriptor.Parameters)
        {
            var schema = new JsonObject
            {
                ["type"] = parameter.Type.ToLowerInvariant() switch
                {
                    "int" => "integer",
                    "double" => "number",
                    "bool" => "boolean",
                    _ => "string",
                },
                ["description"] = parameter.Description,
            };
            if (parameter.AllowedValues is { Count: > 0 })
                schema["enum"] = new JsonArray(parameter.AllowedValues
                    .Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
            if (!string.IsNullOrWhiteSpace(parameter.Default))
                schema["default"] = parameter.Default;
            properties[parameter.Name] = schema;
            if (parameter.Required)
                required.Add(parameter.Name);
        }

        var inputSchema = new JsonObject
        {
            ["type"] = "object",
            ["properties"] = properties,
            ["additionalProperties"] = descriptor.AllowUnspecifiedParameters,
        };
        if (required.Count > 0)
            inputSchema["required"] = required;

        return new McpToolInfo(
            MakeToolName(descriptor.Name, used),
            descriptor.Name,
            customized ? description! : defaultDescription,
            inputSchema,
            descriptor.Ask,
            defaultDescription,
            customized);
    }
}

/// <summary>One MCP tool schema and its source command.</summary>
public sealed record McpToolInfo(
    string ToolName,
    string CommandName,
    string Description,
    JsonObject InputSchema,
    bool Dangerous,
    string DefaultDescription,
    bool Customized);
