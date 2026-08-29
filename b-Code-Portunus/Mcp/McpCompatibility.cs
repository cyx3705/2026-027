using System.Text.Json;
using System.Text.Json.Nodes;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Storage;

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

/// <summary>Centralized, fail-closed visibility policy for the Portunus MCP projection.</summary>
public static class McpExposurePolicy
{
    public static Func<string, string?>? ModuleOfCommand { get; set; }
    public static Func<string, string?>? ModuleExposure { get; set; }

    public static bool IsReadonlyAllowed(string commandName)
        => commandName.Equals("vulcan.command.list", StringComparison.OrdinalIgnoreCase)
           || commandName.Equals("vulcan.command.show", StringComparison.OrdinalIgnoreCase)
           || commandName.Equals("vulcan.command.domains", StringComparison.OrdinalIgnoreCase);

    public static string? HardExclusionReason(CommandDescriptor descriptor)
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

    public static string State(CommandDescriptor descriptor)
    {
        if (HardExclusionReason(descriptor) != null)
            return "hidden";
        return descriptor.Level == CommandLevel.Ask ? "ask" : descriptor.Readonly ? "readonly" : "standard";
    }

    public static bool IsVisible(CommandDescriptor descriptor, string policy)
    {
        if (HardExclusionReason(descriptor) != null || descriptor.Level == CommandLevel.Ask)
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

/// <summary>Confirmation implementation used by integration tests and the Portunus relay path.</summary>
public sealed class GatewayAwareConfirmation(HistoryVulcan.Core.Commands.IConfirmationService? inner)
    : HistoryVulcan.Core.Commands.IConfirmationService
{
    public bool Confirm(string prompt) => McpConfirmationScope.PreApproved || inner?.Confirm(prompt) == true;
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

/// <summary>Transport-owned MCP schema projection for the host command registry.</summary>
public sealed class CommandSchemaExporter(CommandRegistry registry)
{
    public Func<IReadOnlyDictionary<string, string>>? DescriptionsProvider { get; init; }

    public IReadOnlyList<McpToolInfo> ExportTools()
    {
        var descriptions = DescriptionsProvider?.Invoke()
                           ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return registry.All()
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
                ? JsonSerializer.Serialize(property.Value.GetString())
                : property.Value.GetRawText();
            return $"{property.Name}={value}";
        });
        return string.Join(' ', new[] { commandName }.Concat(argumentsText));
    }

    private static McpToolInfo CreateTool(
        CommandDescriptor descriptor,
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
                ["type"] = parameter.Type switch
                {
                    ParamType.Int => "integer",
                    ParamType.Double => "number",
                    ParamType.Bool => "boolean",
                    _ => "string",
                },
                ["description"] = parameter.Description,
            };
            if (parameter.AllowedValues is { Length: > 0 })
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
            descriptor.Level == CommandLevel.Ask,
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
