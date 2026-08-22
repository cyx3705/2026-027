using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HistoryVulcan.Core;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Clients;
using HistoryVulcan.Core.Mcp;
using HistoryVulcan.Core.Storage;
using HistoryPortunus.Mcp;
using Xunit;


namespace HistoryPortunus.Contracts;

[Collection(TestCollections.Gateway)]
public sealed class McpSecurityTests
{
    /// <summary>
    /// 危险指令只在**宿主确认中继**开着的时候可见可调，其余一律不列不调。
    /// </summary>
    /// <remarks>
    /// 本测试此前叫 FrontendOptInIsEnforced…，验的是另一套闸门：描述符上的
    /// <c>ExecutionSite=Frontend</c> 默认不给 MCP 看，除非单独开 <c>AllowMcpExecution</c>。
    /// 界面变成宿主内模块（DEC-008）之后，全仓再没有任何一处把 ExecutionSite 设成
    /// Frontend——那套闸门只在这个测试里被触发过，字段与闸门已一并删除。
    ///
    /// 留下来的是真正在生产里起作用的那条：危险与否 × 中继开关。
    /// </remarks>
    [Fact]
    public async Task DangerousToolsAreCallableOnlyWhileTheHostConfirmRelayIsOn()
    {
        var executions = new List<string>();
        var registry = new CommandRegistry();
        registry.Register(Probe("probe.readable", executions, readOnly: true));
        registry.Register(Probe(
            "probe.danger",
            executions,
            readOnly: false,
            confirmPrompt: _ => "confirm"));

        // 内层确认通道刻意留空：GatewayAwareConfirmation 此时只认 MCP 预批准，
        // 于是危险指令能跑起来这件事，只可能是网关那道确认放行的，不会是别的兜底。
        var bus = new CommandBus(registry, new NullLog())
        {
            Confirmation = new GatewayAwareConfirmation(null),
        };
        var settings = new MemorySettings();
        settings.Set(McpSettingKeys.Policy, "standard");
        settings.Set(McpSettingKeys.Confirm, "host");
        var confirmations = 0;

        await WithGatewayAsync(bus, settings, new CaptureAudit(), () =>
        {
            confirmations++;
            return true;
        }, async client =>
        {
            // standard + host 确认 = 中继开着：危险指令此时可见可调，但必须问过人。
            using (var listed = await PostRpcAsync(client, 1, "tools/list", new { }))
            {
                var names = listed.RootElement.GetProperty("result").GetProperty("tools")
                    .EnumerateArray()
                    .Select(tool => tool.GetProperty("name").GetString())
                    .ToList();
                Assert.Contains("probe_readable", names);
                Assert.Contains("probe_danger", names);
            }

            using (var dangerous = await CallToolAsync(client, 2, "probe_danger", new { }))
                Assert.False(IsToolError(dangerous));
            Assert.Equal(1, confirmations);

            // 切到 readonly 策略，中继随之关闭：同一条指令立刻既不可见也不可调，
            // 而且**不许再弹确认**——弹了就等于把闸门变成一道可以点掉的提示。
            settings.Set(McpSettingKeys.Policy, "readonly");
            using (var listed = await PostRpcAsync(client, 3, "tools/list", new { }))
            {
                var names = listed.RootElement.GetProperty("result").GetProperty("tools")
                    .EnumerateArray()
                    .Select(tool => tool.GetProperty("name").GetString())
                    .ToList();
                Assert.Contains("probe_readable", names);
                Assert.DoesNotContain("probe_danger", names);
            }

            using (var refused = await CallToolAsync(client, 4, "probe_danger", new { }))
                Assert.True(IsToolError(refused));
            Assert.Equal(1, confirmations);

            using (var readable = await CallToolAsync(client, 5, "probe_readable", new { }))
                Assert.False(IsToolError(readable));

            Assert.Equal(["probe.danger", "probe.readable"], executions);
        });
    }

    [Fact]
    public async Task AuditRedactsSensitiveArgumentsOnSuccessfulAndRejectedCalls()
    {
        var registry = new CommandRegistry();
        registry.Register(new CommandDescriptor
        {
            Name = "audit.success",
            Summary = "audit",
            Parameters =
            [
                Parameter("apiToken"),
                Parameter("private_key"),
                Parameter("connectionString"),
                Parameter("code"),
            ],
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("ok")),
        });
        // 被拒调用同样要脱敏。用「危险且中继关着」造这个拒绝，
        // 与 Frontend 选择性暴露无关——那套闸门已随 ExecutionSite 删除。
        registry.Register(new CommandDescriptor
        {
            Name = "audit.hidden",
            Summary = "audit",
            Level = CommandLevel.Ask,
            ConfirmPrompt = _ => "confirm",
            Parameters = [Parameter("password")],
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("unused")),
        });
        registry.Register(new CommandDescriptor
        {
            Name = "vulcan.app.set",
            Summary = "set",
            Parameters = [Parameter("key"), Parameter("value")],
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("set")),
        });

        var bus = new CommandBus(registry, new NullLog());
        var settings = new MemorySettings();
        settings.Set(McpSettingKeys.Policy, "standard");
        var audit = new CaptureAudit();

        await WithGatewayAsync(bus, settings, audit, null, async client =>
        {
            using (var success = await CallToolAsync(client, 1, "audit_success", new
            {
                apiToken = "token-secret",
                private_key = "private-key-secret",
                connectionString = "connection-secret",
                code = "code-secret",
            }))
                Assert.False(IsToolError(success));
            using (var setting = await CallToolAsync(client, 2, "vulcan_app_set", new
            {
                key = "service.token",
                value = "setting-secret",
            }))
                Assert.False(IsToolError(setting));
            using (var rejected = await CallToolAsync(client, 3, "audit_hidden", new
            {
                password = "rejected-secret",
            }))
                Assert.True(IsToolError(rejected));
            using (var duplicateSettingKey = await PostRawRpcAsync(client,
                       """
                       {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"vulcan_app_set","arguments":{"key":"safe.setting","KEY":"mcp.token","value":"duplicate-key-secret"}}}
                       """))
                Assert.True(IsToolError(duplicateSettingKey));
        });

        Assert.Equal(4, audit.Entries.Count);
        var recorded = string.Join('\n', audit.Entries.Select(entry => entry.Arguments));
        foreach (var secret in new[]
                 {
                     "token-secret",
                     "private-key-secret",
                     "connection-secret",
                     "code-secret",
                     "setting-secret",
                     "rejected-secret",
                     "duplicate-key-secret",
                 })
            Assert.DoesNotContain(secret, recorded, StringComparison.Ordinal);
        Assert.All(audit.Entries, entry => Assert.Contains("[REDACTED]", entry.Arguments));
        Assert.Contains(audit.Entries, entry => entry.Tool == "vulcan_app_set"
                                                && entry.Arguments.Contains(
                                                    "service.token", StringComparison.Ordinal));
        Assert.Contains(audit.Entries, entry => entry.Tool == "audit_hidden" && entry.Result == "拒绝");
    }

    [Fact]
    public async Task EarlyToolsCallRejectionsAreAuditedWithoutLeakingArguments()
    {
        var registry = new CommandRegistry();
        registry.Register(new CommandDescriptor
        {
            Name = "audit.ready",
            Summary = "audit",
            Parameters = [Parameter("password")],
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("ok")),
        });
        CommandBus? currentBus = new(registry, new NullLog());
        var settings = new MemorySettings();
        settings.Set(McpSettingKeys.Policy, "standard");
        var audit = new CaptureAudit();

        await WithGatewayAsync(() => currentBus, settings, audit, null, async client =>
        {
            using (var invalidParams = await PostRpcAsync(
                       client, 1, "tools/call", "invalid-params-secret"))
                Assert.True(invalidParams.RootElement.TryGetProperty("error", out _));
            using (var missingName = await PostRpcAsync(client, 2, "tools/call", new
            {
                arguments = new { password = "missing-name-secret" },
            }))
                Assert.True(missingName.RootElement.TryGetProperty("error", out _));
            using (var nonStringName = await PostRpcAsync(client, 3, "tools/call", new
            {
                name = 42,
                arguments = new { password = "non-string-name-secret" },
            }))
                Assert.True(nonStringName.RootElement.TryGetProperty("error", out _));
            using (var unknown = await CallToolAsync(
                       client, 4, "audit_unknown", new { password = "unknown-tool-secret" }))
                Assert.True(unknown.RootElement.TryGetProperty("error", out _));
            using (var invalidName = await CallToolAsync(
                       client, 5, new string('x', 65), new { password = "invalid-name-secret" }))
                Assert.True(invalidName.RootElement.TryGetProperty("error", out _));

            currentBus = null;
            using (var unavailable = await CallToolAsync(
                       client, 6, "audit_ready", new { password = "unavailable-bus-secret" }))
                Assert.True(unavailable.RootElement.TryGetProperty("error", out _));
        });

        Assert.Equal(6, audit.Entries.Count);
        Assert.All(audit.Entries, entry => Assert.Equal("拒绝", entry.Result));
        Assert.Equal(3, audit.Entries.Count(entry => entry.Tool == "<missing>"));
        Assert.Contains(audit.Entries, entry => entry.Tool == "<unknown>");
        Assert.Contains(audit.Entries, entry => entry.Tool == "<invalid>");
        Assert.Contains(audit.Entries, entry => entry.Tool == "audit_ready");
        var recorded = string.Join('\n', audit.Entries.Select(entry => entry.Arguments));
        foreach (var secret in new[]
                 {
                     "invalid-params-secret",
                     "missing-name-secret",
                     "non-string-name-secret",
                      "unknown-tool-secret",
                      "invalid-name-secret",
                      "unavailable-bus-secret",
                 })
            Assert.DoesNotContain(secret, recorded, StringComparison.Ordinal);
        Assert.All(audit.Entries, entry => Assert.Contains("[REDACTED]", entry.Arguments));
    }

    [Fact]
    public async Task BearerAndProtocolRejectionsAreFailClosedAndAudited()
    {
        var registry = new CommandRegistry();
        registry.Register(new CommandDescriptor
        {
            Name = "auth.ready",
            Summary = "auth",
            Readonly = true,
            Parameters = [Parameter("password")],
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("ok")),
        });
        var bus = new CommandBus(registry, new NullLog());
        var settings = new MemorySettings();
        settings.Set(McpSettingKeys.Token, "correct-token");
        var audit = new CaptureAudit();

        await WithGatewayAsync(bus, settings, audit, null, async client =>
        {
            client.DefaultRequestHeaders.Remove("MCP-Protocol-Version");
            const string body =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" +
                "\"name\":\"auth_ready\",\"arguments\":{\"password\":\"protocol-secret\"}}}";

            using (var wrongRequest = new HttpRequestMessage(HttpMethod.Post, "mcp"))
            {
                wrongRequest.Headers.TryAddWithoutValidation("Authorization", "Bearer wrong-token");
                wrongRequest.Headers.TryAddWithoutValidation(
                    "MCP-Protocol-Version", McpGateway.SupportedProtocols[0]);
                wrongRequest.Content = new StringContent(body, Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(wrongRequest);
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            }

            using (var invalidProtocol = new HttpRequestMessage(HttpMethod.Post, "mcp"))
            {
                invalidProtocol.Headers.TryAddWithoutValidation("Authorization", "bEaReR correct-token");
                invalidProtocol.Headers.TryAddWithoutValidation(
                    "MCP-Protocol-Version", new string('v', 100));
                invalidProtocol.Content = new StringContent(body, Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(invalidProtocol);
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                var payload = await response.Content.ReadAsStringAsync();
                Assert.DoesNotContain(new string('v', 65), payload, StringComparison.Ordinal);
            }

            using (var accepted = new HttpRequestMessage(HttpMethod.Post, "mcp"))
            {
                accepted.Headers.TryAddWithoutValidation("Authorization", "Bearer correct-token");
                accepted.Headers.TryAddWithoutValidation(
                    "MCP-Protocol-Version", McpGateway.SupportedProtocols[0]);
                accepted.Content = new StringContent(body, Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(accepted);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
        });

        Assert.Contains(audit.Entries, entry => entry.Tool == "(auth)" && entry.Result == "拒绝");
        Assert.Contains(audit.Entries, entry => entry.Tool == "<invalid>"
                                                && entry.Result == "拒绝·协议版本");
        Assert.Contains(audit.Entries, entry => entry.Tool == "auth_ready" && entry.Result == "成功");
        Assert.DoesNotContain("protocol-secret",
            string.Join('\n', audit.Entries.Select(entry => entry.Arguments)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task InitializeBoundsClientMetadataBeforeCachingAndLogging()
    {
        var registry = new CommandRegistry();
        registry.Register(new CommandDescriptor
        {
            Name = "identity.read",
            Summary = "identity",
            Readonly = true,
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("ok")),
        });
        var bus = new CommandBus(registry, new NullLog());
        var settings = new MemorySettings();
        var audit = new CaptureAudit();

        await WithGatewayAsync(bus, settings, audit, null, async client =>
        {
            var rawName = "client\r\nforged-log-" + new string('n', 300);
            var body = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "unknown\r\nprotocol-" + new string('p', 100),
                    clientInfo = new { name = rawName },
                },
            });
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var response = await client.PostAsync("mcp", content);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(response.Headers.TryGetValues("Mcp-Session-Id", out var ids));
            client.DefaultRequestHeaders.Remove("Mcp-Session-Id");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Mcp-Session-Id", ids.Single());
            using var call = await CallToolAsync(client, 2, "identity_read", new { });
            Assert.False(IsToolError(call));
        });

        var entry = Assert.Single(audit.Entries);
        Assert.Equal(100, entry.Client.Length);
        Assert.DoesNotContain('\r', entry.Client);
        Assert.DoesNotContain('\n', entry.Client);
        Assert.Equal(McpGateway.SupportedProtocols[0], entry.ProtocolVersion);
    }

    [Fact]
    public async Task RemoteConfirmationExceptionsAreAuditedOnceWithoutMessageLeakage()
    {
        var registry = new CommandRegistry();
        registry.Register(new CommandDescriptor
        {
            Name = "secure.action",
            Summary = "secure",
            Parameters = [Parameter("password")],
            Level = CommandLevel.Ask,
            ConfirmPrompt = _ => "confirm",
            Handler = CommandDescriptor.Sync(_ => CommandResult.Ok("should-not-run")),
        });
        var bus = new CommandBus(registry, new NullLog());
        var settings = new MemorySettings();
        settings.Set(McpSettingKeys.Policy, "standard");
        settings.Set(McpSettingKeys.Confirm, "host");
        var audit = new CaptureAudit();
        var log = new CaptureLog();

        await WithGatewayAsync(
            bus,
            settings,
            audit,
            () => throw new InvalidOperationException("callback-secret"),
            async client =>
            {
                using var response = await CallToolAsync(
                    client, 1, "secure_action", new { password = "argument-secret" });
                var payload = response.RootElement.ToString();
                Assert.Contains(nameof(InvalidOperationException), payload, StringComparison.Ordinal);
                Assert.DoesNotContain("callback-secret", payload, StringComparison.Ordinal);
            },
            log);

        var entry = Assert.Single(audit.Entries);
        Assert.Equal("异常", entry.Result);
        Assert.DoesNotContain("argument-secret", entry.Arguments, StringComparison.Ordinal);
        Assert.DoesNotContain("callback-secret",
            string.Join('\n', log.Entries.Select(item => item.Message)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RemoteConfirmationQueueTimesOutWithoutExecutingOrDuplicatingAudit()
    {
        var executions = 0;
        var registry = new CommandRegistry();
        registry.Register(new CommandDescriptor
        {
            Name = "queued.action",
            Summary = "queued",
            Level = CommandLevel.Ask,
            ConfirmPrompt = _ => "confirm",
            Handler = CommandDescriptor.Sync(_ =>
            {
                executions++;
                return CommandResult.Ok("should-not-run");
            }),
        });
        var bus = new CommandBus(registry, new NullLog());
        var settings = new MemorySettings();
        settings.Set(McpSettingKeys.Policy, "standard");
        settings.Set(McpSettingKeys.Confirm, "host");
        settings.Set(McpSettingKeys.ConfirmTimeout, "10");
        var audit = new CaptureAudit();

        await WithGatewayAsync(bus, settings, audit, () => true, async (gateway, client) =>
        {
            var field = typeof(McpGateway).GetField(
                "_confirmGate", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            var gate = Assert.IsType<SemaphoreSlim>(field?.GetValue(gateway));
            await gate.WaitAsync();
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                using var response = await CallToolAsync(client, 1, "queued_action", new { });
                sw.Stop();
                Assert.True(IsToolError(response));
                var message = response.RootElement.GetProperty("result").GetProperty("content")[0]
                    .GetProperty("text").GetString();
                Assert.Contains("确认排队超时", message, StringComparison.Ordinal);
                Assert.InRange(sw.Elapsed, TimeSpan.FromSeconds(9), TimeSpan.FromSeconds(20));
            }
            finally
            {
                gate.Release();
            }
        });

        var entry = Assert.Single(audit.Entries);
        Assert.Equal("确认排队超时", entry.Result);
        Assert.True(entry.ElapsedMs >= 9_000);
        Assert.Equal(0, executions);
    }

    [Fact]
    public void FileAuditRecorderBoundsEveryUntrustedTextField()
    {
        var root = Path.Combine(Path.GetTempPath(), "HistoryVulcan-mcp-audit-bounds-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var recorder = new McpAuditRecorder(root, new NullLog());
            recorder.RecordMcp(null!, null!, null!, null!, 0);
            IMcpAuditLog audit = recorder;
            audit.RecordMcp(
                ClientSession.Create(ClientKind.Mcp, new string('c', 1_000), id: "stable-session"),
                new string('t', 2_000),
                new string('a', 3_000),
                new string('r', 4_000),
                0);

            var path = Path.Combine(root, "state", "mcp-history.jsonl");
            var lines = File.ReadAllLines(path);
            Assert.Equal(2, lines.Length);
            using var nullDocument = JsonDocument.Parse(lines[0]);
            Assert.Equal("", nullDocument.RootElement.GetProperty("Client").GetString());
            Assert.Equal("", nullDocument.RootElement.GetProperty("Tool").GetString());
            Assert.Equal("", nullDocument.RootElement.GetProperty("Arguments").GetString());
            Assert.Equal("", nullDocument.RootElement.GetProperty("Result").GetString());

            using var boundedDocument = JsonDocument.Parse(lines[1]);
            var row = boundedDocument.RootElement;
            Assert.StartsWith("stable-session/", row.GetProperty("Client").GetString(), StringComparison.Ordinal);
            Assert.Equal(256, row.GetProperty("Client").GetString()!.Length);
            Assert.Equal(128, row.GetProperty("Tool").GetString()!.Length);
            Assert.Equal(500, row.GetProperty("Arguments").GetString()!.Length);
            Assert.Equal(100, row.GetProperty("Result").GetString()!.Length);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>执行时把自己的名字记进 <paramref name="executions"/> 的探针指令。</summary>
    private static CommandDescriptor Probe(
        string name,
        List<string> executions,
        bool readOnly,
        Func<CommandContext, string?>? confirmPrompt = null)
        => new()
        {
            Name = name,
            Summary = name,
            Readonly = readOnly,
            Level = confirmPrompt == null ? CommandLevel.Run : CommandLevel.Ask,
            ConfirmPrompt = confirmPrompt,
            Handler = CommandDescriptor.Sync(_ =>
            {
                executions.Add(name);
                return CommandResult.Ok("probe-ok");
            }),
        };

    private static ParameterSpec Parameter(string name)
        => new() { Name = name, Description = name };

    private static async Task WithGatewayAsync(
        CommandBus bus,
        MemorySettings settings,
        CaptureAudit audit,
        Func<bool>? confirm,
        Func<HttpClient, Task> test,
        IShellLog? log = null)
        => await WithGatewayAsync(() => bus, settings, audit, confirm, test, log);

    private static async Task WithGatewayAsync(
        CommandBus bus,
        MemorySettings settings,
        CaptureAudit audit,
        Func<bool>? confirm,
        Func<McpGateway, HttpClient, Task> test,
        IShellLog? log = null)
        => await WithGatewayAsync(() => bus, settings, audit, confirm, test, log);

    private static async Task WithGatewayAsync(
        Func<CommandBus?> busAccessor,
        MemorySettings settings,
        CaptureAudit audit,
        Func<bool>? confirm,
        Func<HttpClient, Task> test,
        IShellLog? log = null)
        => await WithGatewayAsync(
            busAccessor, settings, audit, confirm, (_, client) => test(client), log);

    private static async Task WithGatewayAsync(
        Func<CommandBus?> busAccessor,
        MemorySettings settings,
        CaptureAudit audit,
        Func<bool>? confirm,
        Func<McpGateway, HttpClient, Task> test,
        IShellLog? log = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "HistoryVulcan-mcp-security-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var gatewayLog = log ?? new NullLog();
            using var gateway = new McpGateway(
                busAccessor,
                settings,
                gatewayLog,
                audit,
                new PromptGovernanceStore(root, gatewayLog),
                new HistoryVulcan.Core.ApplicationIdentity("Test", "3.0.0", "3.0.0", "3.0.0.0"),
                confirm == null ? null : (_, _, _) => confirm());
            var started = gateway.Start(FreePort());
            Assert.True(started.Success, started.Message);

            using var client = new HttpClient
            {
                BaseAddress = new Uri($"http://127.0.0.1:{gateway.Port}/"),
            };
            client.DefaultRequestHeaders.TryAddWithoutValidation(
                "MCP-Protocol-Version", McpGateway.SupportedProtocols[0]);
            await test(gateway, client);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task<JsonDocument> CallToolAsync(HttpClient client, int id, string name, object arguments)
        => PostRpcAsync(client, id, "tools/call", new { name, arguments });

    private static async Task<JsonDocument> PostRpcAsync(
        HttpClient client,
        int id,
        string method,
        object parameters)
    {
        var request = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["method"] = method,
            ["params"] = parameters,
        });
        return await PostRawRpcAsync(client, request);
    }

    private static async Task<JsonDocument> PostRawRpcAsync(HttpClient client, string request)
    {
        using var content = new StringContent(request, Encoding.UTF8, "application/json");
        using var response = await client.PostAsync("mcp", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static bool IsToolError(JsonDocument response)
        => response.RootElement.GetProperty("result").GetProperty("isError").GetBoolean();

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private sealed class MemorySettings : ISettingsService
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
        public string? Get(string key) => _values.GetValueOrDefault(key);
        public int GetInt(string key, int fallback) => int.TryParse(Get(key), out var value) ? value : fallback;
        public void Set(string key, string value) => _values[key] = value;
        public IReadOnlyList<KeyValuePair<string, string>> All() => _values.ToList();
    }

    private sealed class CaptureAudit : IMcpAuditLog
    {
        public List<AuditEntry> Entries { get; } = [];

        public void RecordMcp(string client, string tool, string arguments, string result, long elapsedMs)
            => Entries.Add(new AuditEntry(client, "", tool, arguments, result, elapsedMs));

        public void RecordMcp(
            ClientSession session,
            string tool,
            string arguments,
            string result,
            long elapsedMs)
            => Entries.Add(new AuditEntry(
                session.Name, session.ProtocolVersion, tool, arguments, result, elapsedMs));
    }

    private sealed record AuditEntry(
        string Client,
        string ProtocolVersion,
        string Tool,
        string Arguments,
        string Result,
        long ElapsedMs);

    private sealed class CaptureLog : IShellLog
    {
        public List<ShellLogEntry> Entries { get; } = [];
        public void Log(ShellLogLevel level, string category, string message)
            => Entries.Add(new ShellLogEntry(DateTime.Now, level, category, message));
        public event EventHandler<ShellLogEntry>? EntryAdded { add { } remove { } }
        public IReadOnlyList<ShellLogEntry> Snapshot() => Entries;
    }

    private sealed class NullLog : IShellLog
    {
        public void Log(ShellLogLevel level, string category, string message) { }
        public event EventHandler<ShellLogEntry>? EntryAdded { add { } remove { } }
        public IReadOnlyList<ShellLogEntry> Snapshot() => [];
    }
}
