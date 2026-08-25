using System.Text.Json;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;
using HistoryVulcan.Core.Storage;
using HistoryPortunus.Mcp;
using Xunit;

namespace HistoryPortunus.Contracts;

public sealed class PromptGovernanceExternalizationTests
{
    private static readonly string[] RemovedPromptCommands =
    [
        "vulcan.prompt.correct",
        "vulcan.prompt.corrections",
        "vulcan.prompt.diff",
        "vulcan.prompt.get",
        "vulcan.prompt.history",
        "vulcan.prompt.incidents",
        "vulcan.prompt.propose",
        "vulcan.prompt.record",
    ];

    private static readonly string[] RemovedGovernanceCommands =
    [
        .. RemovedPromptCommands,
        "portunus.mcp.apply",
        "portunus.mcp.approve",
        "portunus.mcp.desc",
        "portunus.mcp.pending",
        "portunus.mcp.reject",
        "portunus.mcp.revert",
    ];

    [Fact]
    public void ExistingGovernanceStateRemainsReadableWithoutBeingRewritten()
    {
        var root = TemporaryDirectory();
        try
        {
            var stateDirectory = Path.Combine(root, "state");
            Directory.CreateDirectory(stateDirectory);
            var statePath = Path.Combine(stateDirectory, "prompt-governance.json");
            var original = """
                {
                  "formatVersion": 1,
                  "revisions": [
                    {
                      "id": "rev-existing",
                      "command": "sample.run",
                      "description": "描述来自历史修订",
                      "parentRevision": null,
                      "source": "legacy",
                      "reason": "历史记录",
                      "created": "2026-08-01 10:00:00",
                      "createdBy": "operator",
                      "applied": true,
                      "revertedFrom": null
                    }
                  ],
                  "proposals": [{ "id": "proposal-existing" }],
                  "corrections": [{ "id": "correction-existing" }],
                  "incidents": [{ "id": "incident-existing" }]
                }
                """;
            File.WriteAllText(statePath, original);

            var store = new PromptGovernanceStore(root, new NullLog());

            Assert.Equal(
                "描述来自历史修订",
                Assert.Single(store.AllEffectiveDescriptions()).Value);
            Assert.Equal("rev-existing", store.GetCurrentRevision("sample.run")!.Id);
            Assert.Equal("描述来自历史修订", store.GetRevisions("sample.run").Single().Description);
            Assert.Equal(original, File.ReadAllText(statePath));
        }
        finally
        {
            DeleteDirectory(root);
        }
    }

    [Fact]
    public void DescriptionReaderPreservesToolDescriptionSnapshot()
    {
        var root = TemporaryDirectory();
        try
        {
            var registry = new CommandRegistry();
            registry.Register(new CommandDescriptor
            {
                Name = "sample.run",
                Summary = "默认描述",
                Example = "sample.run",
                Readonly = true,
                Handler = CommandDescriptor.Sync(_ => CommandResult.Ok()),
            });
            registry.Register(new CommandDescriptor
            {
                Name = "sample.other",
                Summary = "另一条描述",
                Readonly = true,
                Handler = CommandDescriptor.Sync(_ => CommandResult.Ok()),
            });

            var store = new PromptGovernanceStore(root, new NullLog());
            var before = ExportDescriptions(registry, store);
            IEffectivePromptDescriptionReader reader = store;
            var after = ExportDescriptions(registry, reader);

            Assert.Equal(before, after);
            Assert.Equal("默认描述\n示例: sample.run", after["sample_run"]);
            Assert.Equal("另一条描述", after["sample_other"]);
        }
        finally
        {
            DeleteDirectory(root);
        }
    }

    /// <summary>
    /// 治理外置只应从可见工具集里拿掉提示词治理那几条，别的一条都不许多、不许少。
    /// </summary>
    /// <remarks>
    /// 断言从「数到 16」改成「集合恰好等于夹具指令」（4.4.0）。原因是数字断言在本轮
    /// 差点放过一个真问题：网关迁往 HistoryPortunus 后指令改名 vulcan.mcp.* → portunus.mcp.*，
    /// 而 McpExposurePolicy 的硬排除写的是 StartsWith("vulcan.mcp.")，当场失效——
    /// start / stop / autostart 一并变成远端可见工具，等于把「关掉正在服务你的那条通道」
    /// 交给了远端。数字从 16 变 18 只说明「多了两个」，集合断言直接说出多的是哪两个。
    ///
    /// 同批 16 → 12：vulcan.command.list / show / domains / manual 改由宿主注册，
    /// 不再经本模块，因此不出现在这里。那是归属变更，不是暴露面变更。
    /// </remarks>
    [Fact]
    public void OnlyPromptGovernanceCommandsLeaveTheVisibleToolContract()
    {
        var root = TemporaryDirectory();
        try
        {
            var registry = new CommandRegistry();
            var settings = new MemorySettings();
            var store = new PromptGovernanceStore(root, new NullLog());
            RegisterUnaffectedHostTools(registry);

            McpCommands.RegisterAll(
                registry,
                () => null,
                () => null,
                settings,
                store,
                "test");

            var exporter = new CommandSchemaExporter(registry)
            {
                DescriptionsProvider = store.AllEffectiveDescriptions,
            };
            var after = exporter.ExportTools()
                .ToDictionary(tool => tool.CommandName, tool => tool.Description, StringComparer.OrdinalIgnoreCase);
            var registeredNames = registry.All()
                .Select(descriptor => descriptor.Name)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            // 可见工具集必须恰好是那些无关的宿主夹具指令：
            // MCP 自身的管理面（<域>.mcp.*）一条都不许出现，无论它挂在哪个域下。
            Assert.Equal(
                UnaffectedHostToolNames().Order(StringComparer.OrdinalIgnoreCase),
                after.Keys.Order(StringComparer.OrdinalIgnoreCase));
            foreach (var command in RemovedGovernanceCommands)
                Assert.DoesNotContain(command, registeredNames);

            RegisterLegacyPromptTools(registry);
            var before = exporter.ExportTools()
                .ToDictionary(tool => tool.CommandName, tool => tool.Description, StringComparer.OrdinalIgnoreCase);

            Assert.Equal(
                UnaffectedHostToolNames().Concat(RemovedPromptCommands)
                    .Order(StringComparer.OrdinalIgnoreCase),
                before.Keys.Order(StringComparer.OrdinalIgnoreCase));
            Assert.Equal(
                RemovedPromptCommands.Order(StringComparer.OrdinalIgnoreCase),
                before.Keys.Except(after.Keys, StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase));
            foreach (var (command, description) in after)
                Assert.Equal(description, before[command]);
        }
        finally
        {
            DeleteDirectory(root);
        }
    }

    /// <summary>与治理无关的宿主夹具指令名；可见工具集应当恰好是这一组。</summary>
    private static IEnumerable<string> UnaffectedHostToolNames()
        => Enumerable.Range(1, 12).Select(index => $"vulcan.fixture{index:00}");

    private static void RegisterUnaffectedHostTools(CommandRegistry registry)
    {
        for (var index = 1; index <= 12; index++)
        {
            var name = $"vulcan.fixture{index:00}";
            registry.Register(new CommandDescriptor
            {
                Name = name,
                Summary = $"Unchanged host tool {index:00}",
                Readonly = true,
                Handler = CommandDescriptor.Sync(_ => CommandResult.Ok()),
            });
        }
    }

    private static void RegisterLegacyPromptTools(CommandRegistry registry)
    {
        foreach (var command in RemovedPromptCommands)
        {
            registry.Register(new CommandDescriptor
            {
                Name = command,
                Summary = $"Legacy prompt tool {command}",
                Readonly = true,
                Handler = CommandDescriptor.Sync(_ => CommandResult.Ok()),
            });
        }
    }

    private static Dictionary<string, string> ExportDescriptions(
        CommandRegistry registry,
        IEffectivePromptDescriptionReader reader)
    {
        var exporter = new CommandSchemaExporter(registry)
        {
            DescriptionsProvider = reader.AllEffectiveDescriptions,
        };
        return exporter.ExportTools()
            .ToDictionary(tool => tool.ToolName, tool => tool.Description, StringComparer.OrdinalIgnoreCase);
    }

    private static string TemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "HistoryVulcan.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteDirectory(string path)
    {
        if (Directory.Exists(path))
            Directory.Delete(path, recursive: true);
    }

    private sealed class MemorySettings : ISettingsService
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

        public string? Get(string key) => _values.GetValueOrDefault(key);

        public int GetInt(string key, int fallback)
            => int.TryParse(Get(key), out var value) ? value : fallback;

        public void Set(string key, string value) => _values[key] = value;

        public IReadOnlyList<KeyValuePair<string, string>> All() => _values.ToList();
    }

    private sealed class NullLog : IShellLog
    {
        public void Log(ShellLogLevel level, string category, string message) { }

        public event EventHandler<ShellLogEntry>? EntryAdded
        {
            add { }
            remove { }
        }

        public IReadOnlyList<ShellLogEntry> Snapshot() => [];
    }
}
