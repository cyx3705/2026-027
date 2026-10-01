// 宿主 6.0.0 统一契约下的模块测试替身（DEC-071）。
//
// 6.0.0 起宿主的总线与注册表是内部类，模块只看得到 ICommandBus / ICommandRegistrar / IModuleLog。
// 这里按宿主总线的公开规则写一份最小实现：解析、参数绑定（位置 / 键=值 / 必填 / 类型 / 取值）、
// 级别为 Ask 时问确认、处理器异常转失败。它只用于本仓离线测试；
// 真实装载与执行以 HistoryVulcan.Cli.exe --probe 为准。

using System.Collections.Concurrent;
using System.Globalization;
using HistoryVulcan.Core.Commands;
using HistoryVulcan.Core.Logging;

/// <summary>登记口替身：记下登记了哪些指令，重名即抛（与宿主一致）。</summary>
internal sealed class TestRegistrar : ICommandRegistrar
{
    private readonly Dictionary<string, CommandDescriptor> _commands = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<CommandDescriptor> All()
    {
        lock (_commands)
            return _commands.Values.OrderBy(command => command.Name, StringComparer.Ordinal).ToList();
    }

    public void Register(CommandDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (descriptor.ConfirmPrompt != null && descriptor.Level != CommandLevel.Ask)
            throw new ArgumentException($"指令 {descriptor.Name} 写了 ConfirmPrompt 但级别不是 Ask", nameof(descriptor));
        lock (_commands)
        {
            if (!_commands.TryAdd(descriptor.Name, descriptor))
                throw new InvalidOperationException($"指令名冲突: {descriptor.Name} 已注册");
        }
    }

    public bool TryGet(string name, out CommandDescriptor descriptor)
    {
        lock (_commands)
            return _commands.TryGetValue(name, out descriptor!);
    }

    /// <summary>撤掉一条（模拟模块热重载后指令消失）。</summary>
    public bool Unregister(string name)
    {
        lock (_commands)
            return _commands.Remove(name);
    }
}

/// <summary>只写日志替身：记下每一条。</summary>
internal sealed class TestLog : IModuleLog
{
    private readonly ConcurrentQueue<(ShellLogLevel Level, string Category, string Message)> _entries = new();

    public IReadOnlyList<(ShellLogLevel Level, string Category, string Message)> Entries => _entries.ToArray();

    public void Log(ShellLogLevel level, string category, string message) => _entries.Enqueue((level, category, message));
}

/// <summary>总线替身：执行 <see cref="TestRegistrar"/> 里登记的指令，其余指令交给 <see cref="Fallback"/>。</summary>
internal sealed class TestCommandBus(TestRegistrar registrar, Func<string, bool>? confirm = null) : ICommandBus
{
    private readonly ConcurrentQueue<(string Text, string Source)> _calls = new();

    public TestRegistrar Registrar { get; } = registrar;

    /// <summary>每次执行的文本与来源（按调用顺序）。</summary>
    public IReadOnlyList<(string Text, string Source)> Calls => _calls.ToArray();

    /// <summary>本仓没登记的指令（例如别的模块的）怎么答；缺省答未知指令。</summary>
    public Func<string, string, Task<CommandResult>>? Fallback { get; set; }

    /// <summary>进度行收集处；缺省丢弃。</summary>
    public IProgress<string>? Progress { get; set; }

    public Task<CommandResult> ExecuteAsync(string text, string source, CancellationToken cancellation = default)
        => RunAsync(text, source, cancellation);

    public Task<CommandResult> InvokeAsync(string text, string source, CancellationToken cancellation = default)
        => RunAsync(text, source, cancellation);

    public bool RequestConfirmation(string prompt) => confirm?.Invoke(prompt) ?? false;

    private async Task<CommandResult> RunAsync(string text, string source, CancellationToken cancellation)
    {
        _calls.Enqueue((text, source));
        ParsedCommand parsed;
        try
        {
            parsed = CommandParser.Parse(text.Trim());
        }
        catch (CommandSyntaxException ex)
        {
            return CommandResult.Fail(ex.Message);
        }

        if (!Registrar.TryGet(parsed.Name, out var descriptor))
        {
            return Fallback != null
                ? await Fallback(text, source).ConfigureAwait(false)
                : CommandResult.Fail($"未知指令: {parsed.Name}");
        }

        var error = Bind(descriptor, parsed, out var values);
        if (error != null)
            return CommandResult.Fail(error);

        var context = new CommandContext(descriptor, values, source, Progress, cancellation);
        if (descriptor.Level == CommandLevel.Ask)
        {
            var prompt = descriptor.ConfirmPrompt == null ? $"确认执行 {descriptor.Name}？" : descriptor.ConfirmPrompt(context);
            if (prompt != null && confirm == null)
                return CommandResult.Fail("该指令需要二次确认,但当前环境没有确认通道,已拒绝执行");
            if (prompt != null && !confirm!(prompt))
                return CommandResult.Fail("已取消(用户未确认)");
        }

        try
        {
            return await descriptor.Handler(context).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return CommandResult.Fail("指令已取消");
        }
        catch (Exception ex)
        {
            return CommandResult.Fail($"{descriptor.Name} 执行异常: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static string? Bind(CommandDescriptor descriptor, ParsedCommand parsed, out IReadOnlyDictionary<string, string> values)
    {
        var bound = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        values = bound;
        if (descriptor.AllowUnspecifiedParameters)
        {
            foreach (var (key, value) in parsed.Named)
                bound[key] = value;
            return null;
        }

        var positional = descriptor.Parameters.Where(p => p.Position.HasValue).OrderBy(p => p.Position!.Value).ToArray();
        if (parsed.Positionals.Count > positional.Length)
            return $"多余的位置参数: {string.Join(" ", parsed.Positionals.Skip(positional.Length))}";
        for (var i = 0; i < parsed.Positionals.Count; i++)
            bound[positional[i].Name] = parsed.Positionals[i];

        foreach (var (key, value) in parsed.Named)
        {
            var spec = descriptor.Parameters.FirstOrDefault(p => p.Name.Equals(key, StringComparison.OrdinalIgnoreCase));
            if (spec == null)
                return $"未知参数: {key}=";
            bound[spec.Name] = value;
        }

        foreach (var spec in descriptor.Parameters)
        {
            if (!bound.TryGetValue(spec.Name, out var value))
            {
                if (spec.Required)
                    return $"缺少必填参数: {spec.Name}=";
                continue;
            }

            var typeError = spec.Type switch
            {
                ParamType.Int when !int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _)
                    => $"参数 {spec.Name} 应为整数,实际: {value}",
                ParamType.Double when !double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _)
                    => $"参数 {spec.Name} 应为数值,实际: {value}",
                ParamType.Bool when value.ToLowerInvariant() is not ("true" or "false" or "1" or "0" or "yes" or "no" or "on" or "off")
                    => $"参数 {spec.Name} 应为 true/false,实际: {value}",
                _ => null,
            };
            if (typeError != null)
                return typeError;
            if (spec.AllowedValues is { Length: > 0 } && !spec.AllowedValues.Contains(value, StringComparer.OrdinalIgnoreCase))
                return $"参数 {spec.Name} 取值应为 {string.Join("/", spec.AllowedValues)},实际: {value}";
        }

        return null;
    }
}
