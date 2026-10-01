using HistoryPortunus.Mcp;
using HistoryVulcan.Core.Commands;

namespace HistoryPortunus.Contracts;

/// <summary>
/// 测试用的指令目录：把 <see cref="TestRegistrar"/> 里的描述符按宿主目录的 JSON 形状投成 <see cref="CatalogCommand"/>。
/// </summary>
/// <remarks>
/// 生产里网关经总线执行 <c>vulcan.command.list</c> 取目录（<see cref="BusCommandCatalog"/>）；测试进程里没有宿主，
/// 这里按宿主模块API写明的字段语义直接投影，来源默认 <c>framework</c>，按名覆盖。
/// </remarks>
internal sealed class TestCatalog(Func<TestRegistrar?> registrar) : ICommandCatalog
{
    private readonly Dictionary<string, string> _sources = new(StringComparer.OrdinalIgnoreCase);

    public TestCatalog(TestRegistrar registrar)
        : this(() => registrar)
    {
    }

    /// <summary>指定某条指令的来源（形如 <c>module:HistoryJanus</c>）。</summary>
    public void SetSource(string name, string source) => _sources[name] = source;

    /// <summary>某条指令的来源；未指定时为 <c>framework</c>。</summary>
    public string SourceOf(string name) => _sources.GetValueOrDefault(name, "framework");

    private TestRegistrar? _last;

    /// <summary>与 <see cref="BusCommandCatalog"/> 一致：总线暂时不在时沿用上一次读到的目录。</summary>
    private TestRegistrar? Current => _last = registrar() ?? _last;

    public IReadOnlyList<CatalogCommand> All()
        => (Current?.All() ?? []).Select(Project).ToList();

    public bool TryGet(string name, out CatalogCommand command)
    {
        command = null!;
        var current = Current;
        if (current == null || !current.TryGet(name, out var descriptor))
            return false;
        command = Project(descriptor);
        return true;
    }

    private CatalogCommand Project(CommandDescriptor descriptor)
        => new(
            descriptor.Name,
            descriptor.Summary,
            descriptor.Example,
            SourceOf(descriptor.Name),
            descriptor.Level == CommandLevel.Ask,
            descriptor.Readonly,
            string.IsNullOrEmpty(descriptor.HiddenReason) ? null : descriptor.HiddenReason,
            descriptor.AllowUnspecifiedParameters,
            descriptor.Parameters.Select(parameter => new CatalogParameter(
                parameter.Name,
                parameter.Type.ToString().ToLowerInvariant(),
                parameter.Required,
                parameter.Default,
                parameter.Position,
                parameter.AllowedValues ?? [],
                parameter.Description)).ToList());
}
