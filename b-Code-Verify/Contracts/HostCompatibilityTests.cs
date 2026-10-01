using System.Reflection;
using HistoryPortunus;
using HistoryVulcan.Core.Commands;
using Xunit;

namespace HistoryPortunus.Contracts;

public sealed class HostCompatibilityTests
{
    [Fact]
    public void ModuleTargetsTheSixPointZeroContractSurfaceWithoutLegacyAssemblies()
    {
        var hostVersion = typeof(ICommandBus).Assembly.GetName().Version;
        Assert.NotNull(hostVersion);
        Assert.True(hostVersion!.Major >= 6, $"宿主契约程序集 {hostVersion} 早于 6.0.0");

        var references = typeof(PortunusComposition).Assembly.GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("HistoryVulcan.Core", references);
        Assert.DoesNotContain("HistoryVulcan.Extensibility", references);
        Assert.DoesNotContain("HistoryVulcan.Services", references);
    }
}
