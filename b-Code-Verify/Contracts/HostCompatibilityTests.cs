using System.Reflection;
using HistoryPortunus;
using HistoryVulcan.Core.Commands;
using Xunit;

namespace HistoryPortunus.Contracts;

public sealed class HostCompatibilityTests
{
    [Fact]
    public void ModuleTargetsThePublishedFivePointOneHostSurfaceWithoutLegacyAssemblies()
    {
        var hostVersion = typeof(CommandBus).Assembly.GetName().Version;
        Assert.NotNull(hostVersion);
        Assert.True(hostVersion!.Major > 5 || hostVersion.Major == 5 && hostVersion.Minor >= 1);

        var references = typeof(PortunusComposition).Assembly.GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("HistoryVulcan.Core", references);
        Assert.DoesNotContain("HistoryVulcan.Extensibility", references);
        Assert.DoesNotContain("HistoryVulcan.Services", references);
    }
}
