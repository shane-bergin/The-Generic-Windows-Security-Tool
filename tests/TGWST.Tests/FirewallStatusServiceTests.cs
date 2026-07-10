using TGWST.Core.Network;

namespace TGWST.Tests;

public sealed class FirewallStatusServiceTests
{
    [Fact]
    public void Parse_PreservesStricterOutboundBlockAsCompliant()
    {
        const string json = """
            [
              {
                "Name":"Public",
                "Enabled":true,
                "DefaultInboundAction":"Block",
                "DefaultOutboundAction":"Block"
              }
            ]
            """;

        var profile = Assert.Single(FirewallStatusService.Parse(json));

        Assert.False(profile.IsVulnerable);
        Assert.Equal("BlockInbound,BlockOutbound", profile.Policy);
    }

    [Fact]
    public void Parse_FlagsDisabledOrAllowInboundProfile()
    {
        const string json = """
            [
              {
                "Name":"Private",
                "Enabled":false,
                "DefaultInboundAction":"Allow",
                "DefaultOutboundAction":"Allow"
              }
            ]
            """;

        var profile = Assert.Single(FirewallStatusService.Parse(json));

        Assert.True(profile.IsVulnerable);
        Assert.Equal("OFF", profile.State);
    }

    [Fact]
    public void Parse_RejectsMissingProfileEvidence()
    {
        Assert.Throws<InvalidOperationException>(() => FirewallStatusService.Parse(""));
        Assert.Throws<InvalidOperationException>(() => FirewallStatusService.Parse("[]"));
    }
}
