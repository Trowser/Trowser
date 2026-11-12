using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public sealed class FederatedAuthSignalsTests
{
    [Fact]
    public void Detects_saml_redirect_binding()
    {
        var signals = FederatedAuthSignals.ScanEntries([
            new NetworkEntry
            {
                Url = "https://idp.example/sso?SAMLRequest=jZFN...",
                Method = "GET"
            }
        ]);
        Assert.Contains(signals, s => s.Protocol == "saml" && s.Binding == "HTTP-Redirect");
    }

    [Fact]
    public void Detects_saml_post_to_acs()
    {
        var signals = FederatedAuthSignals.ScanEntries([
            new NetworkEntry
            {
                Url = "https://sp.example/saml/acs",
                Method = "POST",
                RequestBody = "SAMLResponse=PHNhbWxw..."
            }
        ]);
        Assert.Contains(signals, s => s.Protocol == "saml" && s.Binding == "HTTP-POST");
    }

    [Fact]
    public void Next_actions_include_saml_tools_when_no_oauth()
    {
        var signals = FederatedAuthSignals.ScanEntries([
            new NetworkEntry
            {
                Url = "https://sp.example/saml/acs",
                Method = "POST",
                RequestBody = "SAMLResponse=x"
            }
        ]);
        var actions = FederatedAuthSignals.BuildNextActions(signals, oauthFlowsCaptured: false);
        Assert.Contains(actions, a => a.Contains("saml_decode", StringComparison.OrdinalIgnoreCase));
    }
}
