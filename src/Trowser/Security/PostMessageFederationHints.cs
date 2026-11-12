using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Generic session hints linking postMessage audit to OAuth/SAML federation testing (no app-specific rules).</summary>
internal static class PostMessageFederationHints
{
    public static IEnumerable<string> NextActionsFromSession(
        AutomationContext ctx,
        IReadOnlyList<PostMessageListenerInfo> listeners)
    {
        var actions = new List<string>();
        var hasOAuthAuthorize = ctx.Network.Entries.Any(e => OAuthFlowTester.IsAuthorizeUrl(e.Url));
        var hasOAuthCallback = ctx.Network.Entries.Any(e =>
            e.Url.Contains("code=", StringComparison.OrdinalIgnoreCase)
            || e.Url.Contains("access_token", StringComparison.OrdinalIgnoreCase));
        var hasSaml = FederatedAuthSignals.ScanNetwork(ctx.Network).Count > 0;
        var hasMessageListeners = listeners.Count > 0;

        if (hasOAuthAuthorize || hasOAuthCallback)
        {
            actions.Add("browser_security_oauth_flow_test passiveOnly (or flowBreaker when active probes flag redirect issues)");
            if (hasMessageListeners)
                actions.Add("OAuth callbacks often use postMessage — re-run postmessage audit on the callback origin after authorize");
        }

        if (hasSaml && hasMessageListeners)
            actions.Add("Federation session detected — correlate postMessage handlers with SAML/OAuth landing (see oauth-flow-test authSignals)");

        return actions.Distinct(StringComparer.OrdinalIgnoreCase).Take(4);
    }
}
