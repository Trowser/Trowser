using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

public sealed class XsLeakCredentialObservation
{
    public sealed class DeliveryResult
    {
        public string Subresource { get; init; } = "unknown";
        public string TopLevel { get; init; } = "not-run";
        public string? AuthCookieName { get; init; }
    }

    public static async Task<DeliveryResult> ObserveAsync(
        AutomationContext ctx,
        int probeTabIdx,
        string attackerOrigin,
        string victimUrl,
        IReadOnlyList<XsLeakSessionProfile.AuthCookieCandidate> authCookies,
        string cookieMode,
        bool includeTopLevel)
    {
        var probeCookie = XsLeakSessionProfile.PickCredentialProbeCookie(authCookies, cookieMode);
        var authName = probeCookie?.Name;
        var tab = ctx.Tabs[probeTabIdx];

        var sub = await ObserveOneAsync(tab, attackerOrigin, victimUrl, channel: "img", authName);
        await ctx.ClosePageOpenedChildrenAsync(tab.Id);

        var top = "not-run";
        if (includeTopLevel)
            top = await ObserveOneAsync(tab, attackerOrigin, victimUrl, channel: "popup", authName);

        await ctx.ClosePageOpenedChildrenAsync(tab.Id);

        return new DeliveryResult
        {
            Subresource = sub,
            TopLevel = top,
            AuthCookieName = authName
        };
    }

    private static async Task<string> ObserveOneAsync(
        BrowserTab tab,
        string attackerOrigin,
        string victimUrl,
        string channel,
        string? authCookieName)
    {
        try
        {
            return await await tab.WebView.Dispatcher.InvokeAsync(async () =>
            {
                var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                CoreWebView2DevToolsProtocolEventReceiver? receiver = null;
                CoreWebView2? core = null;

                void OnExtra(object? _, CoreWebView2DevToolsProtocolEventReceivedEventArgs e)
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(e.ParameterObjectAsJson);
                        if (!doc.RootElement.TryGetProperty("associatedCookies", out var assoc))
                            return;
                        foreach (var item in assoc.EnumerateArray())
                        {
                            var name = item.TryGetProperty("cookie", out var c)
                                && c.TryGetProperty("name", out var n)
                                    ? n.GetString()
                                    : null;
                            if (authCookieName != null
                                && !string.Equals(name, authCookieName, StringComparison.OrdinalIgnoreCase))
                                continue;

                            var isTarget = authCookieName == null
                                           || string.Equals(name, authCookieName,
                                               StringComparison.OrdinalIgnoreCase);
                            if (!isTarget)
                                continue;

                            if (item.TryGetProperty("blockedReasons", out var reasons)
                                && reasons.GetArrayLength() > 0)
                            {
                                var reason = reasons[0].GetString() ?? "blocked";
                                tcs.TrySetResult("blocked:" + reason);
                                return;
                            }

                            tcs.TrySetResult("sent");
                            return;
                        }
                    }
                    catch
                    {
                        tcs.TrySetResult("unknown");
                    }
                }

                try
                {
                    core = tab.WebView.CoreWebView2;
                    if (core == null)
                        return "unknown";

                    await core.CallDevToolsProtocolMethodAsync("Network.enable", "{}");
                    receiver = core.GetDevToolsProtocolEventReceiver("Network.requestWillBeSentExtraInfo");
                    receiver.DevToolsProtocolEventReceived += OnExtra;

                    var victimJson = JsonSerializer.Serialize(victimUrl);
                    var page = $"{attackerOrigin.TrimEnd('/')}/xsleak/credential-probe-{channel}";
                    var html = channel switch
                    {
                        "img" =>
                            $"""<!DOCTYPE html><html><body><img src="{victimUrl}" alt=""></body></html>""",
                        _ =>
                            "<!DOCTYPE html><html><body><script>window.open(" + victimJson +
                            ",\"_blank\",\"width=10,height=10\");</script></body></html>"
                    };
                    tab.MockResponse(page, 200, html,
                        headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
                    core.Navigate(page);

                    var completed = await Task.WhenAny(tcs.Task, Task.Delay(5000));
                    return completed == tcs.Task ? await tcs.Task : "unknown";
                }
                catch
                {
                    return "unknown";
                }
                finally
                {
                    if (receiver != null)
                        receiver.DevToolsProtocolEventReceived -= OnExtra;
                }
            });
        }
        catch
        {
            return "unknown";
        }
    }

    public object ToApiObject(DeliveryResult r) => new
    {
        subresource = r.Subresource,
        topLevel = r.TopLevel,
        authCookieName = r.AuthCookieName
    };
}