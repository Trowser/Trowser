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
        var sub = await ObserveOneAsync(tab, attackerOrigin, victimUrl, subresource: true, authName);
        var top = includeTopLevel
            ? await ObserveOneAsync(tab, attackerOrigin, victimUrl, subresource: false, authName)
            : "not-run";
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
        bool subresource,
        string? authCookieName)
    {
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            await tab.WebView.Dispatcher.InvokeAsync(async () =>
            {
                var core = tab.WebView.CoreWebView2;
                await core.CallDevToolsProtocolMethodAsync("Network.enable", "{}");

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
                                ? n.GetString() : null;
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

                var receiver = core.GetDevToolsProtocolEventReceiver("Network.requestWillBeSentExtraInfo");
                receiver.DevToolsProtocolEventReceived += OnExtra;

                var page = $"{attackerOrigin.TrimEnd('/')}/xsleak/credential-probe-{(subresource ? "img" : "popup")}";
                var html = subresource
                    ? $"""<!DOCTYPE html><html><body><img src="{victimUrl}"></body></html>"""
                    : $"""<!DOCTYPE html><html><body><script>window.open({JsonSerializer.Serialize(victimUrl)},"_blank","width=10,height=10");</script></body></html>""";
                tab.MockResponse(page, 200, html,
                    headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
                core.Navigate(page);

                _ = Task.Run(async () =>
                {
                    await Task.Delay(5200);
                    receiver.DevToolsProtocolEventReceived -= OnExtra;
                    tcs.TrySetResult("unknown");
                });
            });

            var completed = await Task.WhenAny(tcs.Task, Task.Delay(5500));
            return completed == tcs.Task ? await tcs.Task : "unknown";
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
