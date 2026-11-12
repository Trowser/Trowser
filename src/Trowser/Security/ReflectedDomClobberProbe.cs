using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Passive HTML reflection check for DOM clobbering gadgets (no runtime trap required on first paint).
/// </summary>
public static class ReflectedDomClobberProbe
{
    private static readonly Regex HtmlEscapeHint = new(
        @"&lt;(?:form|input|a)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public sealed class Outcome
    {
        public string GlobalName { get; init; } = "";
        public string Param { get; init; } = "";
        public string ProbeUrl { get; init; } = "";
        public bool ReflectedUnescaped { get; init; }
        public string? Evidence { get; init; }
    }

    public static async Task<Outcome?> TryFetchReflectionAsync(
        AutomationContext ctx,
        string pageUrl,
        string globalName,
        string paramName,
        int timeoutMs = 12_000,
        CancellationToken ct = default,
        string? propertyName = null)
    {
        if (string.IsNullOrWhiteSpace(pageUrl) || string.IsNullOrWhiteSpace(globalName))
            return null;

        var marker = $"data-trowser-clobber-{Guid.NewGuid():N}"[..28];
        var inputName = string.IsNullOrWhiteSpace(propertyName) ? globalName : propertyName;
        var payload =
            $"<form id=\"{globalName}\"><input name=\"{inputName}\" value=\"{marker}\"></form>";
        var probeUrl = AppendQuery(StripHash(pageUrl), $"{paramName}={Uri.EscapeDataString(payload)}");

        ct.ThrowIfCancellationRequested();
        var resp = await SecurityProbeHttp.FetchAsync(
            ctx, probeUrl, "GET", null, null, timeoutMs, includeBrowserCookies: true, ct);
        if (resp.Status == 0 || string.IsNullOrEmpty(resp.Body))
            return null;

        var body = resp.Body;
        var reflected = body.Contains(marker, StringComparison.Ordinal)
                        && body.Contains($"name=\"{inputName}\"", StringComparison.OrdinalIgnoreCase)
                        && !HtmlEscapeHint.IsMatch(body);

        if (!reflected)
            return null;

        return new Outcome
        {
            GlobalName = globalName,
            Param = paramName,
            ProbeUrl = probeUrl,
            ReflectedUnescaped = true,
            Evidence =
                $"GET parameter '{paramName}' reflects clobbering HTML for global '{globalName}' without entity-encoding (fetch probe)."
        };
    }

    private static string StripHash(string url)
    {
        var i = url.IndexOf('#');
        return i >= 0 ? url[..i] : url;
    }

    private static string AppendQuery(string baseUrl, string query)
    {
        var sep = baseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return baseUrl + sep + query;
    }
}
