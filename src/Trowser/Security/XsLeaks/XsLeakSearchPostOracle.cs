using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

/// <summary>Detects when auto-selected GET search URLs miss POST-driven result pages.</summary>
internal static class XsLeakSearchPostOracle
{
    public static void AppendWarningsIfNeeded(
        AutomationContext ctx,
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        List<string> warnings)
    {
        foreach (var state in states)
        {
            if (!Uri.TryCreate(state.Url, UriKind.Absolute, out var u))
                continue;
            if (!u.Query.Contains('=', StringComparison.Ordinal))
                continue;

            var path = u.AbsolutePath;
            var postEntries = ctx.Network.Entries
                .Where(e => e.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                            && Uri.TryCreate(e.Url, UriKind.Absolute, out var pu)
                            && string.Equals(pu.Host, u.Host, StringComparison.OrdinalIgnoreCase)
                            && string.Equals(pu.AbsolutePath, path, StringComparison.OrdinalIgnoreCase)
                            && e.StatusCode is >= 200 and < 400)
                .ToList();

            if (postEntries.Count == 0)
                continue;

            var getEntries = ctx.Network.Entries
                .Where(e => e.Method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                            && e.Url.StartsWith(u.GetLeftPart(UriPartial.Path), StringComparison.OrdinalIgnoreCase))
                .Take(20)
                .ToList();

            if (getEntries.Count == 0)
            {
                warnings.Add(
                    $"Session traffic shows POST {path} with results, but XS-Leaks states use GET {state.Url}. " +
                    "Model POST with states[].method/form or hypothesis.method=POST and formFields.");
                continue;
            }

            var postLen = postEntries.Max(e => e.ContentLengthBytes ?? e.ResponseBody?.Length ?? 0);
            var getLen = getEntries.Max(e => e.ContentLengthBytes ?? e.ResponseBody?.Length ?? 0);
            if (postLen > 512 && getLen > 0 && Math.Abs(postLen - getLen) < 64)
            {
                warnings.Add(
                    $"GET {path} and POST {path} return similarly sized shells ({getLen} vs {postLen} bytes) — " +
                    "hit/miss on GET query strings may not reflect POST search results. Use POST states or browse POST search before scanning.");
            }
        }
    }
}
