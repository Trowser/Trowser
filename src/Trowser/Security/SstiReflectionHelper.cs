using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>Shared SSTI arithmetic reflection checks (word-boundary token + baseline diff + unevaluated expression guard).</summary>
public static class SstiReflectionHelper
{
    public static bool DetectArithmeticReflection(string payload, string baseline, string probe)
    {
        if (string.IsNullOrEmpty(probe)) return false;

        var expects49 = payload.Contains("7*7", StringComparison.Ordinal)
                        || payload.Contains("7*'7'", StringComparison.Ordinal);
        var expects56 = payload.Contains("7*8", StringComparison.Ordinal);
        if (!expects49 && !expects56) return false;

        var token = expects56 ? "56" : "49";
        if (!ContainsIsolatedToken(probe, token))
            return false;
        if (ContainsIsolatedToken(baseline, token))
            return false;

        // Payload still visible in response → expression was echoed, not evaluated server-side.
        if (ContainsUnevaluatedExpression(probe, payload))
            return false;

        return true;
    }

    private static bool ContainsIsolatedToken(string text, string token) =>
        Regex.IsMatch(text, $@"(?<!\d){Regex.Escape(token)}(?!\d)");

    private static bool ContainsUnevaluatedExpression(string probe, string payload)
    {
        foreach (var fragment in GetExpressionFragments(payload))
        {
            if (probe.Contains(fragment, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static IEnumerable<string> GetExpressionFragments(string payload)
    {
        // Prefer more specific fragments first so doT `{{=7*7}}` is not treated as Jinja `{{7*7}}`.
        if (payload.Contains("{{=", StringComparison.Ordinal))
        {
            yield return "{{=7*7}}";
            yield return "{{= 7*7 }}";
        }
        else if (payload.Contains("{{", StringComparison.Ordinal))
        {
            yield return "{{7*7}}";
        }
        if (payload.Contains("${", StringComparison.Ordinal))
            yield return "${7*7}";
        if (payload.Contains("#{", StringComparison.Ordinal))
            yield return "#{7*7}";
        if (payload.Contains("@(", StringComparison.Ordinal))
            yield return "@(7*7)";
        if (payload.Contains("<%=", StringComparison.Ordinal))
            yield return "7*7";
        if (payload.Contains("7*7", StringComparison.Ordinal))
            yield return "7*7";
        if (payload.Contains("7*8", StringComparison.Ordinal))
            yield return "7*8";
    }
}
