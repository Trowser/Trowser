using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Shared CSRF anti-forgery token name and value heuristics used by the CSRF scanner,
/// secrets harvest correlation, and attack-surface detection.
/// </summary>
public static class CsrfTokenHeuristics
{
    public static readonly string[] KnownHeaderNames =
    [
        "x-csrf-token", "x-xsrf-token", "x-anti-forgery-token",
        "requestverificationtoken", "__requestverificationtoken",
        "x-csrftoken", "csrf-token", "anti-csrf-token",
    ];

    public static readonly string[] KnownFieldNames =
    [
        "__RequestVerificationToken", "_token", "csrf_token", "csrfmiddlewaretoken",
        "_csrf", "authenticity_token", "antiforgery", "XSRF-TOKEN", "anti_forgery_token",
        "_csrf_token", "user_token", "form_token", "session_token", "security_token",
        "nonce", "_nonce", "request_token", "verification_token",
    ];

    /// <summary>Exact DOM field names plus substring rules in <see cref="IsCsrfFieldCandidate"/>.</summary>
    public static readonly string[] KnownDomFieldNames =
    [
        "csrf", "csrfmiddlewaretoken", "_token", "authenticity_token", "anti_forgery_token",
        "__RequestVerificationToken", "csrf_token", "_csrf_token", "_csrf", "xsrf-token", "xsrf_token",
        "user_token", "form_token", "session_token", "security_token", "request_token",
    ];

    private static readonly string[] NameMarkerSubstrings = ["token", "nonce", "key"];

    /// <summary>Names containing these markers are not treated as CSRF (OAuth/API/session identifiers).</summary>
    private static readonly string[] ExcludedNameMarkers =
    [
        "access_token", "id_token", "refresh_token", "token_type", "token_endpoint",
        "api_key", "apikey", "public_key", "private_key", "secret_key", "signing_key",
        "auth_key", "license_key", "product_key", "encryption_key", "master_key",
    ];

    private static readonly Regex Md5Hex = new(@"\A[0-9a-f]{32}\z", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Sha1Hex = new(@"\A[0-9a-f]{40}\z", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Sha256Hex = new(@"\A[0-9a-f]{64}\z", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Uuid = new(
        @"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Base64ish = new(@"\A[A-Za-z0-9+/=_\-]{16,128}\z", RegexOptions.Compiled);
    private static readonly Regex FormFieldNameAttr = new(
        @"\bname\s*=\s*(?:""([^""]+)""|'([^']+)')",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Header names that are not a CSRF control: tracing, proxy, and platform headers
    /// that happen to use an <c>X-</c> prefix.
    /// </summary>
    private static readonly HashSet<string> NonCsrfXHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "X-Request-Id", "X-Correlation-Id", "X-Trace-Id", "X-B3-TraceId", "X-B3-SpanId",
        "X-B3-Sampled", "X-B3-Parentspanid", "X-Datadog-Trace-Id", "X-Datadog-Parent-Id",
        "X-Datadog-Sampling-Priority", "X-Datadog-Origin", "X-Cloud-Trace-Context",
        "X-Amzn-Trace-Id", "X-Amzn-RequestId", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Scheme", "X-Real-IP",
        "X-Client-Ip", "X-Original-URL", "X-Original-Host", "X-Request-Start",
        "X-Scheme", "X-Timer", "X-Accel-Buffering", "X-Content-Type-Options",
        "X-Frame-Options", "X-XSS-Protection", "X-Download-Options", "X-DNS-Prefetch-Control",
        "X-Permitted-Cross-Domain-Policies",
    };

    public static bool IsCsrfHeaderName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;
        if (KnownHeaderNames.Any(n => name.Equals(n, StringComparison.OrdinalIgnoreCase)))
            return true;

        // X-CSRF, X-XSRF, CSRF, and similar names that are not in the exact list.
        // The value may be a fixed flag ("1") rather than a secret; callers still treat the header as the control.
        var lower = name.ToLowerInvariant();
        return lower.Contains("csrf") || lower.Contains("xsrf") || lower.Contains("antiforgery")
               || lower.Contains("forgery") || lower.Contains("requestverification");
    }

    /// <summary>
    /// A non-safelisted request header that a simple cross-site form cannot set.
    /// Names that <see cref="IsCsrfHeaderName"/> already recognizes are excluded so they stay on the token-replay path.
    /// Tracing and proxy <c>X-</c> headers are excluded so dropping them is not treated as a CSRF test.
    /// </summary>
    public static bool IsCustomHeaderCsrfCandidate(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.StartsWith(':'))
            return false;
        if (IsCsrfHeaderName(name) || NonCsrfXHeaders.Contains(name))
            return false;
        if (name.StartsWith("sec-", StringComparison.OrdinalIgnoreCase))
            return false;
        if (name.Equals("X-Requested-With", StringComparison.OrdinalIgnoreCase)
            || name.Equals("X-Request-With", StringComparison.OrdinalIgnoreCase)
            || name.Equals("X-HTTP-Method-Override", StringComparison.OrdinalIgnoreCase))
            return true;
        return name.StartsWith("X-", StringComparison.OrdinalIgnoreCase);
    }

    public static List<string> CustomHeaderCsrfCandidates(IEnumerable<KeyValuePair<string, string>> headers)
    {
        var list = new List<string>();
        foreach (var header in headers)
        {
            if (IsCustomHeaderCsrfCandidate(header.Key))
                list.Add(header.Key);
        }
        return list;
    }

    public static bool IsKnownCsrfFieldName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        foreach (var known in KnownFieldNames)
        {
            if (name.Equals(known, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        foreach (var known in KnownDomFieldNames)
        {
            if (name.Equals(known, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        var lower = name.ToLowerInvariant();
        return lower.Contains("csrf") || lower.Contains("xsrf") || lower.Contains("antiforgery")
               || lower.Contains("forgery") || lower.Contains("requestverification");
    }

    /// <summary>
    /// Returns true when a form/body/query field is likely an anti-CSRF token.
    /// Broad name markers (token/nonce/key) require a hidden input and/or a random-looking value.
    /// </summary>
    public static bool IsCsrfFieldCandidate(string name, string? fieldType = null, string? value = null)
    {
        if (IsKnownCsrfFieldName(name))
            return true;

        if (string.IsNullOrWhiteSpace(name))
            return false;

        var lower = name.ToLowerInvariant();
        foreach (var excluded in ExcludedNameMarkers)
        {
            if (lower.Contains(excluded, StringComparison.Ordinal))
                return false;
        }

        var hasMarker = NameMarkerSubstrings.Any(m => lower.Contains(m, StringComparison.Ordinal));
        if (!hasMarker)
            return false;

        var isHidden = fieldType != null
            && fieldType.Equals("hidden", StringComparison.OrdinalIgnoreCase);
        var randomValue = !string.IsNullOrEmpty(value) && LooksLikeCsrfTokenValue(value);

        return isHidden || randomValue;
    }

    public static bool LooksLikeCsrfTokenValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 8)
            return false;

        if (Md5Hex.IsMatch(value) || Sha1Hex.IsMatch(value) || Sha256Hex.IsMatch(value))
            return true;
        if (Uuid.IsMatch(value))
            return true;

        return value.Length >= 16 && Base64ish.IsMatch(value);
    }

    public static bool BodyContainsField(string body, string field)
    {
        var t = body.TrimStart();
        if (t.StartsWith('{'))
            return body.Contains("\"" + field + "\"", StringComparison.OrdinalIgnoreCase);
        return body.Contains(field + "=", StringComparison.OrdinalIgnoreCase)
               || body.Contains("&" + field + "=", StringComparison.OrdinalIgnoreCase)
               || body.StartsWith(field + "=", StringComparison.OrdinalIgnoreCase);
    }

    public static bool TryExtractFromBody(string? body, out string? fieldName)
    {
        fieldName = null;
        if (string.IsNullOrEmpty(body))
            return false;

        foreach (var known in KnownFieldNames)
        {
            if (BodyContainsField(body, known))
            {
                fieldName = known;
                return true;
            }
        }

        foreach (var (name, value) in EnumerateBodyFields(body))
        {
            if (IsCsrfFieldCandidate(name, null, value))
            {
                fieldName = name;
                return true;
            }
        }

        foreach (Match match in FormFieldNameAttr.Matches(body))
        {
            var name = match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
            if (IsCsrfFieldCandidate(name, "hidden", null))
            {
                fieldName = name;
                return true;
            }
        }

        return false;
    }

    public static bool TryExtractFromQuery(string? query, out string? paramName)
    {
        paramName = null;
        if (string.IsNullOrEmpty(query) || query == "?")
            return false;

        var q = query.TrimStart('?');
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            var pname = eq >= 0 ? Uri.UnescapeDataString(part[..eq]) : Uri.UnescapeDataString(part);
            var pvalue = eq >= 0 ? Uri.UnescapeDataString(part[(eq + 1)..]) : "";

            if (KnownFieldNames.Any(f => pname.Equals(f, StringComparison.OrdinalIgnoreCase))
                || IsCsrfFieldCandidate(pname, "hidden", pvalue))
            {
                paramName = pname;
                return true;
            }
        }

        return false;
    }

    public static IEnumerable<(string Name, string Value)> EnumerateBodyFields(string body)
    {
        var t = body.TrimStart();
        if (t.StartsWith('{'))
        {
            foreach (var (name, value) in EnumerateJsonFields(body))
                yield return (name, value ?? "");
            yield break;
        }

        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0)
                continue;
            yield return (
                Uri.UnescapeDataString(pair[..eq]),
                Uri.UnescapeDataString(pair[(eq + 1)..]));
        }
    }

    private static IEnumerable<(string Name, string? Value)> EnumerateJsonFields(string body)
    {
        JsonDocument? doc = null;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch
        {
            yield break;
        }

        using (doc)
        {
            foreach (var prop in doc.RootElement.EnumerateObject())
                yield return (prop.Name, prop.Value.ValueKind == JsonValueKind.String
                    ? prop.Value.GetString()
                    : prop.Value.ToString());
        }
    }

    /// <summary>Token-like field names visible in a CSRF form-field summary (e.g. user_token=abc…).</summary>
    public static List<string> ExtractMissedTokenFieldsFromSummary(string? formFieldsSummary)
    {
        var missed = new List<string>();
        if (string.IsNullOrWhiteSpace(formFieldsSummary))
            return missed;

        foreach (var segment in formFieldsSummary.Split(',', StringSplitOptions.TrimEntries))
        {
            var eq = segment.IndexOf('=');
            var name = eq >= 0 ? segment[..eq].Trim() : segment.Trim();
            var value = eq >= 0 ? segment[(eq + 1)..].Trim() : null;
            if (string.IsNullOrEmpty(name))
                continue;
            if (IsCsrfFieldCandidate(name, "hidden", value))
                missed.Add(name);
        }

        return missed.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
