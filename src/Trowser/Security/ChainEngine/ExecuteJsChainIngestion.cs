using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.ChainEngine;

/// <summary>
/// Auto-ingests verified security signals from <c>execute-js</c> results into the chain findings feed.
/// Closes the gap between manual browser verification and automated chain analysis.
/// </summary>
public static class ExecuteJsChainIngestion
{
    private static readonly Regex DocumentCookiePattern = new(@"\bdocument\.cookie\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex FetchPattern = new(@"\bfetch\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex AuthCookieNamePattern = new(
        @"(session|auth|token|jwt|sid|access|refresh|bearer|login|credential|xsrf|csrf)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex JwtValuePattern = new(@"^eyJ[A-Za-z0-9_-]+\.", RegexOptions.Compiled);

    /// <summary>
    /// Inspect an execute-js script/result pair and upsert chain findings when verification succeeds.
    /// </summary>
    public static async Task<IReadOnlyList<ChainableFinding>> TryIngestAsync(
        AutomationContext ctx,
        string script,
        string result)
    {
        if (string.IsNullOrWhiteSpace(script) || string.IsNullOrWhiteSpace(result))
            return [];

        var ingested = new List<ChainableFinding>();
        var pageUrl = await SafeGetCurrentUrl(ctx);

        if (DocumentCookiePattern.IsMatch(script))
        {
            var finding = TryIngestMissingHttpOnly(result, pageUrl);
            if (finding != null)
            {
                ctx.UpsertVerifiedChainFinding(finding);
                ingested.Add(finding);
            }
        }

        if (FetchPattern.IsMatch(script))
        {
            var finding = TryIngestSqliFromFetch(result, pageUrl);
            if (finding != null)
            {
                ctx.UpsertVerifiedChainFinding(finding);
                ingested.Add(finding);
            }
        }

        return ingested;
    }

    private static ChainableFinding? TryIngestMissingHttpOnly(string result, string? pageUrl)
    {
        var cookieLine = ExtractCookieLineFromExecuteJsResult(result);
        if (string.IsNullOrEmpty(cookieLine) || !cookieLine.Contains('='))
            return null;

        var cookieNames = ParseCookieNames(cookieLine);
        if (cookieNames.Count == 0)
            return null;

        var auditableNames = cookieNames
            .Where(n => !CookieAuditChecker.IsJsReadableByDesign(n))
            .ToList();
        if (auditableNames.Count == 0)
            return null;

        var authCookies = auditableNames.Where(IsAuthRelevantCookieName).ToList();
        if (authCookies.Count == 0 && CookieLineHasAuthTokenValue(cookieLine))
            authCookies = auditableNames;
        var highlighted = authCookies.Count > 0 ? authCookies : auditableNames;
        var evidence = TruncateEvidence(cookieLine);
        var endpoint = pageUrl ?? "";

        return new ChainableFinding
        {
            Id = BuildStableId("execute-js-httponly", endpoint),
            Source = "execute-js",
            Category = "missing-httponly",
            Severity = authCookies.Count > 0 ? "high" : "low",
            Title = authCookies.Count > 0
                ? "Session/auth cookie readable via document.cookie (HttpOnly missing)"
                : "Cookie readable via document.cookie (HttpOnly missing)",
            Endpoint = string.IsNullOrWhiteSpace(endpoint) ? null : endpoint,
            Detail = $"document.cookie returned {highlighted.Count} cookie(s): {string.Join(", ", highlighted.Take(6))}. " +
                     "Cookies visible to JavaScript are not HttpOnly and can be stolen via XSS.",
            Evidence = evidence,
            Tags = ["execute-js", "verified", "missing-httponly"]
        };
    }

    private static ChainableFinding? TryIngestSqliFromFetch(string result, string? pageUrl)
    {
        var scanText = ExtractFetchScanText(result);
        if (string.IsNullOrWhiteSpace(scanText))
            return null;

        var sqlHits = ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(scanText);
        if (sqlHits.Count == 0)
            return null;

        var hasServerError = LooksLikeServerError(result, scanText);
        if (!hasServerError && !ContainsStrongSqlSignature(sqlHits))
            return null;

        var topHit = sqlHits[0];
        var endpoint = pageUrl ?? "";

        return new ChainableFinding
        {
            Id = BuildStableId("execute-js-sqli", endpoint),
            Source = "execute-js",
            Category = "sqli",
            Severity = "high",
            Title = "SQL error confirmed via execute-js fetch probe",
            Endpoint = string.IsNullOrWhiteSpace(endpoint) ? null : endpoint,
            Detail = $"fetch probe response contains SQL error signature ({topHit.Engine}: {topHit.Pattern}).",
            Evidence = topHit.Snippet ?? TruncateEvidence(scanText),
            Tags = ["execute-js", "verified", "sqli"]
        };
    }

    private static string ExtractFetchScanText(string result)
    {
        var trimmed = result.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return "";

        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                return ExtractTextFromJson(doc.RootElement);
            }
            catch
            {
                return trimmed;
            }
        }

        return trimmed;
    }

    private static string ExtractTextFromJson(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                return element.GetString() ?? "";
            case JsonValueKind.Object:
            {
                var parts = new List<string>();
                foreach (var prop in element.EnumerateObject())
                {
                    if (prop.Name.Equals("body", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Equals("text", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Equals("response", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Equals("data", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Equals("message", StringComparison.OrdinalIgnoreCase) ||
                        prop.Name.Equals("error", StringComparison.OrdinalIgnoreCase))
                    {
                        parts.Add(ExtractTextFromJson(prop.Value));
                    }
                }

                if (parts.Count > 0)
                    return string.Join("\n", parts.Where(p => !string.IsNullOrWhiteSpace(p)));

                return element.GetRawText();
            }
            case JsonValueKind.Array:
                return string.Join("\n", element.EnumerateArray().Select(ExtractTextFromJson));
            default:
                return element.GetRawText();
        }
    }

    private static bool LooksLikeServerError(string rawResult, string scanText)
    {
        if (Regex.IsMatch(rawResult, @"""status""\s*:\s*5\d\d", RegexOptions.IgnoreCase))
            return true;
        if (Regex.IsMatch(scanText, @"\b500\b|\binternal server error\b", RegexOptions.IgnoreCase))
            return true;
        return false;
    }

    private static bool ContainsStrongSqlSignature(IReadOnlyList<ResponseBodySecurityHeuristics.SqlSignatureHit> hits) =>
        hits.Any(h => !h.Engine.Equals("generic", StringComparison.OrdinalIgnoreCase));

    private static string? ExtractCookieLineFromExecuteJsResult(string result)
    {
        var trimmed = result.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Equals("null", StringComparison.OrdinalIgnoreCase))
            return null;

        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (doc.RootElement.ValueKind == JsonValueKind.Object
                    && doc.RootElement.TryGetProperty("cookies", out var cookiesProp))
                {
                    return cookiesProp.ValueKind == JsonValueKind.String
                        ? cookiesProp.GetString()
                        : null;
                }

                // Structured JSON without a cookies field — not a document.cookie probe result.
                return null;
            }
            catch
            {
                return null;
            }
        }

        return trimmed;
    }

    private static List<string> ParseCookieNames(string cookieLine)
    {
        var names = new List<string>();
        foreach (var part in cookieLine.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            var name = eq >= 0 ? part[..eq].Trim() : part.Trim();
            if (!string.IsNullOrEmpty(name))
                names.Add(name);
        }
        return names;
    }

    private static bool IsAuthRelevantCookieName(string name) =>
        AuthCookieNamePattern.IsMatch(name);

    private static bool CookieLineHasAuthTokenValue(string cookieLine)
    {
        foreach (var part in cookieLine.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var value = part[(eq + 1)..].Trim();
            if (JwtValuePattern.IsMatch(value))
                return true;
        }
        return false;
    }

    private static async Task<string?> SafeGetCurrentUrl(AutomationContext ctx)
    {
        try
        {
            return await ctx.GetCurrentUrl();
        }
        catch
        {
            return null;
        }
    }

    private static string BuildStableId(string prefix, string endpoint)
    {
        var key = string.IsNullOrWhiteSpace(endpoint) ? "page" : endpoint;
        return $"{prefix}-{Math.Abs(StringComparer.OrdinalIgnoreCase.GetHashCode(key)):X8}";
    }

    private static string TruncateEvidence(string value) =>
        value.Length <= 240 ? value : value[..240] + "...";
}
