using System.Security.Cryptography;
using System.Text;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Detects when mutating-probe responses are generic SPA shell HTML rather than API data.
/// </summary>
public static class SpaShellGuard
{
    private static readonly string[] ScannerProbeNeedles =
    [
        "trowser-xss-baseline", "trowser-ssti-baseline", "trowser-bfla-canary",
        "trowser_sqli", "trowser-xss", "__trowser_spa_probe__"
    ];
    public sealed class ShellFingerprint
    {
        public string BodyHash { get; init; } = "";
        public int BodyLength { get; init; }
        public bool IsHtmlShell { get; init; }
    }

    public static async Task<ShellFingerprint?> CaptureOriginShellAsync(
        AutomationContext ctx, string origin, int timeoutMs = 12000)
    {
        try
        {
            var json = await ctx.Fetch(origin.TrimEnd('/') + "/", "GET", null, null, timeoutMs);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var status = doc.RootElement.GetProperty("status").GetInt32();
            var body = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            if (status is not (200 or 304) || string.IsNullOrWhiteSpace(body))
                return null;

            return new ShellFingerprint
            {
                BodyHash = Hash(body),
                BodyLength = body.Length,
                IsHtmlShell = IsSpaHtmlShell(body)
            };
        }
        catch
        {
            return null;
        }
    }

    public static bool IsApiLikeResponse(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        if (t.StartsWith('{') || t.StartsWith('[')) return true;
        if (t.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public static bool IsSpaHtmlShell(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        if (!t.StartsWith('<')) return false;
        if (IsApiLikeResponse(body)) return false;
        return t.Contains("<app-root", StringComparison.OrdinalIgnoreCase)
               || t.Contains("<div id=\"root\"", StringComparison.OrdinalIgnoreCase)
               || t.Contains("<div id='root'", StringComparison.OrdinalIgnoreCase)
               || t.Contains("ng-version", StringComparison.OrdinalIgnoreCase)
               || t.Contains("__NEXT_DATA__", StringComparison.OrdinalIgnoreCase)
               || t.Contains("<!doctype html", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeSpaShellDuplicate(
        string body, int status, ShellFingerprint? shell, bool requireOriginHashMatch = false)
    {
        if (status is not (200 or 201 or 204 or 304)) return false;
        if (IsApiLikeResponse(body)) return false;
        if (!requireOriginHashMatch && IsSpaHtmlShell(body)) return true;

        if (shell == null || !shell.IsHtmlShell) return false;
        if (Math.Abs(body.Length - shell.BodyLength) > Math.Max(200, shell.BodyLength / 10))
            return false;

        return string.Equals(Hash(body), shell.BodyHash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True when a security probe URL is an internal scanner artifact (canary payloads, SPA probes).
    /// </summary>
    public static bool IsScannerProbeArtifact(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        return ScannerProbeNeedles.Any(n => url.Contains(n, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Dominant 2xx body hash from attack-surface response patterns (lowercase hex prefix).
    /// </summary>
    public static string? GetDominantSuccessBodyHash(AttackSurfaceEndpoint? ep)
    {
        if (ep == null) return null;
        foreach (var (code, pattern) in ep.ResponsePatterns)
        {
            if (int.TryParse(code, out var status) && status is >= 200 and < 300
                && !string.IsNullOrEmpty(pattern.BodyHash))
                return pattern.BodyHash;
        }

        return null;
    }

    public static AttackSurfaceEndpoint? FindDocumentRootEndpoint(IEnumerable<AttackSurfaceEndpoint> endpoints)
    {
        return endpoints.FirstOrDefault(ep =>
                   ep.UrlTemplate is "/" or "")
               ?? endpoints.FirstOrDefault(ep =>
                   Uri.TryCreate(ep.Url, UriKind.Absolute, out var u)
                   && (u.AbsolutePath is "/" or "" || string.IsNullOrEmpty(u.AbsolutePath)));
    }

    /// <summary>
    /// True when endpoint traffic looks like the same HTML SPA shell as the document root — not a real API.
    /// Never suppresses when response patterns indicate JSON/XML API payloads.
    /// </summary>
    public static bool IsAttackSurfaceSpaFallback(AttackSurfaceEndpoint ep, AttackSurfaceEndpoint? documentRoot)
    {
        if (EndpointResponsesLookApiLike(ep))
            return false;

        var docHash = GetDominantSuccessBodyHash(documentRoot);
        var epHash = GetDominantSuccessBodyHash(ep);
        if (docHash != null && epHash != null
            && string.Equals(docHash, epHash, StringComparison.OrdinalIgnoreCase))
            return true;

        return ep.ResponsePatterns.Values.All(p =>
            p.Description.Contains("HTML", StringComparison.OrdinalIgnoreCase))
               && ep.ResponsePatterns.Values.Any(p => p.BodyLength > 500);
    }

    public static bool EndpointResponsesLookApiLike(AttackSurfaceEndpoint ep) =>
        ep.ResponsePatterns.Values.Any(p =>
            p.Description.Contains("JSON", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("XML", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("GraphQL", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True when every successful IDOR probe row is the SPA shell (or duplicate of origin shell).
    /// </summary>
    public static bool AllIdorRowsAreSpaShell(IEnumerable<HttpSecurityProbes.IdorRow> rows, ShellFingerprint? shell)
    {
        var okRows = rows.Where(r => r.Status is >= 200 and < 300).ToList();
        if (okRows.Count == 0) return false;

        foreach (var row in okRows)
        {
            var body = row.BodySample ?? "";
            if (string.IsNullOrWhiteSpace(body))
                return false;
            if (IsApiLikeResponse(body))
                return false;
            if (!LooksLikeSpaShellDuplicate(body, row.Status, shell) && !IsSpaHtmlShell(body))
                return false;
        }

        return true;
    }

    private static string Hash(string body)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(body));
        return Convert.ToHexString(bytes)[..16];
    }
}
