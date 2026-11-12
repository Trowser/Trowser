using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Path-filter bypass probes (NUL byte, double-encoding) for static file ACL bugs.
/// </summary>
public static partial class PathFilterBypassChecker
{
    public sealed class BypassOptions
    {
        public string? BasePath { get; set; }
        public IReadOnlyList<string>? PathBases { get; set; }
        /// <summary>Alias for <see cref="PathBases"/>.</summary>
        public IReadOnlyList<string>? Bases { get; set; }
        public int TimeoutMs { get; set; } = 15000;
        public int MaxBases { get; set; } = 8;
    }

    public sealed class BypassFinding
    {
        public string BaselineUrl { get; init; } = "";
        public string BypassUrl { get; init; } = "";
        public string Payload { get; init; } = "";
        public int BaselineStatus { get; init; }
        public int BypassStatus { get; init; }
        public string Indicator { get; init; } = "";
        public string? Snippet { get; init; }
    }

    public sealed class BypassResult
    {
        public List<BypassFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public List<string> BasesUsed { get; init; } = [];
        public int BasesProbed { get; init; }
    }

    public static readonly (string Label, string Suffix)[] DefaultBypassPayloads =
    [
        ("nul-percent-encoded", "%2500.md"),
        ("nul-raw", "%00"),
        ("double-dot-encoded", "%2e%2e%2f"),
        ("semicolon-trick", "..;/"),
        ("semicolon-trick-alt", ";/"),
        ("backslash-normalize", "..\\"),
        ("encoded-dot-dot", "%2e%2e/"),
        ("double-encoded-slash", "%252f"),
    ];

    private static readonly string[] DefaultBases =
    [
        "/admin/", "/api/", "/internal/", "/debug/", "/console/",
        "/ftp/", "/files/", "/static/", "/uploads/"
    ];

    public static async Task<BypassResult> RunAsync(
        AutomationContext ctx,
        BypassOptions options,
        CancellationToken ct = default)
    {
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running path-filter bypass tests.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var bases = ResolveBases(options, currentUri).Take(options.MaxBases).ToList();
        var findings = new List<BypassFinding>();
        var summary = new List<string>();

        var rootUrl = origin + "/";
        SecurityProbeHttp.FetchResult root;
        try
        {
            root = await SecurityProbeHttp.FetchAsync(ctx, rootUrl, "GET", null, null, options.TimeoutMs, includeBrowserCookies: true, ct);
        }
        catch (Exception ex)
        {
            return new BypassResult
            {
                Summary = [$"Failed to fetch site root: {ex.Message}"],
                BasesUsed = bases,
                BasesProbed = bases.Count
            };
        }

        foreach (var rawBase in bases)
        {
            ct.ThrowIfCancellationRequested();
            var basePath = NormalizePath(rawBase);
            var baselineUrl = origin + basePath.TrimEnd('/') + "/";

            SecurityProbeHttp.FetchResult baseline;
            try
            {
                baseline = await SecurityProbeHttp.FetchAsync(ctx, baselineUrl, "GET", null, null, options.TimeoutMs, includeBrowserCookies: true, ct);
            }
            catch
            {
                continue;
            }

            foreach (var (label, suffix) in DefaultBypassPayloads)
            {
                ct.ThrowIfCancellationRequested();
                var bypassUrl = origin + basePath.TrimEnd('/') + "/" + suffix.TrimStart('/');

                SecurityProbeHttp.FetchResult bypass;
                try
                {
                    bypass = await SecurityProbeHttp.FetchAsync(ctx, bypassUrl, "GET", null, null, options.TimeoutMs, includeBrowserCookies: true, ct);
                }
                catch
                {
                    continue;
                }

                if (bypass.Status is not (>= 200 and < 300))
                    continue;

                if (IsEquivalentToSiteRoot(bypass, root, rootUrl, origin))
                    continue;

                if (TraversesToSiteRoot(basePath, suffix, label, origin, bypass))
                    continue;

                if (baseline.Status is >= 200 and < 300 && string.Equals(baseline.Body, bypass.Body, StringComparison.Ordinal))
                    continue;

                var indicator = DetectBypassIndicator(bypass.Body, baseline.Body);
                if (indicator == null)
                    continue;

                findings.Add(new BypassFinding
                {
                    BaselineUrl = baselineUrl,
                    BypassUrl = bypassUrl,
                    Payload = label,
                    BaselineStatus = baseline.Status,
                    BypassStatus = bypass.Status,
                    Indicator = indicator,
                    Snippet = Snip(bypass.Body, 240)
                });
            }
        }

        if (findings.Count > 0)
            summary.Add($"{findings.Count} path-filter bypass candidate(s) — content differs from site root and baseline.");
        else
            summary.Add("No path-filter bypass indicators detected on selected bases.");

        return new BypassResult
        {
            Findings = findings,
            Summary = summary,
            BasesUsed = bases,
            BasesProbed = bases.Count
        };
    }

    private static List<string> ResolveBases(BypassOptions options, Uri currentUri)
    {
        var custom = options.Bases ?? options.PathBases;
        if (custom is { Count: > 0 })
            return custom.Where(s => !string.IsNullOrWhiteSpace(s)).Select(NormalizePath).ToList();
        if (!string.IsNullOrWhiteSpace(options.BasePath))
            return [NormalizePath(options.BasePath)];
        return DefaultBases.ToList();
    }

    private static string NormalizePath(string s)
    {
        s = s.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var abs))
            return abs.AbsolutePath;
        return s.StartsWith('/') ? s : "/" + s;
    }

    private static string? DetectBypassIndicator(string bypassBody, string baselineBody)
    {
        if (string.IsNullOrWhiteSpace(bypassBody)) return null;
        var lower = bypassBody.ToLowerInvariant();
        if (lower.Contains("root:") && lower.Contains("/bin/")) return "etc-passwd-pattern";
        if (lower.Contains("[extensions]") || lower.Contains("for 16-bit app support")) return "win.ini-pattern";
        if (lower.Contains("package.json") || lower.Contains("\"dependencies\"")) return "manifest-leak";
        if (LooksLikeDirectoryListing(bypassBody))
            return "directory-listing";
        if (bypassBody.Length > 120 && !string.Equals(bypassBody, baselineBody, StringComparison.Ordinal))
            return "content-differential";
        return null;
    }

    private static bool LooksLikeDirectoryListing(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var lower = body.ToLowerInvariant();
        if (lower.Contains("index of /") || lower.Contains("parent directory")) return true;
        if (lower.Contains("<pre>") && lower.Contains("<a href=") && (lower.Contains("bytes") || lower.Contains("last modified")))
            return true;
        return false;
    }

    private static bool IsEquivalentToSiteRoot(
        SecurityProbeHttp.FetchResult bypass,
        SecurityProbeHttp.FetchResult root,
        string rootUrl,
        string origin)
    {
        if (string.Equals(bypass.Body, root.Body, StringComparison.Ordinal))
            return true;

        if (ShortHash(bypass.Body) == ShortHash(root.Body))
            return true;

        if (FinalUrlIsSiteRoot(bypass.FinalUrl, rootUrl, origin))
        {
            var bypassTitle = ExtractHtmlTitle(bypass.Body);
            var rootTitle = ExtractHtmlTitle(root.Body);
            if (!string.IsNullOrEmpty(bypassTitle) && bypassTitle == rootTitle)
                return true;
        }

        var titleBypass = ExtractHtmlTitle(bypass.Body);
        var titleRoot = ExtractHtmlTitle(root.Body);
        if (!string.IsNullOrEmpty(titleBypass) && titleBypass == titleRoot)
        {
            var lenBypass = bypass.Body?.Length ?? 0;
            var lenRoot = root.Body?.Length ?? 0;
            if (lenRoot > 0 && Math.Abs(lenBypass - lenRoot) <= Math.Max(128, lenRoot / 20))
                return true;
        }

        if (ContentFingerprint(bypass.Body) == ContentFingerprint(root.Body))
            return true;

        return false;
    }

    private static bool TraversesToSiteRoot(
        string basePath,
        string suffix,
        string label,
        string origin,
        SecurityProbeHttp.FetchResult bypass)
    {
        if (!IsParentTraversalPayload(label, suffix))
            return false;

        var resolved = NormalizeTraversalPath(basePath, suffix);
        if (resolved is "/" or "")
            return true;

        if (FinalUrlIsSiteRoot(bypass.FinalUrl, origin + "/", origin))
            return true;

        return resolved != null && FinalUrlPathMatches(bypass.FinalUrl, resolved);
    }

    private static bool IsParentTraversalPayload(string label, string suffix)
    {
        var s = suffix.ToLowerInvariant();
        var l = label.ToLowerInvariant();
        return l.Contains("dot-dot", StringComparison.Ordinal)
            || l.Contains("backslash", StringComparison.Ordinal)
            || s.Contains("..", StringComparison.Ordinal)
            || s.Contains("%2e%2e", StringComparison.Ordinal);
    }

    private static string? NormalizeTraversalPath(string basePath, string suffix)
    {
        var combined = basePath.TrimEnd('/') + "/" + suffix.TrimStart('/');
        try
        {
            combined = Uri.UnescapeDataString(combined);
        }
        catch
        {
            // keep raw combined path
        }

        combined = combined.Replace('\\', '/');
        var segments = combined.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var stack = new List<string>();
        foreach (var seg in segments)
        {
            if (seg == "..")
            {
                if (stack.Count > 0) stack.RemoveAt(stack.Count - 1);
            }
            else if (seg != ".")
            {
                stack.Add(seg);
            }
        }

        return stack.Count == 0 ? "/" : "/" + string.Join('/', stack);
    }

    private static bool FinalUrlIsSiteRoot(string? finalUrl, string rootUrl, string origin)
    {
        if (string.IsNullOrWhiteSpace(finalUrl)) return false;
        if (!Uri.TryCreate(finalUrl, UriKind.Absolute, out var uri)) return false;
        if (!Uri.TryCreate(rootUrl, UriKind.Absolute, out var rootUri)) return false;
        if (!uri.GetLeftPart(UriPartial.Authority).Equals(origin, StringComparison.OrdinalIgnoreCase))
            return false;

        var path = uri.AbsolutePath.TrimEnd('/');
        var rootPath = rootUri.AbsolutePath.TrimEnd('/');
        return path.Length == 0 || path == rootPath;
    }

    private static bool FinalUrlPathMatches(string? finalUrl, string expectedPath)
    {
        if (string.IsNullOrWhiteSpace(finalUrl) || !Uri.TryCreate(finalUrl, UriKind.Absolute, out var uri))
            return false;
        var actual = uri.AbsolutePath.TrimEnd('/');
        var expected = expectedPath.TrimEnd('/');
        if (expected.Length == 0) expected = "";
        if (actual.Length == 0) actual = "";
        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string? ExtractHtmlTitle(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        var lower = body.ToLowerInvariant();
        var start = lower.IndexOf("<title", StringComparison.Ordinal);
        if (start < 0) return null;
        start = lower.IndexOf('>', start);
        if (start < 0) return null;
        start++;
        var end = lower.IndexOf("</title", start, StringComparison.Ordinal);
        if (end < 0) return null;
        return System.Net.WebUtility.HtmlDecode(body[start..end].Trim());
    }

    private static string ContentFingerprint(string? body)
    {
        if (string.IsNullOrEmpty(body)) return "";
        var collapsed = RegexCollapseWhitespace().Replace(body, " ").Trim().ToLowerInvariant();
        if (collapsed.Length > 8192) collapsed = collapsed[..8192];
        return ShortHash(collapsed);
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex RegexCollapseWhitespace();

    private static string ShortHash(string body)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(body ?? ""));
        return Convert.ToHexString(bytes)[..12];
    }

    private static string? Snip(string? s, int n) =>
        string.IsNullOrEmpty(s) ? s : s.Length <= n ? s : s[..n] + "…";
}
