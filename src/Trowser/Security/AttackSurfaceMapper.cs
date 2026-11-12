using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// A single endpoint discovered from network traffic, with aggregated method/parameter/auth/response data.
/// </summary>
public class AttackSurfaceEndpoint
{
    public string Url { get; set; } = "";
    public string UrlTemplate { get; set; } = "";
    public HashSet<string> Methods { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public AttackSurfaceParameters Parameters { get; set; } = new();
    public AttackSurfaceAuth Auth { get; set; } = new();
    public Dictionary<string, AttackSurfaceResponsePattern> ResponsePatterns { get; set; } = new();
    public HashSet<string> DiscoveredVia { get; set; } = new();
    public string TestPriority { get; set; } = "medium";
    public int RequestCount { get; set; }
}

public class AttackSurfaceParameters
{
    public List<string> Query { get; set; } = new();
    public List<string> Body { get; set; } = new();
    public List<string> Headers { get; set; } = new();
    public List<string> Path { get; set; } = new();

    /// <summary>Content-Type of the request body (e.g. application/json, application/xml).</summary>
    public string? RequestContentType { get; set; }

    /// <summary>A sample request body from captured traffic (first non-empty body seen, capped at 2KB).</summary>
    public string? RequestBodySample { get; set; }
}

public class AttackSurfaceAuth
{
    public bool Required { get; set; }
    public string Type { get; set; } = "none";
}

public class AttackSurfaceResponsePattern
{
    public string Description { get; set; } = "";
    public string? BodySnippet { get; set; }
    public string? BodyHash { get; set; }
    public int? BodyLength { get; set; }
    public int Count { get; set; } = 1;
}

/// <summary>DOM/runtime view of the attack surface (inputs, links, form count) from the same
/// interactive scan as <c>GET /api/state</c> — for SPAs where network APIs matter but static HTML is an empty shell.</summary>
public sealed class SpaRuntimeSurface
{
    public int HtmlFormCount { get; set; }
    public int InputFieldCount { get; set; }
    public int LinkCount { get; set; }
    public int ButtonCount { get; set; }
    public int OtherInteractiveCount { get; set; }
    public int TotalInteractiveElements { get; set; }
    public string? PageUrl { get; set; }
    public string? PageTitle { get; set; }
    public List<SpaFieldSummary> InputFields { get; set; } = new();
    public List<SpaFieldSummary> Links { get; set; } = new();
    public IReadOnlyList<string> Warnings { get; set; } = Array.Empty<string>();
}

public sealed class SpaFieldSummary
{
    public int? Ref { get; set; }
    public string? Tag { get; set; }
    public string? Type { get; set; }
    public string? Name { get; set; }
    public string? Id { get; set; }
    public string? Label { get; set; }
    public string? Placeholder { get; set; }
    public string? Href { get; set; }
    public string? Text { get; set; }
    public string? Selector { get; set; }
}

public sealed class AttackSurfaceEnrichmentReport
{
    public bool Enabled { get; set; }

    /// <summary>Response bodies inspected with OpenAPI/Swagger heuristics (passive).</summary>
    public int NetworkLogSpecBodiesExamined { get; set; }

    /// <summary>Captured JSON/YAML/OpenAPI payloads from browsing (passive).</summary>
    public int OpenApiSpecsFromNetworkLog { get; set; }

    /// <summary>GET probes to well-known spec paths (active, same origins as page + API traffic).</summary>
    public int OpenApiProbesAttempted { get; set; }

    /// <summary>GET probes for exposed development/config files (.env, package.json, .git, Docker, etc.).</summary>
    public int DevArtifactProbesAttempted { get; set; }

    /// <summary>Paths that returned a non-404 status (may include 401/403 or redirects).</summary>
    public int DevArtifactHits { get; set; }

    public int OpenApiSpecsParsed { get; set; }
    public List<string> OpenApiSpecSources { get; set; } = new();
    public List<string> OpenApiErrors { get; set; } = new();

    public int JsScriptsFetched { get; set; }
    public int JsHintUrlsExtracted { get; set; }
    public List<string> JsErrors { get; set; } = new();

    public int EndpointsAddedBeforeMerge { get; set; }

    /// <summary>WordPress REST index documents parsed (from traffic or probes) into synthetic endpoints.</summary>
    public int WordPressRestIndexesParsed { get; set; }
}

public class AttackSurfaceResult
{
    public List<AttackSurfaceEndpoint> Endpoints { get; set; } = new();
    public AttackSurfaceSummary Summary { get; set; } = new();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Source { get; set; } = "network-log";
    public SpaRuntimeSurface? SpaRuntime { get; set; }
    public bool NetworkLogEmpty { get; set; }

    /// <summary>Optional OpenAPI + JS bundle hints merged into <see cref="Endpoints"/> — see <see cref="Enrichment"/>.</summary>
    public AttackSurfaceEnrichmentReport? Enrichment { get; set; }

    /// <summary>RFC 9116 <c>security.txt</c> probe for the navigated tab host (optional; API / <c>PrintAttackSurfaceReport</c>).</summary>
    public List<SecurityTxtHostResult> SecurityTxt { get; set; } = new();

    public string Format(bool includeDetails = true)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Attack Surface Map ===");
        AppendSecurityTxtSection(sb, includeDetails);
        sb.AppendLine($"Source: {Source}");
        if (Enrichment is { Enabled: true } er)
        {
            sb.AppendLine(
                $"API enrichment: passive bodies inspected={er.NetworkLogSpecBodiesExamined}  " +
                $"network-log specs={er.OpenApiSpecsFromNetworkLog}  probes={er.OpenApiProbesAttempted}  parsed={er.OpenApiSpecsParsed}  " +
                $"WordPress REST indexes={er.WordPressRestIndexesParsed}  " +
                $"dev-artifact probes={er.DevArtifactProbesAttempted}  dev-artifact hits={er.DevArtifactHits}  " +
                $"JS scripts={er.JsScriptsFetched}  JS URL hints={er.JsHintUrlsExtracted}");
            if (er.OpenApiSpecSources.Count > 0)
                sb.AppendLine($"  Spec sources: {string.Join("; ", er.OpenApiSpecSources.Take(12))}");
        }

        if (NetworkLogEmpty)
            sb.AppendLine("Note: network log was empty — API endpoints are from browsing once traffic is captured, or use spaMode to map the live DOM.");
        sb.AppendLine($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Total endpoints: {Summary.TotalEndpoints}");
        sb.AppendLine($"Authenticated: {Summary.Authenticated}");
        sb.AppendLine($"Unauthenticated: {Summary.Unauthenticated}");
        sb.AppendLine($"Methods: {string.Join(", ", Summary.MethodDistribution.Select(kv => $"{kv.Key}: {kv.Value}"))}");
        sb.AppendLine($"Priority: high={Summary.HighPriority}, medium={Summary.MediumPriority}, low={Summary.LowPriority}");

        if (includeDetails && Endpoints.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(new string('─', 80));

            foreach (var ep in Endpoints.OrderByDescending(e => PriorityRank(e.TestPriority)))
            {
                sb.AppendLine();
                sb.AppendLine($"[{ep.TestPriority.ToUpper()}] {AttackSurfaceMapper.FormatDisplayUrl(ep)}");
                sb.AppendLine($"  Methods: {string.Join(", ", ep.Methods)}");
                sb.AppendLine($"  Requests seen: {ep.RequestCount}");
                if (ep.DiscoveredVia.Count > 0)
                    sb.AppendLine($"  Via: {string.Join(", ", ep.DiscoveredVia.OrderBy(v => v, StringComparer.OrdinalIgnoreCase))}");

                if (ep.Parameters.Query.Count > 0)
                    sb.AppendLine($"  Query params: {string.Join(", ", ep.Parameters.Query)}");
                if (ep.Parameters.Body.Count > 0)
                    sb.AppendLine($"  Body params: {string.Join(", ", ep.Parameters.Body)}");
                if (!string.IsNullOrEmpty(ep.Parameters.RequestContentType))
                    sb.AppendLine($"  Content-Type: {ep.Parameters.RequestContentType}");
                if (!string.IsNullOrEmpty(ep.Parameters.RequestBodySample))
                {
                    var sample = ep.Parameters.RequestBodySample.Length > 200
                        ? ep.Parameters.RequestBodySample[..200] + "..."
                        : ep.Parameters.RequestBodySample;
                    sb.AppendLine($"  Body sample: {sample}");
                }
                if (ep.Parameters.Headers.Count > 0)
                    sb.AppendLine($"  Notable headers: {string.Join(", ", ep.Parameters.Headers)}");
                if (ep.Parameters.Path.Count > 0)
                    sb.AppendLine($"  Path params: {string.Join(", ", ep.Parameters.Path)}");

                sb.AppendLine($"  Auth: {(ep.Auth.Required ? ep.Auth.Type : "none")}");

                if (ep.ResponsePatterns.Count > 0)
                {
                    sb.AppendLine("  Responses:");
                    foreach (var (status, rp) in ep.ResponsePatterns)
                    {
                        var countSuffix = rp.Count > 1 ? $" ({rp.Count}×)" : "";
                        var lengthSuffix = rp.BodyLength.HasValue ? $" [{rp.BodyLength}B]" : "";
                        sb.AppendLine($"    {status}: {rp.Description}{countSuffix}{lengthSuffix}");
                        if (!string.IsNullOrEmpty(rp.BodySnippet))
                            sb.AppendLine($"      snippet: {rp.BodySnippet}");
                    }
                }
            }
        }

        if (includeDetails && SpaRuntime is { } spa)
        {
            sb.AppendLine();
            sb.AppendLine(new string('─', 80));
            sb.AppendLine("=== SPA / runtime (interactiveElements) ===");
            sb.AppendLine($"Page: {spa.PageTitle ?? "?"}  {spa.PageUrl ?? ""}");
            sb.AppendLine(
                $"<form> in DOM: {spa.HtmlFormCount}  " +
                $"input fields: {spa.InputFieldCount}  links: {spa.LinkCount}  buttons: {spa.ButtonCount}  other: {spa.OtherInteractiveCount}  total elements: {spa.TotalInteractiveElements}");
            foreach (var w in spa.Warnings)
                sb.AppendLine($"  ! {w}");
            if (spa.InputFields.Count > 0)
            {
                sb.AppendLine("Input fields (sample, first 20):");
                foreach (var f in spa.InputFields.Take(20))
                {
                    sb.AppendLine(
                        $"  [ref {f.Ref}] <{f.Tag}> type={f.Type} name={f.Name} id={f.Id} label={f.Label}");
                }
            }

            if (spa.Links.Count > 0)
            {
                sb.AppendLine("Links (sample, first 15):");
                foreach (var l in spa.Links.Take(15))
                    sb.AppendLine($"  {l.Href}  text={l.Text}");
            }
        }

        return sb.ToString().TrimEnd();
    }

    private void AppendSecurityTxtSection(StringBuilder sb, bool includeDetails)
    {
        if (SecurityTxt.Count == 0)
            return;

        sb.AppendLine("--- RFC 9116 security.txt (current tab host) ---");
        var total = SecurityTxt.Count;
        var ok = SecurityTxt.Count(r => r.Found);
        if (total == 1)
        {
            sb.AppendLine(
                ok == 1
                    ? "This host publishes machine-readable security.txt — read Contact/Policy before active testing."
                    : "No valid security.txt for this host — exercise extra caution; prefer responsible disclosure.");
        }
        else if (ok == total)
        {
            sb.AppendLine(
                $"All {total} host(s) publish a machine-readable security.txt — read Contact/Policy before active testing.");
        }
        else if (ok > 0)
        {
            sb.AppendLine(
                $"{ok}/{total} host(s) publish security.txt; the rest did not yield a valid file at /.well-known/ or / — coordinate disclosure carefully.");
        }
        else
        {
            sb.AppendLine(
                $"No valid security.txt found for {total} probed host(s) — exercise extra caution; prefer responsible disclosure and avoid unsolicited intrusive testing.");
        }

        foreach (var row in SecurityTxt.OrderBy(r => r.Host, StringComparer.OrdinalIgnoreCase))
        {
            if (row.Found)
            {
                sb.AppendLine(
                    $"  {row.Host}: {row.Url}  (via {row.PathKind})");
            }
            else
            {
                var detail = includeDetails && !string.IsNullOrEmpty(row.Error)
                    ? row.Error
                    : "not found or not RFC 9116-shaped (see API securityTxt[] for detail)";
                sb.AppendLine($"  {row.Host}: {detail}");
            }
        }

        sb.AppendLine();
    }

    private static int PriorityRank(string priority) => priority switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };
}

public class AttackSurfaceSummary
{
    public int TotalEndpoints { get; set; }
    public int Authenticated { get; set; }
    public int Unauthenticated { get; set; }
    public int HighPriority { get; set; }
    public int MediumPriority { get; set; }
    public int LowPriority { get; set; }
    public Dictionary<string, int> MethodDistribution { get; set; } = new();
    public List<string> Hosts { get; set; } = new();
}

/// <summary>
/// Analyzes captured network traffic to auto-generate an attack surface map:
/// discovered endpoints, methods, parameters, authentication requirements, and response patterns.
/// </summary>
public class AttackSurfaceMapper
{
    private static readonly Regex OpenApiPathBraceParam = new(@"\{[^/}]+\}", RegexOptions.Compiled);

    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".eot", ".map", ".webp", ".avif", ".mp4", ".webm", ".mp3", ".ogg"
    };

    private static readonly HashSet<string> AuthCookiePatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "session", "sess", "sid", "token", "auth", "jwt", "access_token", "id_token",
        "jsessionid", ".aspxauth", ".aspnetcore", "connect.sid"
    };

    private static readonly HashSet<string> NotableRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization", "x-csrf-token", "x-xsrf-token", "x-requested-with",
        "x-api-key", "x-forwarded-for", "x-real-ip"
    };

    /// <summary>
    /// Browser/transport headers that are not useful injection sinks — everything else observed
    /// in traffic (especially custom <c>X-*</c> app headers) is inventoried for auto-scan probes.
    /// </summary>
    private static readonly HashSet<string> IgnoredInjectableRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "host", "connection", "content-length", "content-type", "accept", "accept-encoding",
        "accept-language", "accept-charset", "user-agent", "cookie", "origin", "referer",
        "referrer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version-list",
        "cache-control", "pragma", "upgrade-insecure-requests", "dnt", "te", "priority",
        "if-none-match", "if-modified-since", "range", "authorization",
        // Auth material — probed by authz playbooks, not injection engines.
        "proxy-authorization", "cookie2"
    };

    /// <summary>Path segments that are an email address, raw or <c>%40</c>-encoded, become <c>{email}</c>.</summary>
    private static readonly Regex EmailSegmentPattern = new(
        @"(?<=/)([A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?=/|$|\?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static string ReplaceIdentityPathSegments(string path)
    {
        path = EmailSegmentPattern.Replace(path, "{email}");
        path = GuidPattern.Replace(path, "{id}");
        // 24-hex Mongo ids are object ids, not credentials. {token} made agents think a secret was redacted.
        path = HexTokenPattern.Replace(path, "{id}");
        path = NumericIdPattern.Replace(path, "{id}");
        return path;
    }

    private static readonly Regex GuidPattern = new(
        @"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex NumericIdPattern = new(
        @"(?<=/)(\d+)(?=/|$|\?)",
        RegexOptions.Compiled);

    private static readonly Regex HexTokenPattern = new(
        @"(?<=/)([0-9a-f]{16,})(?=/|$|\?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Base64SegmentPattern = new(
        @"(?<=/)([A-Za-z0-9_-]{20,}={0,2})(?=/|$|\?)",
        RegexOptions.Compiled);

    /// <summary>Dedupe key aligning OpenAPI templates with observed traffic (e.g. /users/{userId} vs /users/1).</summary>
    public static string EndpointMergeKeyFromUrl(string absoluteUrl)
    {
        if (Uri.TryCreate(absoluteUrl, UriKind.Absolute, out var uri))
        {
            var path = uri.AbsolutePath.TrimEnd('/');
            if (string.IsNullOrEmpty(path)) path = "/";
            path = OpenApiPathBraceParam.Replace(path, "{param}");
            path = ReplaceIdentityPathSegments(path);
            return $"{uri.Host}|{path}";
        }

        var schemeIdx = absoluteUrl.IndexOf("://", StringComparison.Ordinal);
        if (schemeIdx <= 0)
            return absoluteUrl.ToLowerInvariant();

        var afterScheme = absoluteUrl[(schemeIdx + 3)..];
        var slashIdx = afterScheme.IndexOf('/');
        if (slashIdx < 0)
            return $"{afterScheme.ToLowerInvariant()}|/";

        var host = afterScheme[..slashIdx];
        var rawPath = afterScheme[slashIdx..].Split('?', 2)[0].TrimEnd('/');
        var pathFrag = string.IsNullOrEmpty(rawPath) ? "/" : rawPath;
        pathFrag = OpenApiPathBraceParam.Replace(pathFrag, "{param}");
        pathFrag = ReplaceIdentityPathSegments(pathFrag);
        return $"{host.ToLowerInvariant()}|{pathFrag}";
    }

    /// <summary>Refresh summary totals after enrichment merged new endpoints.</summary>
    public void AttachRefreshedSummary(AttackSurfaceResult result, List<NetworkEntry> allEntries)
    {
        var filteredApi = allEntries
            .Where(e => !IsStaticResource(e))
            .Where(e => !IsDataUrl(e.Url))
            .Where(e => e.StatusCode > 0)
            .ToList();
        result.Summary = BuildSummary(result.Endpoints, filteredApi, allEntries);
    }

    /// <summary>Heuristic priority for endpoints with no captured traffic (OpenAPI / JS hints).</summary>
    public static string EstimatePriorityWithoutTraffic(AttackSurfaceEndpoint ep)
    {
        var score = 0;
        if (ep.Methods.Any(m => m is "POST" or "PUT" or "PATCH" or "DELETE"))
            score += 3;
        if (ep.Parameters.Body.Count > 0)
            score += 2;
        var pathLower = ep.UrlTemplate.ToLowerInvariant();
        if (pathLower.Contains("login") || pathLower.Contains("auth") ||
            pathLower.Contains("token") || pathLower.Contains("session") ||
            pathLower.Contains("password") || pathLower.Contains("register") ||
            pathLower.Contains("signup") || pathLower.Contains("saml") ||
            pathLower.Contains("oauth") || pathLower.Contains("sso"))
            score += 3;
        if (pathLower.Contains("admin") || pathLower.Contains("config") ||
            pathLower.Contains("settings") || pathLower.Contains("manage"))
            score += 2;
        if (ep.Parameters.Path.Count > 0)
            score += 1;
        return score switch
        {
            >= 7 => "critical",
            >= 5 => "high",
            >= 3 => "medium",
            _ => "low"
        };
    }

    public AttackSurfaceResult Analyze(
        List<NetworkEntry> entries,
        bool includeParameters = true,
        bool includeAuth = true,
        bool includeResponsePatterns = true,
        string? hostFilter = null,
        bool includeDataUrls = false)
    {
        var apiEntries = entries
            .Where(e => !ScannerTrafficExclusion.ShouldExcludeFromAttackSurface(e))
            .Where(e => !IsStaticResource(e))
            .Where(e => includeDataUrls || !IsDataUrl(e.Url))
            .Where(e => e.StatusCode > 0)
            .Where(e => SecurityHostScope.MatchesHostFilter(e.Host, hostFilter))
            .ToList();

        var grouped = apiEntries
            .GroupBy(e => NormalizeEndpoint(e.Method, e.Url))
            .OrderBy(g => g.Key)
            .ToList();

        var endpoints = new List<AttackSurfaceEndpoint>();

        foreach (var group in grouped)
        {
            var allEntries = group.ToList();
            // Prefer a representative that still carries query parameters so agents cloning
            // the URL for injection keep sibling fields (Submit, tokens, etc.).
            var representative = allEntries.FirstOrDefault(e =>
                                    Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                                    && !string.IsNullOrEmpty(u.Query))
                                ?? allEntries[0];

            var ep = new AttackSurfaceEndpoint
            {
                Url = representative.Url,
                UrlTemplate = TemplatizePath(representative.Path),
                Methods = new HashSet<string>(allEntries.Select(e => e.Method), StringComparer.OrdinalIgnoreCase),
                RequestCount = allEntries.Count,
                DiscoveredVia = { "network-log" }
            };

            if (includeParameters)
                ep.Parameters = ExtractParameters(allEntries);

            if (includeAuth)
                ep.Auth = DetectAuth(allEntries);

            if (includeResponsePatterns)
                ep.ResponsePatterns = BuildResponsePatterns(allEntries);

            ep.TestPriority = AssessTestPriority(ep, allEntries);

            endpoints.Add(ep);
        }

        var result = new AttackSurfaceResult
        {
            Endpoints = endpoints,
            Source = "network-log"
        };
        result.Summary = BuildSummary(endpoints, apiEntries, entries);

        return result;
    }

    private static bool IsStaticResource(NetworkEntry entry)
    {
        if (string.IsNullOrEmpty(entry.Url)) return true;
        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) return false;

        var path = uri.AbsolutePath;
        var ext = System.IO.Path.GetExtension(path);
        if (!string.IsNullOrEmpty(ext) && StaticExtensions.Contains(ext))
            return true;

        var resourceType = entry.ResourceType;
        if (resourceType is "Image" or "Stylesheet" or "Font" or "Media" or "Script")
        {
            // A bearer-protected API image is an IDOR surface. Decorative images stay out.
            if (resourceType == "Image" &&
                (path.Contains("/api/", StringComparison.OrdinalIgnoreCase) ||
                 entry.RequestHeaders.Keys.Any(k =>
                     k.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                     k.Equals("X-Api-Key", StringComparison.OrdinalIgnoreCase))))
                return false;
            return true;
        }

        return false;
    }

    private static bool IsDataUrl(string url) =>
        url.StartsWith("data:", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Groups requests by normalized endpoint: method-agnostic path with dynamic segments replaced.
    /// </summary>
    private static string NormalizeEndpoint(string method, string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        var path = uri.AbsolutePath.TrimEnd('/');
        if (string.IsNullOrEmpty(path)) path = "/";

        path = ReplaceIdentityPathSegments(path);

        return $"{uri.Host}|{path}";
    }

    public static string TemplatizePath(string pathAndQuery)
    {
        var qIdx = pathAndQuery.IndexOf('?');
        var path = qIdx >= 0 ? pathAndQuery[..qIdx] : pathAndQuery;
        var query = qIdx >= 0 ? pathAndQuery[(qIdx + 1)..] : "";

        path = ReplaceIdentityPathSegments(path);

        // Keep identity query parameters (orderId, user, uuid) and drop the rest, so
        // /order/details?orderId=0254809 and the same path with another id share one template,
        // while /catalog?page=2 stays /catalog.
        if (string.IsNullOrEmpty(query))
            return path;

        var identityParams = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = segment.IndexOf('=');
            var rawName = eq >= 0 ? segment[..eq] : segment;
            if (string.IsNullOrEmpty(rawName)) continue;
            var name = Uri.UnescapeDataString(rawName.Replace('+', ' '));
            if (IsIdentityQueryName(name))
                identityParams.Add(name);
        }

        if (identityParams.Count == 0)
            return path;

        return path + "?" + string.Join("&", identityParams.Select(n => n + "={id}"));
    }

    /// <summary>
    /// Query names that identify a resource or a principal (orderId, user_id, email), as opposed
    /// to presentation parameters (page, sort, locale).
    /// </summary>
    public static bool IsIdentityQueryName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (name.Equals("id", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.EndsWith("_id", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith("-id", StringComparison.OrdinalIgnoreCase))
            return true;
        if (name.Length > 2 && name.EndsWith("Id", StringComparison.Ordinal)) return true;
        if (name.Equals("username", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("email", StringComparison.OrdinalIgnoreCase))
            return true;
        return IdentityQueryNoun.IsMatch(name);
    }

    private static readonly Regex IdentityQueryNoun = new(
        @"(?i)(^|_)(order|user|account|owner|tenant|customer|invoice|basket|cart|uuid|guid|token)($|_)",
        RegexOptions.Compiled);

    /// <summary>
    /// Absolute URL prefix for reporting: scheme + authority + templated path (same path shape as
    /// <see cref="AttackSurfaceEndpoint.UrlTemplate"/>). Use when logs span multiple origins.
    /// </summary>
    public static string FormatDisplayUrl(AttackSurfaceEndpoint ep)
    {
        var templatePath = ep.UrlTemplate ?? "";
        if (string.IsNullOrEmpty(ep.Url))
            return DecodeTemplateBraces(templatePath);

        // UrlTemplate may already be absolute (playbook scope / synthetic endpoints).
        // Never concatenate authority + absolute URL → "https://hosthttps://host/...".
        // Avoid Uri.GetLeftPart for brace templates — it encodes {id} as %7Bid%7D.
        if (LooksAbsoluteUrl(templatePath))
            return DecodeTemplateBraces(SplitAuthorityAndRest(templatePath));

        if (!Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri))
        {
            if (string.IsNullOrEmpty(templatePath))
                return ep.Url;
            return DecodeTemplateBraces(templatePath.StartsWith('/') ? templatePath : "/" + templatePath);
        }

        if (string.IsNullOrEmpty(templatePath))
            templatePath = uri.AbsolutePath;

        // Strip an accidental absolute prefix that slipped into path templates.
        if (LooksAbsoluteUrl(templatePath))
            return DecodeTemplateBraces(SplitAuthorityAndRest(templatePath));

        if (!templatePath.StartsWith('/'))
            templatePath = "/" + templatePath;

        var authority = uri.GetLeftPart(UriPartial.Authority);
        return DecodeTemplateBraces($"{authority.TrimEnd('/')}{templatePath}");
    }

    /// <summary>
    /// <see cref="Uri"/> encodes <c>{</c>/<c>}</c> as <c>%7B</c>/<c>%7D</c>. Findings and
    /// harvest-ids templates must keep brace placeholders for agents and authz/boundary.
    /// </summary>
    public static string DecodeTemplateBraces(string? url)
    {
        if (string.IsNullOrEmpty(url)) return url ?? "";
        return url
            .Replace("%7B", "{", StringComparison.OrdinalIgnoreCase)
            .Replace("%7D", "}", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksAbsoluteUrl(string value) =>
        value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>Keep path/query as raw text so <c>{id}</c> is not percent-encoded.</summary>
    private static string SplitAuthorityAndRest(string absoluteUrl)
    {
        var schemeSep = absoluteUrl.IndexOf("://", StringComparison.Ordinal);
        if (schemeSep < 0) return absoluteUrl;
        var pathStart = absoluteUrl.IndexOf('/', schemeSep + 3);
        if (pathStart < 0) return absoluteUrl;
        return absoluteUrl; // already absolute with path — return as-is (brace-safe)
    }

    private const int MaxBodySampleLength = 2048;

    private static AttackSurfaceParameters ExtractParameters(List<NetworkEntry> entries)
    {
        var queryParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var bodyParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var headerParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pathParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? bodySample = null;
        string? requestContentType = null;

        foreach (var entry in entries)
        {
            // Query parameters
            if (Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri) &&
                !string.IsNullOrEmpty(uri.Query))
            {
                var qs = HttpUtility.ParseQueryString(uri.Query);
                foreach (string? key in qs)
                {
                    if (!string.IsNullOrEmpty(key))
                        queryParams.Add(key);
                }
            }

            // Body parameters (JSON)
            if (!string.IsNullOrEmpty(entry.RequestBody))
            {
                if (bodySample == null)
                {
                    bodySample = entry.RequestBody.Length > MaxBodySampleLength
                        ? entry.RequestBody[..MaxBodySampleLength] + "..."
                        : entry.RequestBody;

                    if (entry.RequestHeaders.TryGetValue("Content-Type", out var ct))
                        requestContentType = ct;
                    else if (entry.RequestHeaders.TryGetValue("content-type", out var ct2))
                        requestContentType = ct2;
                }

                try
                {
                    using var doc = JsonDocument.Parse(entry.RequestBody);
                    if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var prop in doc.RootElement.EnumerateObject())
                            bodyParams.Add(prop.Name);
                    }
                    else if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        // Message-array bodies: [{role,content},…] — report nested field names, never invent "prompt".
                        foreach (var item in doc.RootElement.EnumerateArray())
                        {
                            if (item.ValueKind != JsonValueKind.Object) continue;
                            foreach (var prop in item.EnumerateObject())
                                bodyParams.Add(prop.Name);
                        }
                    }
                }
                catch
                {
                    // URL-encoded body
                    if (entry.RequestBody.Contains('='))
                    {
                        var qs = HttpUtility.ParseQueryString(entry.RequestBody);
                        foreach (string? key in qs)
                        {
                            if (!string.IsNullOrEmpty(key))
                                bodyParams.Add(key);
                        }
                    }
                }
            }
            else if (entry.RequestHeaders.TryGetValue("Content-Type", out var bareCt)
                     || entry.RequestHeaders.TryGetValue("content-type", out bareCt))
            {
                // Capture CT even when body wasn't logged — helps classify text/plain sinks.
                requestContentType ??= bareCt;
            }

            // Request headers from traffic — custom X-* / app headers become injection candidates.
            // Browser/transport/auth headers are ignored (see IgnoredInjectableRequestHeaders).
            foreach (var (key, _) in entry.RequestHeaders)
            {
                if (string.IsNullOrWhiteSpace(key)) continue;
                if (IgnoredInjectableRequestHeaders.Contains(key)) continue;
                headerParams.Add(key);
            }
        }

        // Path parameters from template
        var template = TemplatizePath(entries.First().Path);
        var pathParamMatches = Regex.Matches(template, @"\{(\w+)\}");
        foreach (Match m in pathParamMatches)
            pathParams.Add(m.Groups[1].Value);

        // Raw text/plain (or non-JSON/non-form) bodies have no named fields — synthesize "body"
        // so injectableEndpoints / SSTI probes see the sink.
        if (bodyParams.Count == 0
            && (!string.IsNullOrEmpty(bodySample) || LooksLikeRawContentType(requestContentType)))
        {
            var path = entries.First().Path ?? "";
            if (LooksLikeRawContentType(requestContentType)
                || InjectionParamClassifier.LooksLikeTemplateEndpoint(path)
                || LooksLikeRawBodySample(bodySample))
            {
                bodyParams.Add("body");
                requestContentType ??= "text/plain";
            }
        }

        return new AttackSurfaceParameters
        {
            Query = queryParams.OrderBy(p => p).ToList(),
            Body = bodyParams.OrderBy(p => p).ToList(),
            Headers = headerParams.OrderBy(p => p).ToList(),
            Path = pathParams.OrderBy(p => p).ToList(),
            RequestContentType = requestContentType,
            RequestBodySample = bodySample
        };
    }

    private static bool LooksLikeRawContentType(string? ct) =>
        !string.IsNullOrWhiteSpace(ct)
        && (ct.Contains("text/plain", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("text/template", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("application/octet-stream", StringComparison.OrdinalIgnoreCase));

    private static bool LooksLikeRawBodySample(string? sample)
    {
        if (string.IsNullOrWhiteSpace(sample)) return false;
        var t = sample.TrimStart();
        if (t.StartsWith('{') || t.StartsWith('[')) return false;
        if (t.Contains('=') && !t.Contains('<') && !t.Contains("{{", StringComparison.Ordinal))
            return false;
        return true;
    }

    private static AttackSurfaceAuth DetectAuth(List<NetworkEntry> entries)
    {
        var authTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var anyAuthHeader = false;
        var anyCsrf = false;

        foreach (var entry in entries)
        {
            // Authorization header
            if (entry.RequestHeaders.Any(h =>
                h.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase)))
            {
                anyAuthHeader = true;
                var authVal = entry.RequestHeaders
                    .FirstOrDefault(h => h.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase)).Value ?? "";
                if (authVal.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    authTypes.Add("bearer-token");
                else if (authVal.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                    authTypes.Add("basic");
                else
                    authTypes.Add("authorization-header");
            }

            // CSRF tokens
            if (entry.RequestHeaders.Any(h =>
                h.Key.Contains("csrf", StringComparison.OrdinalIgnoreCase) ||
                h.Key.Contains("xsrf", StringComparison.OrdinalIgnoreCase)))
            {
                anyCsrf = true;
                authTypes.Add("csrf-token");
            }

            // Session cookies
            if (entry.RequestHeaders.TryGetValue("Cookie", out var cookieHeader) ||
                entry.RequestHeaders.TryGetValue("cookie", out cookieHeader))
            {
                if (AuthCookiePatterns.Any(p =>
                    cookieHeader.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    authTypes.Add("session-cookie");
                }
            }
        }

        // Derive "required" from observed access outcomes, not merely from a cookie being attached.
        // The browser sends session cookies on *every* same-site request (including public files), so
        // cookie presence alone is not evidence that the endpoint gates access.
        var sawAuthChallenge = entries.Any(e => e.StatusCode is 401 or 403);
        var sawSuccess = entries.Any(e => e.StatusCode is >= 200 and < 300);

        bool required;
        if (anyAuthHeader)
            // The page attached Authorization itself. Unlike a cookie, that is not sent on public files.
            required = true;
        else if (sawSuccess)
            // Content was served in the observed context (possibly anonymous) → treat as reachable.
            required = false;
        else if (sawAuthChallenge)
            // Only saw auth challenges and never a success → gated.
            required = true;
        else
            // No conclusive outcome: fall back to explicit auth mechanisms (Authorization/Bearer/Basic),
            // but NOT a bare session cookie.
            required = anyAuthHeader || anyCsrf;

        string type;
        if (required)
            type = authTypes.Count > 0
                ? string.Join(" + ", authTypes.OrderBy(t => t))
                : (sawAuthChallenge ? "unknown (401/403 observed)" : "unknown");
        else if (sawSuccess && authTypes.Count > 0)
            // Reachable even though credentials were attached — note what was sent for transparency.
            type = $"none (accessible; {string.Join(" + ", authTypes.OrderBy(t => t))} sent)";
        else
            type = "none";

        return new AttackSurfaceAuth
        {
            Required = required,
            Type = type
        };
    }

    private static Dictionary<string, AttackSurfaceResponsePattern> BuildResponsePatterns(List<NetworkEntry> entries)
    {
        var patterns = new Dictionary<string, AttackSurfaceResponsePattern>();

        var byStatus = entries
            .GroupBy(e => e.StatusCode)
            .OrderBy(g => g.Key);

        foreach (var statusGroup in byStatus)
        {
            var status = statusGroup.Key.ToString();
            var representative = statusGroup.First();
            var contentType = representative.ContentType;
            var body = representative.ResponseBody;

            string description;
            if (!string.IsNullOrEmpty(body))
                description = DescribeResponseBody(body, contentType);
            else if (!string.IsNullOrEmpty(contentType))
                description = DescribeContentType(contentType);
            else
                description = statusGroup.Key is >= 300 and < 400 ? "redirect" : "unknown";

            var rp = new AttackSurfaceResponsePattern
            {
                Description = description,
                Count = statusGroup.Count()
            };

            if (!string.IsNullOrEmpty(body))
            {
                rp.BodyLength = body.Length;
                rp.BodySnippet = BuildBodySnippet(body, contentType);
                rp.BodyHash = ComputeBodyHash(body);
            }

            patterns[status] = rp;
        }

        return patterns;
    }

    private static string BuildBodySnippet(string body, string contentType)
    {
        const int maxLen = 200;
        string text;

        if (contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
        {
            text = StripHtmlTags(body);
            text = Regex.Replace(text, @"\s+", " ").Trim();
        }
        else
        {
            text = body.Trim();
        }

        if (text.Length <= maxLen)
            return text;
        return text[..maxLen] + "…";
    }

    private static string StripHtmlTags(string html)
    {
        var noScript = Regex.Replace(html, @"<(script|style)[^>]*>[\s\S]*?</\1>", " ",
            RegexOptions.IgnoreCase);
        var noTags = Regex.Replace(noScript, @"<[^>]+>", " ");
        return System.Net.WebUtility.HtmlDecode(noTags);
    }

    private static string ComputeBodyHash(string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    private static string DescribeResponseBody(string body, string contentType)
    {
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
            body.TrimStart().StartsWith("{") || body.TrimStart().StartsWith("["))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object)
                {
                    var keys = root.EnumerateObject()
                        .Select(p => p.Name)
                        .Take(6)
                        .ToList();
                    var keyStr = string.Join(", ", keys);
                    if (root.EnumerateObject().Count() > 6)
                        keyStr += ", ...";
                    return $"JSON {{{keyStr}}}";
                }
                if (root.ValueKind == JsonValueKind.Array)
                {
                    return $"JSON array[{root.GetArrayLength()}]";
                }
            }
            catch { }
        }

        if (contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
            return "HTML";
        if (contentType.Contains("xml", StringComparison.OrdinalIgnoreCase))
            return "XML";
        if (contentType.Contains("text/plain", StringComparison.OrdinalIgnoreCase))
            return "plain text";

        return DescribeContentType(contentType);
    }

    private static string DescribeContentType(string contentType)
    {
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase)) return "JSON";
        if (contentType.Contains("html", StringComparison.OrdinalIgnoreCase)) return "HTML";
        if (contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)) return "XML";
        if (contentType.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)) return "form-urlencoded";
        if (contentType.Contains("text/plain", StringComparison.OrdinalIgnoreCase)) return "plain text";
        if (string.IsNullOrEmpty(contentType)) return "unknown";
        return contentType.Split(';')[0].Trim();
    }

    private static string AssessTestPriority(AttackSurfaceEndpoint ep, List<NetworkEntry> entries)
    {
        var score = 0;

        // State-changing methods
        if (ep.Methods.Any(m => m is "POST" or "PUT" or "PATCH" or "DELETE"))
            score += 3;

        // Has body parameters (higher attack surface)
        if (ep.Parameters.Body.Count > 0)
            score += 2;

        // Auth-related endpoints (login, token, etc.)
        var pathLower = ep.UrlTemplate.ToLowerInvariant();
        if (pathLower.Contains("login") || pathLower.Contains("auth") ||
            pathLower.Contains("token") || pathLower.Contains("session") ||
            pathLower.Contains("password") || pathLower.Contains("register") ||
            pathLower.Contains("signup") || pathLower.Contains("saml") ||
            pathLower.Contains("oauth") || pathLower.Contains("sso"))
            score += 3;

        // Admin / config endpoints
        if (pathLower.Contains("admin") || pathLower.Contains("config") ||
            pathLower.Contains("settings") || pathLower.Contains("manage"))
            score += 2;

        // Search / query sinks — high injection value even on GET
        if (pathLower.Contains("/search") || pathLower.Contains("/lookup") || pathLower.Contains("/find")
            || ep.Parameters.Query.Any(p => InjectionParamClassifier.XssLikelihoodScore(p) >= 3
                                            || InjectionParamClassifier.SqliLikelihoodScore(p) >= 3))
            score += 2;

        // File-like params (path traversal / LFI candidates)
        if (ep.Parameters.Query.Concat(ep.Parameters.Body).Any(p =>
                p.Equals("file", StringComparison.OrdinalIgnoreCase)
                || p.Equals("path", StringComparison.OrdinalIgnoreCase)
                || p.Equals("document", StringComparison.OrdinalIgnoreCase)
                || p.Equals("filename", StringComparison.OrdinalIgnoreCase)))
            score += 2;

        // Has path parameters (potential IDOR)
        if (ep.Parameters.Path.Count > 0)
            score += 1;

        // Received error responses (potential for exploitation)
        if (entries.Any(e => e.StatusCode >= 500))
            score += 2;
        if (entries.Any(e => e.StatusCode is 401 or 403))
            score += 1;

        // CSRF token present (sensitive action)
        if (ep.Auth.Type.Contains("csrf", StringComparison.OrdinalIgnoreCase))
            score += 1;

        // Response JSON that dumps credentials / tokens — elevate even for plain GET /api/users
        if (ResponseLooksCredentialSensitive(ep))
            score += 3;

        if (entries.All(e => e.StatusCode == 404))
            score = Math.Min(score, 1);

        return score switch
        {
            >= 7 => "critical",
            >= 5 => "high",
            >= 3 => "medium",
            _ => "low"
        };
    }

    private static bool ResponseLooksCredentialSensitive(AttackSurfaceEndpoint ep)
    {
        foreach (var pattern in ep.ResponsePatterns.Values)
        {
            var snippet = pattern.BodySnippet ?? "";
            if (snippet.Length < 8) continue;
            if (snippet.Contains("\"password\"", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("\"passwd\"", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("\"token\"", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("\"apiKey\"", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("\"api_key\"", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("\"secret\"", StringComparison.OrdinalIgnoreCase)
                || snippet.Contains("\"access_token\"", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <param name="endpoints">Aggregated endpoint objects (for method distribution, priority counts).</param>
    /// <param name="apiEntries">Filtered API entries (static resources removed).</param>
    /// <param name="allEntries">Full unfiltered network entries — used for the <c>Hosts</c> list so every
    /// contacted domain appears even if it only served static resources.</param>
    private static AttackSurfaceSummary BuildSummary(
        List<AttackSurfaceEndpoint> endpoints,
        List<NetworkEntry> apiEntries,
        List<NetworkEntry> allEntries)
    {
        var methodDist = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var ep in endpoints)
        {
            foreach (var method in ep.Methods)
            {
                methodDist.TryGetValue(method, out var count);
                methodDist[method] = count + 1;
            }
        }

        var hosts = allEntries
            .Select(e => e.Host)
            .Where(h => !string.IsNullOrEmpty(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(h => h)
            .ToList();

        return new AttackSurfaceSummary
        {
            TotalEndpoints = endpoints.Count,
            Authenticated = endpoints.Count(e => e.Auth.Required),
            Unauthenticated = endpoints.Count(e => !e.Auth.Required),
            HighPriority = endpoints.Count(e => e.TestPriority is "high" or "critical"),
            MediumPriority = endpoints.Count(e => e.TestPriority == "medium"),
            LowPriority = endpoints.Count(e => e.TestPriority == "low"),
            MethodDistribution = methodDist.OrderBy(kv => kv.Key).ToDictionary(kv => kv.Key, kv => kv.Value),
            Hosts = hosts
        };
    }

    /// <summary>
    /// Build a runtime DOM view from the same interactive list as <c>GET /api/state</c> (<see cref="AutomationContext.GetInteractiveElements"/>).
    /// </summary>
    public static SpaRuntimeSurface BuildSpaRuntimeSurface(
        IReadOnlyList<Dictionary<string, object>>? elements,
        int htmlFormCount,
        string? pageUrl,
        string? pageTitle,
        int maxFieldRows = 200,
        int maxLinkRows = 200)
    {
        var w = new List<string>();
        if (elements is not { Count: > 0 })
        {
            w.Add(
                "No interactive elements — the page may still be loading, or use POST /api/state/refresh after the SPA routes.");
            return new SpaRuntimeSurface
            {
                HtmlFormCount = htmlFormCount,
                PageUrl = pageUrl,
                PageTitle = pageTitle,
                Warnings = w
            };
        }

        var inputC = 0;
        var linkC = 0;
        var btnC = 0;
        var othC = 0;
        var inRows = new List<SpaFieldSummary>();
        var linkRows = new List<SpaFieldSummary>();
        foreach (var d in elements)
        {
            var tag = (ElemStr(d, "tag") ?? "").ToLowerInvariant();
            var type = (ElemStr(d, "type") ?? "").ToLowerInvariant();
            var s = new SpaFieldSummary
            {
                Ref = ElemInt(d, "ref"),
                Tag = tag,
                Type = type,
                Name = ElemStr(d, "name"),
                Id = ElemStr(d, "id"),
                Label = TruncField(ElemStr(d, "label"), 200),
                Placeholder = TruncField(ElemStr(d, "placeholder"), 120),
                Href = TruncField(ElemStr(d, "href"), 500),
                Text = TruncField(ElemStr(d, "text"), 200),
                Selector = TruncField(ElemStr(d, "selector"), 300)
            };

            if (tag == "a")
            {
                linkC++;
                if (linkRows.Count < maxLinkRows) linkRows.Add(s);
            }
            else if (tag is "input" or "textarea" or "select")
            {
                inputC++;
                if (inRows.Count < maxFieldRows) inRows.Add(s);
            }
            else if (tag == "button" || (tag == "input" && type is "button" or "submit" or "reset" or "image")
                || type is "button" or "submit" or "reset" or "image")
            {
                btnC++;
            }
            else
            {
                othC++;
            }
        }

        return new SpaRuntimeSurface
        {
            HtmlFormCount = htmlFormCount,
            InputFieldCount = inputC,
            LinkCount = linkC,
            ButtonCount = btnC,
            OtherInteractiveCount = othC,
            TotalInteractiveElements = elements.Count,
            PageUrl = pageUrl,
            PageTitle = pageTitle,
            InputFields = inRows,
            Links = linkRows,
            Warnings = w
        };
    }

    private static string? TruncField(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Length <= max ? s : s[..max] + "…";
    }

    private static string? ElemStr(Dictionary<string, object> d, string key)
    {
        if (!d.TryGetValue(key, out var o) || o == null) return null;
        if (o is string s) return s;
        if (o is JsonElement je)
        {
            return je.ValueKind switch
            {
                JsonValueKind.String => je.GetString(),
                JsonValueKind.Number => je.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => je.ToString()
            };
        }

        return o.ToString();
    }

    private static int? ElemInt(Dictionary<string, object> d, string key)
    {
        if (!d.TryGetValue(key, out var o) || o == null) return null;
        if (o is int i) return i;
        if (o is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.Number) return je.GetInt32();
            if (je.ValueKind == JsonValueKind.String && int.TryParse(je.GetString(), out var n)) return n;
        }

        return null;
    }
}
