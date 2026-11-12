using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Web Cache Deception: path-normalization variants that may cache authenticated responses for anonymous clients.
/// Confirmed only with auth delta (cookie vs cookieless) plus cacheability signal or matching authed body on anon variant.
/// Inspired by PortSwigger cache-deception research; also influenced by pentest-ai <c>web.cache_deception</c>.
/// Requires an authenticated session. Category: <c>cache-deception</c>.
/// </summary>
public sealed class CacheDeceptionScanner
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private static readonly string[] DefaultAuthPaths =
    [
        "/api/me", "/api/profile", "/api/account", "/me", "/account", "/dashboard",
        "/api/users/me", "/api/v1/me"
    ];

    private static readonly string[] VariantTemplates =
    [
        "{p}/.css", "{p}/.js", "{p}/.json", "{p};.css", "{p}%2F.css", "{p}%3B.css", "{p}/static.css",
        "{p}/wcd.css", "{p}?.css", "{p}%00.css"
    ];

    public CacheDeceptionScanner(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<CacheDeceptionResult> RunAsync(CacheDeceptionOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running cache deception tests.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var minBody = options.MinBodySize > 0 ? options.MinBodySize : 64;
        var maxCandidates = options.MaxCandidates > 0 ? options.MaxCandidates : 12;

        var cookieHeader = await _ctx.GetCookieHeaderForUrl(origin);
        if (string.IsNullOrWhiteSpace(cookieHeader) && options.RequireSession)
        {
            return new CacheDeceptionResult
            {
                Message = "No session cookies for origin — cache deception requires an authenticated session. Log in first.",
                Origin = origin,
                SkippedReason = "no-session"
            };
        }

        var basePaths = ResolveBasePaths(options, origin, currentUri);
        var findings = new List<CacheDeceptionFinding>();
        var probesRun = 0;

        var shellFingerprint = await UploadProbeSupport.CaptureSpaShellFingerprintAsync(_ctx, origin, timeout, ct);

        _log($"CacheDeception: {basePaths.Count} base path(s) on {origin}", "#888888");

        foreach (var basePath in basePaths)
        {
            ct.ThrowIfCancellationRequested();
            var undecoratedUrl = AbsoluteUrl(origin, basePath);

            probesRun++;
            var authedBase = await SecurityProbeHttp.FetchAsync(
                _ctx, undecoratedUrl, "GET", null, null, timeout, includeBrowserCookies: true, ct);
            if (authedBase.Status != 200 || authedBase.Body.Length < minBody)
                continue;

            if (IsSpaShellBody(authedBase.Body, shellFingerprint))
                continue;

            var anonBase = await SecurityProbeHttp.FetchAsync(
                _ctx, undecoratedUrl, "GET", null, null, timeout, includeBrowserCookies: false, ct);

            // (a) Auth delta on undecorated path — cookie body must differ from cookieless.
            if (BodiesMatchOrClose(authedBase.Body, anonBase.Body))
                continue;

            if (IsSpaShellBody(anonBase.Body, shellFingerprint) && IsSpaShellBody(authedBase.Body, shellFingerprint))
                continue;

            var variants = BuildVariantsForPath(basePath, maxCandidates);
            foreach (var variantPath in variants)
            {
                ct.ThrowIfCancellationRequested();
                var variantUrl = AbsoluteUrl(origin, variantPath);

                probesRun++;
                var anonVariant = await SecurityProbeHttp.FetchAsync(
                    _ctx, variantUrl, "GET", null, null, timeout, includeBrowserCookies: false, ct);
                if (anonVariant.Status != 200 || anonVariant.Body.Length < minBody)
                    continue;

                if (IsSpaShellBody(anonVariant.Body, shellFingerprint))
                    continue;

                // (b) Anon decorated body matches (or is close to) AUTHED undecorated body.
                if (!BodiesMatchOrClose(anonVariant.Body, authedBase.Body))
                    continue;

                // (c) Cacheability header signal — missing demotes confidence/severity.
                var hasCacheSignal = CacheHeaderAnalyzer.HasCacheabilitySignal(anonVariant.ResponseHeaders)
                                     || CacheHeaderAnalyzer.HasCacheabilitySignal(authedBase.ResponseHeaders);
                var confidence = hasCacheSignal ? "confirmed" : "tentative";

                if (!hasCacheSignal)
                {
                    probesRun++;
                    var confirm = await SecurityProbeHttp.FetchAsync(
                        _ctx, variantUrl, "GET", null, null, timeout, includeBrowserCookies: false, ct);
                    if (BodiesMatchOrClose(confirm.Body, authedBase.Body)
                        && CacheHeaderAnalyzer.HasCacheabilitySignal(confirm.ResponseHeaders))
                    {
                        hasCacheSignal = true;
                        confidence = "confirmed";
                    }
                }

                var severity = hasCacheSignal ? "high" : "medium";

                _log($"  FLAG WCD: {variantUrl} (auth-delta + anon-variant≈authed, cache={hasCacheSignal})", "#F44747");
                findings.Add(new CacheDeceptionFinding
                {
                    Severity = severity,
                    Confidence = confidence,
                    Url = variantUrl,
                    VariantPath = variantPath,
                    AuthedStatus = authedBase.Status,
                    AnonStatus = anonVariant.Status,
                    BodyLength = authedBase.Body.Length,
                    BodySnippet = authedBase.Body.Length > 200 ? authedBase.Body[..200] + "..." : authedBase.Body,
                    CacheHeaders = CacheHeaderAnalyzer.FormatCacheHeadersPair(
                        authedBase.ResponseHeaders, anonVariant.ResponseHeaders, "authed", "anon"),
                    Indicator = "cache-deception"
                });
            }
        }

        sw.Stop();
        return BuildResult(findings, origin, probesRun, sw.ElapsedMilliseconds);
    }

    private static string AbsoluteUrl(string origin, string path)
    {
        if (path.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            return path;
        return origin.TrimEnd('/') + (path.StartsWith('/') ? path : "/" + path);
    }

    private static bool IsSpaShellBody(string? body, string? shellFingerprint)
    {
        if (string.IsNullOrEmpty(body)) return false;
        if (UploadProbeSupport.LooksLikeSpaShell(body, shellFingerprint))
            return true;
        return SpaShellGuard.IsSpaHtmlShell(body);
    }

    private static bool BodiesMatchOrClose(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.Ordinal))
            return true;
        return ExceptionalConditionHeuristics.BodiesSimilar(a, b);
    }

    private static List<string> ResolveBasePaths(CacheDeceptionOptions options, string origin, Uri currentUri)
    {
        var currentPath = currentUri.AbsolutePath;
        if (string.IsNullOrEmpty(currentPath) || currentPath == "/")
            currentPath = "";

        List<string> list;
        if (options.Paths is { Count: > 0 })
        {
            list = options.Paths.Select(NormalizePath).Where(p => !string.IsNullOrEmpty(p)).ToList();
        }
        else
        {
            var fromHints = options.EndpointHints?
                .Select(h => h.Url)
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u =>
                {
                    if (!Uri.TryCreate(u, UriKind.Absolute, out var uri)) return null;
                    if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                        return null;
                    return uri.AbsolutePath;
                })
                .Where(p => p != null)
                .Select(p => p!)
                .ToList();

            list = fromHints is { Count: > 0 } ? fromHints : DefaultAuthPaths.ToList();
        }

        if (!string.IsNullOrEmpty(currentPath)
            && !list.Any(p => p.Equals(currentPath, StringComparison.OrdinalIgnoreCase)))
            list.Insert(0, currentPath);

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<string> BuildVariantsForPath(string basePath, int maxCandidates)
    {
        var outList = new List<string>();
        var p = basePath.TrimEnd('/');
        if (string.IsNullOrEmpty(p)) return outList;
        foreach (var tpl in VariantTemplates)
        {
            outList.Add(tpl.Replace("{p}", p, StringComparison.Ordinal));
            if (outList.Count >= maxCandidates)
                break;
        }

        return outList;
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        if (Uri.TryCreate(path, UriKind.Absolute, out var uri))
            return uri.AbsolutePath;
        return path.StartsWith('/') ? path : "/" + path;
    }

    private static CacheDeceptionResult BuildResult(
        List<CacheDeceptionFinding> findings, string origin, int probesRun, long elapsedMs)
    {
        var deduped = findings
            .GroupBy(f => f.Url, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        var message = deduped.Count == 0
            ? probesRun == 0
                ? "No cache deception candidates to probe."
                : $"No web cache deception detected ({probesRun} request(s) probed)."
            : $"Found {deduped.Count} web cache deception issue(s) across {probesRun} request(s).";

        return new CacheDeceptionResult
        {
            Message = message,
            Origin = origin,
            CandidatesProbed = probesRun,
            Findings = deduped,
            ElapsedMs = elapsedMs
        };
    }
}

public sealed class CacheDeceptionOptions
{
    public List<string>? Paths { get; init; }
    public List<EndpointParamHint>? EndpointHints { get; init; }
    public int MaxCandidates { get; init; } = 12;
    public int MinBodySize { get; init; } = 64;
    public int TimeoutMs { get; init; } = 15000;
    public bool RequireSession { get; init; } = true;
}

public sealed class CacheDeceptionResult
{
    public string Message { get; init; } = "";
    public string Origin { get; init; } = "";
    public string? SkippedReason { get; init; }
    public int CandidatesProbed { get; init; }
    public long ElapsedMs { get; init; }
    public List<CacheDeceptionFinding> Findings { get; init; } = [];
}

public sealed class CacheDeceptionFinding
{
    public string Severity { get; init; } = "high";
    public string Confidence { get; init; } = "confirmed";
    public string Url { get; init; } = "";
    public string VariantPath { get; init; } = "";
    public int AuthedStatus { get; init; }
    public int AnonStatus { get; init; }
    public int BodyLength { get; init; }
    public string BodySnippet { get; init; } = "";
    public string CacheHeaders { get; init; } = "";
    public string Indicator { get; init; } = "cache-deception";
}
