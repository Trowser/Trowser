using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Fast reflected SSTI probe — single polyglot GET payload targeting multiple template engines.
/// Hit when attack response contains evaluated token <c>49</c> (word-boundary) absent from baseline; partial markers are medium.
/// Inspired by OWASP WSTG-INPV-18 and PortSwigger SSTI methodology; also influenced by pentest-ai <c>web.ssti_polyglot</c>.
/// Trowser-specific: traffic + scaffold paths; GET-only (does not cover POST body SSTI).
/// </summary>
public sealed class SstiPolyglotScanProbe
{
    public const string Canary = "trowser-ssti-canary";
    public const string Polyglot = "${7*7}{{7*7}}{{=7*7}}<%=7*7%>#{7*7}";
    public const string EvaluatedToken = "49";

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public SstiPolyglotScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class SstiPolyglotScanOptions
    {
        public int MaxCandidates { get; set; } = 25;
        /// <summary>Max path×param probe attempts (each = baseline + attack GET). 0 = unlimited.</summary>
        public int MaxProbes { get; set; }
        /// <summary>Max query parameter names to try per path. 0 = all defaults.</summary>
        public int MaxParams { get; set; }
        public int TimeoutMs { get; set; } = 12000;
        public bool IncludeScaffold { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;
        public List<string>? Paths { get; set; }
        public List<string>? Params { get; set; }
    }

    public sealed class SstiPolyglotFinding
    {
        public string Category { get; init; } = "ssti-polyglot";
        public string Severity { get; init; } = "high";
        public string Url { get; init; } = "";
        public string ParamName { get; init; } = "";
        public string Detail { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Source { get; init; } = "scaffold";
    }

    public sealed class SstiPolyglotScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public List<SstiPolyglotFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public static readonly string[] DefaultPaths =
    [
        "/",
        "/search",
        "/api/search",
        "/q",
        "/lookup",
        "/name",
        "/greet",
        "/preview",
        "/render",
        "/template",
        "/msg",
        "/text"
    ];

    public static readonly string[] DefaultParams =
    [
        "q", "query", "search", "name", "message", "text", "greet", "template", "content"
    ];

    private static readonly string[] PartialMarkers =
    [
        "{{49}}", "${49}", "<%=49%>", "#{49}"
    ];

    public async Task<SstiPolyglotScanResult> RunAsync(
        SstiPolyglotScanOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running ssti-polyglot-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var paths = BuildPaths(origin, options);
        var paramNames = options.Params is { Count: > 0 }
            ? options.Params
            : DefaultParams.ToList();
        if (options.MaxParams > 0)
            paramNames = paramNames.Take(options.MaxParams).ToList();

        var findings = new List<SstiPolyglotFinding>();
        var probed = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var maxPaths = options.MaxCandidates > 0 ? options.MaxCandidates : int.MaxValue;

        foreach (var (path, pathSource) in paths.Take(maxPaths))
        {
            foreach (var param in paramNames)
            {
                if (options.MaxProbes > 0 && probed >= options.MaxProbes)
                    goto done;

                ct.ThrowIfCancellationRequested();
                probed++;

                var baselineUrl = BuildUrl(origin, path, param, Canary);
                var baseline = await LoginInjectionHelpers.SendAsync(
                    _ctx, baselineUrl, "GET", null, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
                if (baseline.Status != 200)
                    continue;

                var attackUrl = BuildUrl(origin, path, param, Polyglot);
                var attack = await LoginInjectionHelpers.SendAsync(
                    _ctx, attackUrl, "GET", null, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
                if (attack.Status != 200)
                    continue;

                var severity = Classify(baseline.Body, attack.Body);
                if (severity == null)
                    continue;

                var key = $"{path}::{param}";
                if (!seen.Add(key))
                    continue;

                var idx = IndexOfEvaluatedToken(attack.Body);
                var evidence = idx >= 0
                    ? attack.Body[Math.Max(0, idx - 64)..Math.Min(attack.Body.Length, idx + 64)]
                    : attack.Body[..Math.Min(attack.Body.Length, 128)];

                findings.Add(new SstiPolyglotFinding
                {
                    Severity = severity,
                    Url = attackUrl,
                    ParamName = param,
                    Detail = severity == "high"
                        ? "Polyglot template evaluated to 49 in response."
                        : "Partial or weak polyglot evaluation artifact in response.",
                    Evidence = evidence,
                    Source = pathSource
                });
                _log($"  FLAG SSTI polyglot: {param} on {path} ({severity})", "#F44747");
            }
        }

        done:
        return new SstiPolyglotScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} SSTI polyglot finding(s) across {probed} probe(s)."
                : $"No SSTI polyglot indicators across {probed} probe(s).",
            CandidatesProbed = probed,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    internal static string? Classify(string baselineBody, string attackBody)
    {
        if (ContainsEvaluatedToken(baselineBody))
            return null;
        if (!ContainsEvaluatedToken(attackBody))
            return null;

        foreach (var marker in PartialMarkers)
        {
            if (attackBody.Contains(marker, StringComparison.Ordinal))
                return "medium";
        }

        // High only with non-digit-bounded 49 and no leftover template delimiter residue.
        if (HasPolyglotResidue(attackBody))
            return "medium";

        return "high";
    }

    /// <summary>True when <see cref="EvaluatedToken"/> appears with non-digit characters (or edges) on both sides.</summary>
    internal static bool ContainsEvaluatedToken(string body) => IndexOfEvaluatedToken(body) >= 0;

    internal static int IndexOfEvaluatedToken(string body)
    {
        if (string.IsNullOrEmpty(body))
            return -1;

        var idx = 0;
        while ((idx = body.IndexOf(EvaluatedToken, idx, StringComparison.Ordinal)) >= 0)
        {
            var beforeOk = idx == 0 || !char.IsDigit(body[idx - 1]);
            var afterIdx = idx + EvaluatedToken.Length;
            var afterOk = afterIdx >= body.Length || !char.IsDigit(body[afterIdx]);
            if (beforeOk && afterOk)
                return idx;
            idx += EvaluatedToken.Length;
        }

        return -1;
    }

    private static bool HasPolyglotResidue(string body) =>
        body.Contains("{{", StringComparison.Ordinal)
        || body.Contains("}}", StringComparison.Ordinal)
        || body.Contains("${", StringComparison.Ordinal)
        || body.Contains("<%=", StringComparison.Ordinal)
        || body.Contains("#{", StringComparison.Ordinal);

    private static string BuildUrl(string origin, string path, string param, string value)
    {
        var root = path.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? path
            : origin.TrimEnd('/') + (path.StartsWith('/') ? path : "/" + path);
        var sep = root.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return $"{root}{sep}{Uri.EscapeDataString(param)}={Uri.EscapeDataString(value)}";
    }

    private List<(string Path, string Source)> BuildPaths(string origin, SstiPolyglotScanOptions options)
    {
        var paths = new List<(string, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.Paths is { Count: > 0 })
        {
            foreach (var p in options.Paths)
            {
                if (seen.Add(p))
                    paths.Add((p, "explicit"));
            }
        }

        foreach (var entry in _ctx.Network.Entries)
        {
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
                continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            var path = uri.AbsolutePath;
            if (string.IsNullOrEmpty(path))
                path = "/";
            if (seen.Add(path))
                paths.Add((path, "network"));
        }

        if (options.IncludeScaffold)
        {
            foreach (var p in DefaultPaths)
            {
                if (seen.Add(p))
                    paths.Add((p, "scaffold"));
            }

            foreach (var tpl in InjectionScaffold.SstiAlwaysProbed)
            {
                var qIdx = tpl.IndexOf('?', StringComparison.Ordinal);
                var pathOnly = qIdx >= 0 ? tpl[..qIdx] : tpl;
                if (seen.Add(pathOnly))
                    paths.Add((pathOnly, "scaffold"));
            }
        }

        return paths;
    }
}
