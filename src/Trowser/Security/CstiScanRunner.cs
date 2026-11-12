using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Standalone CSTI scan — discovers URL parameters from DOM/network log and probes rendered DOM for template evaluation.
/// </summary>
public sealed class CstiScanRunner
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CstiScanRunner(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class CstiScanOptions
    {
        public string? Url { get; set; }
        public string? ParamName { get; set; }
        public List<string>? Engines { get; set; }
        public List<string>? Sources { get; set; }
        public bool Escalate { get; set; }
        public bool MonitorSinks { get; set; } = true;
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 10_000;
    }

    public sealed class CstiCandidate
    {
        public string BaseUrl { get; init; } = "";
        public string ParamName { get; init; } = "";
        public CstiProbes.Source Source { get; init; }
        public string Discovery { get; init; } = "";
    }

    public sealed class CstiFinding
    {
        public string Url { get; init; } = "";
        public string Parameter { get; init; } = "";
        public string Source { get; init; } = "";
        public string Engine { get; init; } = "";
        public string BasicExpression { get; init; } = "";
        public string? EvaluatedToken { get; init; }
        public bool CodeExecution { get; init; }
        public List<string> Sinks { get; init; } = [];
        public string Severity { get; init; } = "medium";
    }

    public sealed class CstiScanBatchResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public List<string> EnginesTested { get; init; } = [];
        public List<CstiProbeResultEntry> Probes { get; init; } = [];
        public List<CstiFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;

        public sealed class CstiProbeResultEntry
        {
            public string Url { get; init; } = "";
            public string ParamName { get; init; } = "";
            public string Source { get; init; } = "";
            public string Engine { get; init; } = "";
            public CstiScanner.CstiProbeResult Result { get; init; } = new();
            public bool HasFindings => Result.HasFindings;
        }

        public string Format(bool includeDetails = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== CSTI Scan (Client-Side Template Injection) ===");
            sb.AppendLine(Message);
            sb.AppendLine($"Candidates: {CandidatesProbed}, Engines: {string.Join(", ", EnginesTested)}, Elapsed: {ElapsedMs}ms");
            sb.AppendLine();

            if (Findings.Count == 0)
            {
                sb.AppendLine("NO CSTI INDICATORS");
                return sb.ToString();
            }

            sb.AppendLine($"FINDINGS ({Findings.Count}):");
            foreach (var f in Findings)
            {
                sb.AppendLine($"  [{f.Severity.ToUpperInvariant()}] {f.Parameter} ({f.Source}) on {f.Url}");
                sb.AppendLine($"    Engine: {f.Engine}, Expression: {f.BasicExpression} -> {f.EvaluatedToken}");
                if (f.CodeExecution) sb.AppendLine("    Code execution: yes");
                if (f.Sinks.Count > 0) sb.AppendLine($"    Sinks: {string.Join(", ", f.Sinks.Distinct())}");
            }

            if (!includeDetails) return sb.ToString();

            sb.AppendLine();
            sb.AppendLine("--- Probe details ---");
            foreach (var probe in Probes.Where(p => p.HasFindings))
            {
                sb.AppendLine($"  {probe.Engine} / {probe.Source} / {probe.ParamName}:");
                foreach (var row in probe.Result.Rows)
                {
                    var hint = row.EngineHint != null ? $" [{row.EngineHint}]" : "";
                    sb.AppendLine($"    [{row.Level}]{hint} {row.Payload} -> evaluated={row.ExpressionEvaluated}, severity={row.Severity}");
                }
            }

            return sb.ToString();
        }
    }

    public async Task<CstiScanBatchResult> RunAsync(CstiScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running csti-scan.");

        TechStackResult? stack = null;
        try { stack = await _ctx.CheckTechStack(); }
        catch { /* optional — DOM fallback still available */ }

        var engines = await CstiProbes.ResolveEnginesAsync(_ctx, options.Engines, stack);
        var sources = CstiProbes.ResolveSources(options.Sources);
        var candidates = await BuildCandidatesAsync(options, currentUrl, currentUri, sources, ct);
        if (candidates.Count == 0)
        {
            return new CstiScanBatchResult
            {
                Message = "No CSTI parameter candidates found. Browse the app or pass url + paramName.",
                EnginesTested = engines.Select(CstiProbes.EngineName).ToList(),
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var probeOptions = new CstiScanner.CstiProbeOptions
        {
            Escalate = options.Escalate,
            MonitorSinks = options.MonitorSinks,
            TimeoutMs = options.TimeoutMs > 0 ? options.TimeoutMs : 10_000,
            EngineCandidates = engines
        };

        var probes = new List<CstiScanBatchResult.CstiProbeResultEntry>();
        var findings = new List<CstiFinding>();
        _log($"CstiScan: {candidates.Count} candidate(s), engines={string.Join(",", engines.Select(CstiProbes.EngineName))}", "#888888");

        var baselineUrl = await ProbeNavigationRestore.CaptureBaselineUrlAsync(_ctx);
        try
        {
        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var result = await CstiScanner.IdentifyAndProbeAsync(
                    _ctx, candidate.BaseUrl, candidate.ParamName, candidate.Source, probeOptions, ct);

                probes.Add(new CstiScanBatchResult.CstiProbeResultEntry
                {
                    Url = candidate.BaseUrl,
                    ParamName = candidate.ParamName,
                    Source = result.Source,
                    Engine = result.Engine,
                    Result = result
                });

                if (!result.HasFindings) continue;

                var basic = result.Rows.First(r => r.Level == "basic" && r.ExpressionEvaluated);
                var escalation = result.Rows.LastOrDefault(r => r.Level == "escalation" && r.ExpressionEvaluated);

                _log($"  FLAG CSTI: {candidate.ParamName} ({result.Source}) engine={result.Engine}", "#F44747");
                var bestRow = escalation ?? basic;
                findings.Add(new CstiFinding
                {
                    Url = candidate.BaseUrl,
                    Parameter = candidate.ParamName,
                    Source = result.Source,
                    Engine = result.Engine,
                    BasicExpression = basic.Payload,
                    EvaluatedToken = bestRow.EvaluatedToken ?? basic.EvaluatedToken,
                    CodeExecution = escalation?.CodeExecution == true,
                    Sinks = bestRow.Sinks.Distinct().ToList(),
                    Severity = bestRow.Severity
                });
            }
            catch (Exception ex)
            {
                _log($"  CSTI skip {candidate.ParamName}: {ex.Message}", "#888888");
            }
        }
        }
        finally
        {
            await ProbeNavigationRestore.TryRestoreAsync(_ctx, baselineUrl);
        }

        sw.Stop();
        var findingCount = findings.Count;
        return new CstiScanBatchResult
        {
            Message = findingCount > 0
                ? $"{findingCount} CSTI finding(s) across {candidates.Count} candidate(s)."
                : $"No CSTI indicators across {candidates.Count} candidate(s).",
            CandidatesProbed = candidates.Count,
            EnginesTested = engines.Select(CstiProbes.EngineName).ToList(),
            Probes = probes,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private async Task<List<CstiCandidate>> BuildCandidatesAsync(
        CstiScanOptions options,
        string currentUrl,
        Uri currentUri,
        List<CstiProbes.Source> sources,
        CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(options.Url) && !string.IsNullOrWhiteSpace(options.ParamName))
        {
            if (!CstiCandidateDiscovery.IsProbeableParam(options.ParamName))
                return [];

            var baseUrl = CstiCandidateDiscovery.CandidateBaseUrl(options.Url);
            var list = new List<CstiCandidate>();
            foreach (var source in sources)
            {
                list.Add(new CstiCandidate
                {
                    BaseUrl = baseUrl,
                    ParamName = options.ParamName!,
                    Source = source,
                    Discovery = "explicit"
                });
            }
            return list;
        }

        var explicitUrl = !string.IsNullOrWhiteSpace(options.Url);
        var discoveryUrl = explicitUrl ? options.Url! : currentUrl;
        if (!Uri.TryCreate(discoveryUrl, UriKind.Absolute, out var discoveryUri))
            discoveryUri = currentUri;

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 10;
        var origin = discoveryUri.GetLeftPart(UriPartial.Authority);
        var pageBase = CstiCandidateDiscovery.CandidateBaseUrl(discoveryUrl);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var candidates = new List<CstiCandidate>();

        void TryAdd(string url, string paramName, CstiProbes.Source source, string discovery)
        {
            if (!CstiCandidateDiscovery.IsProbeableParam(paramName)) return;

            var baseUrl = CstiCandidateDiscovery.CandidateBaseUrl(url);
            var key = CstiCandidateDiscovery.CandidateKey(baseUrl, paramName, source);
            if (!seen.Add(key)) return;

            candidates.Add(new CstiCandidate
            {
                BaseUrl = baseUrl,
                ParamName = paramName,
                Source = source,
                Discovery = discovery
            });
        }

        static void AddQueryParamsFromUri(Uri uri, Action<string> addParam)
        {
            foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = pair.IndexOf('=');
                if (eq <= 0) continue;
                addParam(Uri.UnescapeDataString(pair[..eq]));
            }
        }

        if (sources.Contains(CstiProbes.Source.UrlQuery))
        {
            AddQueryParamsFromUri(discoveryUri,
                name => TryAdd(pageBase, name, CstiProbes.Source.UrlQuery, explicitUrl ? "url-query" : "current-url-query"));
            AddHashRouterQueryParams(discoveryUri,
                (name, src) => TryAdd(pageBase, name, src, "hash-route-query"));
            foreach (var name in DiscoverTemplateParamNamesFromLinks(discoveryUri, pageBase))
                TryAdd(pageBase, name, CstiProbes.Source.UrlQuery, "dom-href-query");
            if (candidates.Count >= max) return PrioritizeCstiCandidates(candidates, max);

            // Network-log discovery only when no explicit target URL — avoids probing unrelated pages from history.
            if (!explicitUrl)
            {
                foreach (var entry in _ctx.Network.Entries)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
                    if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                        continue;

                    AddQueryParamsFromUri(uri,
                        name => TryAdd(CstiCandidateDiscovery.CandidateBaseUrl(entry.Url), name, CstiProbes.Source.UrlQuery, "network-log"));
                    if (candidates.Count >= max) return PrioritizeCstiCandidates(candidates, max);
                }
            }
        }

        if (sources.Contains(CstiProbes.Source.UrlQuery) || sources.Contains(CstiProbes.Source.UrlHash))
        {
            await _ctx.Navigate(pageBase);
            await Task.Delay(300, ct);
            foreach (var name in await DiscoverQueryParamsFromDomLinksAsync())
            {
                TryAdd(pageBase, name, CstiProbes.Source.UrlQuery, "dom-href-query");
                if (candidates.Count >= max) return PrioritizeCstiCandidates(candidates, max);
            }

            var discovered = await DomUrlParamDiscovery.DiscoverAsync(_ctx);
            if (discovered != null)
            {
                if (!string.IsNullOrEmpty(discovered.PreferredQueryParam))
                    TryAdd(pageBase, discovered.PreferredQueryParam, CstiProbes.Source.UrlQuery, "dom-script-query");
                if (!string.IsNullOrEmpty(discovered.PreferredHashParam))
                    TryAdd(pageBase, discovered.PreferredHashParam, CstiProbes.Source.UrlHash, "dom-script-hash");

                foreach (var name in discovered.ParamNames)
                {
                    var src = sources.Contains(CstiProbes.Source.UrlQuery)
                        ? CstiProbes.Source.UrlQuery
                        : CstiProbes.Source.UrlHash;
                    TryAdd(pageBase, name, src, "dom-script");
                    if (candidates.Count >= max) return PrioritizeCstiCandidates(candidates, max);
                }
            }

            foreach (var name in CstiCandidateDiscovery.CstiTemplateParamNames.Default)
                TryAdd(pageBase, name, CstiProbes.Source.UrlQuery, "template-param-heuristic");
            if (candidates.Count >= max) return PrioritizeCstiCandidates(candidates, max);
        }

        if (sources.Contains(CstiProbes.Source.UrlQuery) && candidates.Count < max)
        {
            var formNames = await DiscoverFormFieldNamesAsync();
            foreach (var name in formNames)
            {
                TryAdd(pageBase, name, CstiProbes.Source.UrlQuery, "form-field");
                if (candidates.Count >= max) return PrioritizeCstiCandidates(candidates, max);
            }
        }

        if (candidates.Count == 0)
            TryAdd(pageBase, "q", CstiProbes.Source.UrlQuery, "default");

        return PrioritizeCstiCandidates(candidates, max);
    }

    private static List<CstiCandidate> PrioritizeCstiCandidates(List<CstiCandidate> candidates, int max)
    {
        static int Rank(CstiCandidate c) => c.Discovery switch
        {
            "explicit" => 120,
            "current-url-query" => 110,
            "url-query" => 105,
            "dom-script-query" => 100,
            "dom-href-query" => 95,
            "dom-script-hash" => 90,
            "dom-script" => 85,
            "template-param-heuristic" => 80,
            "network-log" => 70,
            "form-field" => 50,
            "default" => 10,
            _ => 40
        };

        return candidates
            .OrderByDescending(Rank)
            .ThenBy(c => c.ParamName, StringComparer.OrdinalIgnoreCase)
            .Take(max)
            .ToList();
    }

    private static IEnumerable<string> DiscoverTemplateParamNamesFromLinks(Uri pageUri, string pageBase)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!Uri.TryCreate(pageBase, UriKind.Absolute, out var baseUri))
            yield break;

        foreach (var name in CstiCandidateDiscovery.CstiTemplateParamNames.Default)
        {
            if (names.Add(name))
                yield return name;
        }

        foreach (var part in pageUri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var key = Uri.UnescapeDataString(part[..eq]);
            if (key.Length > 0 && key.Length <= 64 && names.Add(key))
                yield return key;
        }
    }

    private static void AddHashRouterQueryParams(Uri discoveryUri, Action<string, CstiProbes.Source> tryAdd)
    {
        var frag = discoveryUri.Fragment;
        if (string.IsNullOrEmpty(frag)
            || !(frag.StartsWith("#/", StringComparison.Ordinal) || frag.StartsWith("#!/", StringComparison.Ordinal)))
            return;

        var route = frag.TrimStart('#');
        if (route.StartsWith('!')) route = route[1..];
        var qIdx = route.IndexOf('?', StringComparison.Ordinal);
        if (qIdx >= 0)
        {
            foreach (var pair in route[(qIdx + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = pair.IndexOf('=');
                var name = eq > 0 ? Uri.UnescapeDataString(pair[..eq]) : Uri.UnescapeDataString(pair);
                if (name.Length > 0)
                    tryAdd(name, CstiProbes.Source.UrlHash);
            }
        }

        if (route.Contains("search", StringComparison.OrdinalIgnoreCase))
            tryAdd("q", CstiProbes.Source.UrlHash);
        if (route.Contains("blog", StringComparison.OrdinalIgnoreCase))
            tryAdd("post", CstiProbes.Source.UrlHash);
    }

    private async Task<List<string>> DiscoverQueryParamsFromDomLinksAsync()
    {
        try
        {
            var json = await _ctx.ExecuteJs(
                """
                (function(){
                    var names = [];
                    document.querySelectorAll('a[href*="?"]').forEach(function(a){
                        try {
                            var u = new URL(a.href, location.href);
                            u.searchParams.forEach(function(v,k){
                                if (names.indexOf(k) < 0) names.push(k);
                            });
                        } catch(e) {}
                    });
                    return JSON.stringify(names);
                })()
                """);
            var s = json.Trim();
            if (s.Length >= 2 && s[0] == '"')
                s = JsonSerializer.Deserialize<string>(s) ?? "[]";
            using var doc = JsonDocument.Parse(s);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return [];
            return doc.RootElement.EnumerateArray()
                .Select(e => e.GetString() ?? "")
                .Where(n => n.Length > 0 && CstiCandidateDiscovery.IsProbeableParam(n))
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private async Task<List<string>> DiscoverFormFieldNamesAsync()
    {
        try
        {
            var json = await _ctx.ExecuteJs(
                """
                (function(){
                    var names = [];
                    document.querySelectorAll('input[name], textarea[name]').forEach(function(el){
                        var n = el.getAttribute('name');
                        if (n && names.indexOf(n) < 0) names.push(n);
                    });
                    return JSON.stringify(names);
                })()
                """);
            var s = json.Trim();
            if (s.Length >= 2 && s[0] == '"')
                s = JsonSerializer.Deserialize<string>(s) ?? "[]";
            using var doc = JsonDocument.Parse(s);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return [];
            return doc.RootElement.EnumerateArray()
                .Select(e => e.GetString() ?? "")
                .Where(n => n.Length > 0)
                .ToList();
        }
        catch
        {
            return [];
        }
    }
}
