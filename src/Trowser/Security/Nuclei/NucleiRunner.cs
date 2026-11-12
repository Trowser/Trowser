using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;

namespace Trowser.Security.Nuclei;

/// <summary>
/// Native runner for a curated embedded subset of nuclei HTTP templates (status/word/regex/header matchers only).
/// </summary>
public static class NucleiRunner
{
    private const string ResourcePrefix = "Trowser.Resources.nuclei.";

    private static readonly Lazy<EmbeddedLoad> Embedded = new(LoadEmbeddedTemplates);

    // Nuclei matchers frequently assert on redirect status + Location header, so by default we do NOT
    // follow redirects (a following client would only ever see the final 200). A separate following
    // client is used when the caller explicitly opts in.
    private static readonly HttpClient HttpNoRedirect = CreateHttpClient(followRedirects: false);
    private static readonly HttpClient HttpFollowRedirect = CreateHttpClient(followRedirects: true);

    public sealed class NucleiScanOptions
    {
        public string TargetUrl { get; init; } = "";

        /// <summary>Optional additional base URLs to scan. Merged with <see cref="TargetUrl"/> (deduped).</summary>
        public IReadOnlyList<string>? TargetUrls { get; init; }

        public IReadOnlyList<string>? Tags { get; init; }
        public string? MinSeverity { get; init; }
        public int MaxTemplates { get; set; } = 50;
        public int TimeoutMs { get; set; } = 10_000;
        public SafetyMode SafetyMode { get; set; } = SafetyMode.Safe;
        public bool RegisterChainFindings { get; set; } = true;

        /// <summary>
        /// Optional directory of user-supplied *.yaml templates to load in addition to (or instead of)
        /// the embedded subset. Falls back to <c>%TROWSER_NUCLEI_TEMPLATES%</c> or a <c>nuclei-templates/</c>
        /// folder beside the exe when not set.
        /// </summary>
        public string? TemplatesDir { get; init; }

        /// <summary>When false, only user templates (from <see cref="TemplatesDir"/> / convention) run.</summary>
        public bool IncludeBuiltinTemplates { get; init; } = true;

        /// <summary>Follow HTTP redirects. Default false so redirect/Location matchers work.</summary>
        public bool FollowRedirects { get; init; }

        /// <summary>Resolve/select templates but send no HTTP. Used for previewing what would run.</summary>
        public bool DryRun { get; init; }

        /// <summary>Record a per-template/URL trace (status + matcher pass/fail) for debugging.</summary>
        public bool VerboseTemplateTrace { get; init; }

        /// <summary>Attach the WebView2 cookie jar to each probe (default true).</summary>
        public bool IncludeBrowserCookies { get; init; } = true;
    }

    public sealed class NucleiFinding
    {
        public string TemplateId { get; init; } = "";
        public string TemplateName { get; init; } = "";
        public string Severity { get; init; } = "info";
        public string Category { get; init; } = "nuclei-match";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public int StatusCode { get; init; }
        public string? Detail { get; init; }
        public List<string> Tags { get; init; } = [];

        /// <summary>Stable common alias (== <see cref="TemplateName"/>) shared across scanners.</summary>
        public string Title => TemplateName;

        /// <summary>Stable common alias (== <see cref="Detail"/>) shared across scanners.</summary>
        public string Description => Detail ?? "";
    }

    /// <summary>A template that was present but could not be run (unsupported DSL, parse error, …).</summary>
    public sealed record SkippedTemplate(string Id, string Reason, string Source);

    /// <summary>Inventory row describing a runnable template without executing it.</summary>
    public sealed record TemplateInfo(
        string Id, string Name, string Severity, List<string> Tags, List<string> Methods, string Source);

    /// <summary>One row of the optional verbose per-template execution trace.</summary>
    public sealed record TemplateTraceEntry(
        string TemplateId, string Url, string Method, int StatusCode, bool Matched, bool Requested);

    private sealed record EmbeddedLoad(List<NucleiTemplate> Templates, List<SkippedTemplate> Skipped);

    /// <summary>Templates + skip reasons after loading embedded (optional) and user-dir templates.</summary>
    public sealed record TemplateLoad(List<NucleiTemplate> Templates, List<SkippedTemplate> Skipped);

    public sealed class NucleiScanResult
    {
        public string TargetUrl { get; init; } = "";

        /// <summary>All base URLs that were scanned.</summary>
        public List<string> TargetUrls { get; init; } = [];

        /// <summary>Total templates embedded in the build.</summary>
        public int TemplatesLoaded { get; init; }

        /// <summary>Templates selected to run after tag / severity / maxTemplates filtering.</summary>
        public int TemplatesSelected { get; init; }

        /// <summary>Number of individual HTTP requests actually sent (one per template path).</summary>
        public int TemplatesRun { get; init; }

        /// <summary>Loaded templates filtered out by tag/severity/max (TemplatesLoaded - TemplatesSelected).</summary>
        public int TemplatesFilteredOut { get; init; }

        /// <summary>Back-compat alias of <see cref="TemplatesFilteredOut"/>.</summary>
        public int TemplatesSkipped => TemplatesFilteredOut;

        /// <summary>IDs of the templates actually selected to run (present even when findingCount=0).</summary>
        public List<string> SelectedTemplateIds { get; init; } = [];

        /// <summary>IDs of templates that produced at least one finding.</summary>
        public List<string> MatchedTemplateIds { get; init; } = [];

        /// <summary>Templates present but not runnable (unsupported DSL / parse error), with reasons.</summary>
        public List<SkippedTemplate> SkippedTemplates { get; init; } = [];

        /// <summary>Optional per-template execution trace (populated when verboseTemplateTrace is set).</summary>
        public List<TemplateTraceEntry> TemplateTrace { get; init; } = [];

        /// <summary>True when the scan only resolved templates and sent no HTTP.</summary>
        public bool DryRun { get; init; }

        /// <summary>HTTP requests that would be / were sent (paths × payload expansions × targets).</summary>
        public int EstimatedHttpRequests { get; init; }

        public bool IncludeBrowserCookies { get; init; }

        public NucleiCompatibilitySummary? CompatibilitySummary { get; init; }

        public List<string> Summary { get; init; } = [];
        public List<NucleiFinding> Findings { get; init; } = [];

        public bool IsClean => Findings.Count == 0;

        public List<NucleiFinding> GetByMinSeverity(string minSeverity)
        {
            var minRank = SeverityRank(minSeverity);
            return Findings.Where(f => SeverityRank(f.Severity) >= minRank).ToList();
        }

        public string Format(bool includeDetails = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== Nuclei Template Scan ===");
            if (TargetUrls.Count > 1)
                sb.AppendLine($"Targets ({TargetUrls.Count}): {string.Join(", ", TargetUrls)}");
            else
                sb.AppendLine($"Target: {TargetUrl}");
            var runLabel = DryRun ? "dry run (no HTTP sent)" : $"{TemplatesRun} HTTP request(s) sent";
            sb.AppendLine($"Templates: {TemplatesLoaded} loaded, {TemplatesSelected} selected, {runLabel}");
            sb.AppendLine($"Findings: {Findings.Count}");
            if (SkippedTemplates.Count > 0)
                sb.AppendLine($"Skipped (unsupported): {SkippedTemplates.Count} — {string.Join("; ", SkippedTemplates.Select(s => $"{s.Id} ({s.Reason})"))}");
            sb.AppendLine();

            foreach (var line in Summary)
                sb.AppendLine(line);
            sb.AppendLine();

            if (DryRun)
            {
                sb.AppendLine($"Selected templates: {string.Join(", ", SelectedTemplateIds)}");
                return sb.ToString().TrimEnd();
            }

            if (Findings.Count == 0)
            {
                sb.AppendLine("No template matches.");
                return sb.ToString().TrimEnd();
            }

            if (!includeDetails)
                return sb.ToString().TrimEnd();

            foreach (var f in Findings.OrderByDescending(x => SeverityRank(x.Severity)).ThenBy(x => x.TemplateId))
            {
                sb.AppendLine($"--- [{f.Severity.ToUpperInvariant()}] {f.TemplateName} ({f.TemplateId}) ---");
                sb.AppendLine($"  {f.Method} {f.Url} -> HTTP {f.StatusCode}");
                if (!string.IsNullOrEmpty(f.Detail))
                    sb.AppendLine($"  {f.Detail}");
                if (f.Tags.Count > 0)
                    sb.AppendLine($"  tags: {string.Join(", ", f.Tags)}");
                sb.AppendLine();
            }

            return sb.ToString().TrimEnd();
        }
    }

    /// <summary>
    /// Full candidate template pool before tag/severity/max filtering: embedded subset (when
    /// <paramref name="includeBuiltin"/>) plus any user templates from <paramref name="templatesDir"/>
    /// (or the <c>TROWSER_NUCLEI_TEMPLATES</c> / beside-exe <c>nuclei-templates/</c> convention).
    /// </summary>
    public static IReadOnlyList<NucleiTemplate> GetAllTemplates(
        string? templatesDir = null,
        bool includeBuiltin = true)
        => GetAllTemplatesDetailed(templatesDir, includeBuiltin).Templates;

    /// <summary>Load the candidate pool plus per-file skip reasons (embedded + optional user dir).</summary>
    public static TemplateLoad GetAllTemplatesDetailed(
        string? templatesDir = null,
        bool includeBuiltin = true)
    {
        var pool = new List<NucleiTemplate>();
        var skipped = new List<SkippedTemplate>();

        if (includeBuiltin)
        {
            pool.AddRange(Embedded.Value.Templates);
            skipped.AddRange(Embedded.Value.Skipped);
        }

        var dir = ResolveTemplatesDir(templatesDir);
        if (dir != null)
        {
            var (userTemplates, userSkipped) = LoadTemplatesFromDirectory(dir);
            pool.AddRange(userTemplates);
            skipped.AddRange(userSkipped);
        }

        return new TemplateLoad(pool, skipped);
    }

    /// <summary>Inventory of runnable templates (id/name/severity/tags/methods/source), no HTTP.</summary>
    public static List<TemplateInfo> GetTemplateInventory(
        string? templatesDir = null,
        bool includeBuiltin = true)
        => GetAllTemplatesDetailed(templatesDir, includeBuiltin).Templates
            .Select(t => new TemplateInfo(
                t.Id, t.Name, t.Severity, t.Tags,
                t.HttpRequests.Select(r => r.Method).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                t.Source))
            .ToList();

    /// <summary>Distinct tags present across the (embedded + user) template pool, with counts.</summary>
    public static List<(string Tag, int Count)> GetTagCatalog(
        string? templatesDir = null,
        bool includeBuiltin = true)
        => GetAllTemplates(templatesDir, includeBuiltin)
            .SelectMany(t => t.Tags)
            .GroupBy(t => t, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => (g.Key, g.Count()))
            .ToList();

    public static NucleiCompatibilitySummary GetCompatibilitySummary(
        string? templatesDir = null,
        bool includeBuiltin = true)
        => NucleiCompatibilitySummary.FromLoad(GetAllTemplatesDetailed(templatesDir, includeBuiltin));

    public static int CountExpandedRequests(NucleiTemplate template)
        => template.HttpRequests.Sum(CountExpandedPathsForRequest);

    public static int EstimateHttpRequests(
        IReadOnlyList<NucleiTemplate> templates,
        int targetCount)
        => templates.Sum(CountExpandedRequests) * Math.Max(1, targetCount);

    public static IReadOnlyList<NucleiTemplate> LoadTemplates(
        IReadOnlyList<string>? tags = null,
        string? minSeverity = null,
        int maxTemplates = 50,
        string? templatesDir = null,
        bool includeBuiltin = true)
        => FilterTemplates(GetAllTemplates(templatesDir, includeBuiltin), tags, minSeverity, maxTemplates);

    private static IReadOnlyList<NucleiTemplate> FilterTemplates(
        IReadOnlyList<NucleiTemplate> pool,
        IReadOnlyList<string>? tags,
        string? minSeverity,
        int maxTemplates)
    {
        maxTemplates = Math.Clamp(maxTemplates, 1, 500);
        var minRank = string.IsNullOrWhiteSpace(minSeverity) ? 0 : SeverityRank(minSeverity);
        var tagSet = tags is { Count: > 0 }
            ? new HashSet<string>(tags.Where(t => !string.IsNullOrWhiteSpace(t)), StringComparer.OrdinalIgnoreCase)
            : null;

        IEnumerable<NucleiTemplate> q = pool;

        if (tagSet != null)
            q = q.Where(t => t.Tags.Any(tag => tagSet.Contains(tag)));

        if (minRank > 0)
            q = q.Where(t => SeverityRank(t.Severity) >= minRank);

        return q.Take(maxTemplates).ToList();
    }

    /// <summary>
    /// Resolve the user templates directory: explicit path &gt; <c>%TROWSER_NUCLEI_TEMPLATES%</c> &gt;
    /// <c>nuclei-templates/</c> beside the exe. Returns null when none exist.
    /// </summary>
    private static string? ResolveTemplatesDir(string? explicitDir)
    {
        if (!string.IsNullOrWhiteSpace(explicitDir) && Directory.Exists(explicitDir))
            return explicitDir;

        var env = Environment.GetEnvironmentVariable("TROWSER_NUCLEI_TEMPLATES");
        if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env))
            return env;

        var exeDir = Path.GetDirectoryName(Environment.ProcessPath);
        if (!string.IsNullOrEmpty(exeDir))
        {
            var beside = Path.Combine(exeDir, "nuclei-templates");
            if (Directory.Exists(beside)) return beside;
        }

        return null;
    }

    private static (List<NucleiTemplate> Templates, List<SkippedTemplate> Skipped) LoadTemplatesFromDirectory(string dir)
    {
        var templates = new List<NucleiTemplate>();
        var skipped = new List<SkippedTemplate>();
        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.yaml", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(dir, "*.yml", SearchOption.AllDirectories))
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            skipped.Add(new SkippedTemplate(dir, $"could not enumerate directory: {ex.Message}", "user"));
            return (templates, skipped);
        }

        foreach (var file in files)
        {
            var id = Path.GetFileName(file);
            try
            {
                var yaml = File.ReadAllText(file);
                if (NucleiTemplateParser.TryParse(yaml, out var template, out var reason, file) && template != null)
                {
                    template.Source = "user";
                    templates.Add(template);
                }
                else
                {
                    skipped.Add(new SkippedTemplate(id, reason ?? "unsupported template", "user"));
                }
            }
            catch (Exception ex)
            {
                skipped.Add(new SkippedTemplate(id, $"read error: {ex.Message}", "user"));
            }
        }

        return (templates, skipped);
    }

    public static bool SelectedTemplatesRequireWriteVerbs(IReadOnlyList<NucleiTemplate> templates) =>
        templates.Any(t => t.HttpRequests.Any(r => !IsReadOnlyMethod(r.Method)));

    public static async Task<NucleiScanResult> RunAsync(
        NucleiScanOptions options,
        AutomationContext? ctx = null,
        CancellationToken ct = default)
    {
        // Collect target URLs (single + list), dedupe, validate.
        var rawUrls = new List<string>();
        if (!string.IsNullOrWhiteSpace(options.TargetUrl)) rawUrls.Add(options.TargetUrl);
        if (options.TargetUrls != null) rawUrls.AddRange(options.TargetUrls.Where(u => !string.IsNullOrWhiteSpace(u)));

        var targets = new List<Uri>();
        var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in rawUrls)
        {
            if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri))
                throw new InvalidOperationException($"Invalid target URL: {raw}");
            if (seenTargets.Add(uri.AbsoluteUri))
                targets.Add(uri);
        }

        if (targets.Count == 0)
            throw new InvalidOperationException("At least one targetUrl (or targetUrls) is required.");

        var load = GetAllTemplatesDetailed(options.TemplatesDir, options.IncludeBuiltinTemplates);
        var compatibility = NucleiCompatibilitySummary.FromLoad(load);
        var pool = load.Templates;
        var templates = FilterTemplates(pool, options.Tags, options.MinSeverity, options.MaxTemplates);
        var selectedIds = templates.Select(t => t.Id).Distinct(StringComparer.Ordinal).ToList();
        var estimatedRequests = EstimateHttpRequests(templates, targets.Count);

        // Dry run: report the selection without sending any HTTP (allowed in any safety mode).
        if (options.DryRun)
        {
            var dryScope = targets.Count > 1 ? $" across {targets.Count} URLs" : "";
            return new NucleiScanResult
            {
                TargetUrl = targets[0].AbsoluteUri,
                TargetUrls = targets.Select(t => t.AbsoluteUri).ToList(),
                TemplatesLoaded = pool.Count,
                TemplatesSelected = templates.Count,
                TemplatesRun = 0,
                TemplatesFilteredOut = pool.Count - templates.Count,
                SelectedTemplateIds = selectedIds,
                SkippedTemplates = load.Skipped,
                DryRun = true,
                EstimatedHttpRequests = estimatedRequests,
                IncludeBrowserCookies = options.IncludeBrowserCookies,
                CompatibilitySummary = compatibility,
                Summary =
                [
                    $"Dry run: {templates.Count} template(s) would run{dryScope} (~{estimatedRequests} HTTP request(s), no traffic sent)."
                ]
            };
        }

        if (!options.SafetyMode.AllowsProbes())
            throw new InvalidOperationException("Nuclei scan requires safetyMode 'safe' or higher (passive blocks outbound probes).");

        var findings = new List<NucleiFinding>();
        var summary = new List<string>();
        var trace = new List<TemplateTraceEntry>();
        var matchedIds = new HashSet<string>(StringComparer.Ordinal);
        var runCount = 0;
        var skipNoted = new HashSet<string>(StringComparer.Ordinal);

        foreach (var targetUri in targets)
        {
            var vars = NucleiTargetVariables.FromUri(targetUri);

            foreach (var template in templates)
            {
                ct.ThrowIfCancellationRequested();

                foreach (var request in template.HttpRequests)
                {
                    if (!IsMethodAllowed(request.Method, options.SafetyMode))
                    {
                        if (skipNoted.Add(template.Id))
                            summary.Add($"Skipped {template.Id}: {request.Method} requires safetyMode active or aggressive.");
                        continue;
                    }

                    foreach (var url in ExpandRequestUrls(request, vars))
                    {
                        runCount++;
                        var response = await SendAsync(
                            url,
                            request,
                            vars,
                            options.TimeoutMs,
                            options.FollowRedirects,
                            options.IncludeBrowserCookies,
                            ctx,
                            ct);
                        if (response == null)
                        {
                            if (options.VerboseTemplateTrace)
                                trace.Add(new TemplateTraceEntry(template.Id, url, request.Method, 0, false, false));
                            continue;
                        }

                        var matched = EvaluateMatchers(request, response);
                        if (options.VerboseTemplateTrace)
                            trace.Add(new TemplateTraceEntry(
                                template.Id, url, request.Method, (int)response.StatusCode, matched, true));

                        if (!matched)
                            continue;

                        matchedIds.Add(template.Id);
                        findings.Add(new NucleiFinding
                        {
                            TemplateId = template.Id,
                            TemplateName = template.Name,
                            Severity = template.Severity,
                            Category = MapCategory(template),
                            Url = url,
                            Method = request.Method,
                            StatusCode = (int)response.StatusCode,
                            Detail = template.Description.Length > 0
                                ? template.Description
                                : $"Template matchers satisfied for {template.Name}.",
                            Tags = template.Tags
                        });

                        if (request.StopAtFirstMatch)
                            break;
                    }
                }
            }
        }

        var scope = targets.Count > 1 ? $" across {targets.Count} URLs" : "";
        if (findings.Count == 0)
            summary.Insert(0, $"No nuclei template matches on target{(targets.Count > 1 ? "s" : "")}.");
        else
            summary.Insert(0, $"{findings.Count} template match(es){scope} — review exposed paths and misconfigurations.");

        if (options.RegisterChainFindings && ctx != null)
            RegisterFindingsForChain(ctx, findings);

        return new NucleiScanResult
        {
            TargetUrl = targets[0].AbsoluteUri,
            TargetUrls = targets.Select(t => t.AbsoluteUri).ToList(),
            TemplatesLoaded = pool.Count,
            TemplatesSelected = templates.Count,
            TemplatesRun = runCount,
            TemplatesFilteredOut = pool.Count - templates.Count,
            SelectedTemplateIds = selectedIds,
            MatchedTemplateIds = matchedIds.ToList(),
            SkippedTemplates = load.Skipped,
            TemplateTrace = trace,
            EstimatedHttpRequests = runCount,
            IncludeBrowserCookies = options.IncludeBrowserCookies,
            CompatibilitySummary = compatibility,
            Summary = summary,
            Findings = findings
        };
    }

    private static int CountExpandedPathsForRequest(NucleiHttpRequest request)
    {
        var perPath = request.PathPayloadValues.Count > 0 ? request.PathPayloadValues.Count : 1;
        return request.Paths.Count * perPath;
    }

    private static IEnumerable<string> ExpandRequestUrls(NucleiHttpRequest request, NucleiTargetVariables vars)
    {
        foreach (var pathTemplate in request.Paths)
        {
            if (request.PathPayloadValues.Count > 0)
            {
                foreach (var segment in request.PathPayloadValues)
                {
                    var url = vars.Apply(pathTemplate, segment);
                    if (Uri.TryCreate(url, UriKind.Absolute, out _))
                        yield return url;
                }
            }
            else
            {
                var url = vars.Apply(pathTemplate);
                if (Uri.TryCreate(url, UriKind.Absolute, out _))
                    yield return url;
            }
        }
    }

    private static HttpClient CreateHttpClient(bool followRedirects)
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            AllowAutoRedirect = followRedirects,
            AutomaticDecompression = DecompressionMethods.All
        };
        var client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "Trowser-Nuclei/1.0");
        return client;
    }

    private static EmbeddedLoad LoadEmbeddedTemplates()
    {
        var asm = typeof(NucleiRunner).Assembly;
        var names = asm.GetManifestResourceNames()
            .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal) && n.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var templates = new List<NucleiTemplate>();
        var skipped = new List<SkippedTemplate>();
        foreach (var name in names)
        {
            var id = name.Length > ResourcePrefix.Length ? name[ResourcePrefix.Length..] : name;
            using var stream = asm.GetManifestResourceStream(name);
            if (stream == null) continue;
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var yaml = reader.ReadToEnd();
            if (NucleiTemplateParser.TryParse(yaml, out var template, out var reason) && template != null)
                templates.Add(template);
            else
                skipped.Add(new SkippedTemplate(id, reason ?? "unsupported template", "embedded"));
        }

        return new EmbeddedLoad(templates, skipped);
    }

    private static bool IsReadOnlyMethod(string method)
    {
        var m = method.Trim().ToUpperInvariant();
        return m is "GET" or "HEAD" or "OPTIONS";
    }

    private static bool IsMethodAllowed(string method, SafetyMode mode)
    {
        if (!mode.AllowsProbes()) return false;
        return IsReadOnlyMethod(method) || mode.AllowsWriteVerbs();
    }

    private sealed class HttpProbeResponse
    {
        public HttpStatusCode StatusCode { get; init; }
        public string Body { get; init; } = "";
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<HttpProbeResponse?> SendAsync(
        string url,
        NucleiHttpRequest request,
        NucleiTargetVariables vars,
        int timeoutMs,
        bool followRedirects,
        bool includeBrowserCookies,
        AutomationContext? ctx,
        CancellationToken ct)
    {
        var headers = new Dictionary<string, string>(request.Headers, StringComparer.OrdinalIgnoreCase);
        headers.TryAdd("User-Agent", "Trowser-Nuclei/1.0");
        foreach (var key in headers.Keys.ToList())
            headers[key] = vars.Apply(headers[key]);

        var body = string.IsNullOrEmpty(request.Body) ? null : vars.Apply(request.Body);
        var timeout = Math.Clamp(timeoutMs, 1000, 120_000);

        if (ctx != null)
        {
            try
            {
                var direct = await DirectFetchHelper.FetchAsync(
                    ctx,
                    url,
                    request.Method,
                    headers,
                    body,
                    timeout,
                    followRedirects,
                    includeBrowserCookies);
                if (!string.IsNullOrEmpty(direct.Error))
                    return null;

                return new HttpProbeResponse
                {
                    StatusCode = (HttpStatusCode)direct.Status,
                    Body = direct.Body,
                    Headers = direct.Headers
                };
            }
            catch
            {
                return null;
            }
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        try
        {
            using var msg = new HttpRequestMessage(new HttpMethod(request.Method), url);
            if (!string.IsNullOrEmpty(body)
                && request.Method is not "GET" and not "HEAD")
                msg.Content = new StringContent(body, Encoding.UTF8);

            foreach (var (key, value) in headers)
                msg.Headers.TryAddWithoutValidation(key, value);

            var client = followRedirects ? HttpFollowRedirect : HttpNoRedirect;
            using var response = await client.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            var responseBody = await SecurityProbeHttp.ReadBodyCappedAsync(response, 2_000_000, cts.Token);
            var responseHeaders = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
            foreach (var h in response.Content.Headers)
                responseHeaders[h.Key] = string.Join(", ", h.Value);

            return new HttpProbeResponse
            {
                StatusCode = response.StatusCode,
                Body = responseBody,
                Headers = responseHeaders
            };
        }
        catch
        {
            return null;
        }
    }

    private static bool EvaluateMatchers(NucleiHttpRequest request, HttpProbeResponse response)
    {
        if (request.Matchers.Count == 0) return false;

        var results = request.Matchers.Select(m => EvaluateMatcher(m, response)).ToList();
        var condition = request.MatchersCondition.Equals("or", StringComparison.OrdinalIgnoreCase);
        return condition ? results.Any(x => x) : results.All(x => x);
    }

    private static bool EvaluateMatcher(NucleiMatcher matcher, HttpProbeResponse response)
    {
        var matched = matcher.Type switch
        {
            "status" => matcher.Status.Contains((int)response.StatusCode),
            "word" => EvaluateWords(matcher, response),
            "regex" => EvaluateRegex(matcher, response),
            "header" => EvaluateHeaderMatcher(matcher, response),
            _ => false
        };

        return matcher.Negative ? !matched : matched;
    }

    private static bool EvaluateWords(NucleiMatcher matcher, HttpProbeResponse response)
    {
        if (matcher.Words.Count == 0) return false;
        var haystack = GetPartText(matcher.Part, response);
        var checks = matcher.Words.Select(w =>
            haystack.Contains(w, StringComparison.OrdinalIgnoreCase)).ToList();
        return matcher.Condition.Equals("and", StringComparison.OrdinalIgnoreCase)
            ? checks.All(x => x)
            : checks.Any(x => x);
    }

    private static bool EvaluateRegex(NucleiMatcher matcher, HttpProbeResponse response)
    {
        if (matcher.Regex.Count == 0) return false;
        var haystack = GetPartText(matcher.Part, response);
        var checks = matcher.Regex.Select(pattern =>
        {
            try
            {
                return Regex.IsMatch(haystack, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));
            }
            catch
            {
                return false;
            }
        }).ToList();

        return matcher.Condition.Equals("and", StringComparison.OrdinalIgnoreCase)
            ? checks.All(x => x)
            : checks.Any(x => x);
    }

    private static bool EvaluateHeaderMatcher(NucleiMatcher matcher, HttpProbeResponse response)
    {
        var headerBlob = GetPartText("header", response);
        var entries = matcher.Headers.Count > 0 ? matcher.Headers : matcher.Words;
        if (entries.Count == 0) return false;

        var checks = entries.Select(entry =>
        {
            var idx = entry.IndexOf(':');
            if (idx <= 0)
                return headerBlob.Contains(entry, StringComparison.OrdinalIgnoreCase);

            var name = entry[..idx].Trim();
            var value = entry[(idx + 1)..].Trim();
            if (!response.Headers.TryGetValue(name, out var actual))
                return false;
            return actual.Contains(value, StringComparison.OrdinalIgnoreCase);
        }).ToList();

        return matcher.Condition.Equals("and", StringComparison.OrdinalIgnoreCase)
            ? checks.All(x => x)
            : checks.Any(x => x);
    }

    private static string GetPartText(string part, HttpProbeResponse response)
    {
        var headerBlob = string.Join("\n", response.Headers.Select(h => $"{h.Key}: {h.Value}"));
        return part switch
        {
            "header" => headerBlob,
            "all" => headerBlob + "\n" + response.Body,
            _ => response.Body
        };
    }

    private static string MapCategory(NucleiTemplate template)
    {
        foreach (var tag in template.Tags)
        {
            var normalized = tag.Trim().ToLowerInvariant();
            if (normalized is "exposure" or "misconfig" or "info-leak" or "config" or "debug" or "panel")
                return "info-leak";
            if (normalized is "spring" or "docker" or "wordpress" or "swagger" or "php")
                return "nuclei-match";
        }

        return "nuclei-match";
    }

    private static void RegisterFindingsForChain(AutomationContext ctx, List<NucleiFinding> findings)
    {
        foreach (var f in findings)
        {
            ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"nuclei-{Math.Abs((f.TemplateId + f.Url).GetHashCode(StringComparison.Ordinal))}",
                Source = "nuclei",
                Category = f.Category,
                Severity = f.Severity,
                Title = f.TemplateName,
                Endpoint = f.Url,
                Method = f.Method,
                Detail = f.Detail,
                Evidence = $"HTTP {f.StatusCode}",
                Tags = f.Tags
            });
        }
    }

    private static int SeverityRank(string severity) =>
        severity.Trim().ToLowerInvariant() switch
        {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0
        };
}
