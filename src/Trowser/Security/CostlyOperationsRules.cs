using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

internal static class CostlyOperationsRules
{
    internal sealed class ScanContext
    {
        public List<NetworkEntry> Entries { get; }
        public AttackSurfaceResult Surface { get; }
        public SpaRuntimeSurface? Spa { get; }
        public string Origin { get; }
        public int SlowThresholdMs { get; }
        public int MaxCandidates { get; }
        public IReadOnlyList<CostlyOperationsSpecAnalyzer.SpecDocument> SpecDocuments { get; }
        public IReadOnlyList<string>? UrlScope { get; }

        public ScanContext(
            List<NetworkEntry> entries,
            AttackSurfaceResult surface,
            SpaRuntimeSurface? spa,
            string origin,
            int slowThresholdMs,
            int maxCandidates,
            IReadOnlyList<CostlyOperationsSpecAnalyzer.SpecDocument>? specDocuments = null,
            IReadOnlyList<string>? urlScope = null)
        {
            Entries = entries;
            Surface = surface;
            Spa = spa;
            Origin = origin;
            SlowThresholdMs = slowThresholdMs;
            MaxCandidates = maxCandidates;
            SpecDocuments = specDocuments ?? [];
            UrlScope = urlScope;
        }
    }

    internal sealed class ConfirmCandidate
    {
        public string Url { get; init; } = "";
        public string BaselineUrl { get; init; } = "";
        public string ProbeUrl { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public string ParamName { get; init; } = "";
        public string BaselineValue { get; init; } = "";
        public string ProbeValue { get; init; } = "";
        public string? Evidence { get; init; }
        /// <summary><c>step</c> raises an existing page-size param. <c>inject</c> adds <c>limit</c> to an unpaged list GET.</summary>
        public string Kind { get; init; } = "step";
        public int? SourceNetworkEntryId { get; init; }
    }

    /// <summary>Parameters that change how many rows one response contains.</summary>
    private static readonly string[] PageSizeParamNames =
    [
        "limit", "pageSize", "pagesize", "page_size", "per_page", "perPage", "size", "count",
        "top", "$top", "take"
    ];

    /// <summary>Parameters that move through a list without changing page size. Not used for page-size confirms.</summary>
    private static readonly string[] OffsetParamNames =
    [
        "offset", "skip", "$skip", "cursor", "pageToken", "page_token", "page"
    ];

    private static readonly string[] CacheBusterParamNames =
    [
        "t", "_", "ts", "timestamp", "cb", "cachebust", "nocache", "_t"
    ];

    private static readonly string[] ListWrapperPropertyNames =
    [
        "items", "results", "data", "records", "hits", "values", "content", "rows", "entries", "nodes", "edges"
    ];

    private static readonly string[] RecipientFieldNames =
    [
        "to", "bcc", "cc", "recipients", "recipient", "emails", "email", "phones", "phoneNumbers", "numbers"
    ];

    private static readonly string[] DateRangeParamNames =
    [
        "from", "to", "start", "end", "startDate", "endDate", "dateFrom", "dateTo", "since", "until"
    ];

    private const int LargeResponseMediumBytes = 32_768;
    private const int LargeResponseHighBytes = 200_000;
    private const int ListSignalFloorBytes = 4_096;
    private const int ListMediumCount = 50;
    private const int ListHighCount = 100;
    private const int MissingPageMinCount = 25;
    private const int EmbeddedPayloadMinChars = 800;

    private static readonly string[] ExpansionParamNames =
    [
        "include", "expand", "fields", "embed", "$expand", "$select", "populate", "relations"
    ];

    private static readonly string[] HeavyPathTokens =
    [
        "export", "download", "report", "dump", "csv", "xlsx", "pdf", "render", "preview",
        "convert", "transcode", "thumbnail", "screenshot", "html-to-pdf"
    ];

    private static readonly string[] UploadPathTokens =
    [
        "upload", "import", "attach", "media", "convert", "thumbnail", "resize"
    ];

    private static readonly string[] BulkPathTokens = ["batch", "bulk", "multi"];

    private static readonly string[] SsrfFetchParams =
    [
        "url", "uri", "src", "source", "callback", "webhook", "redirect", "fetch", "target"
    ];

    private static readonly string[] ImageDimParams = ["width", "height", "w", "h", "scale", "dpi", "quality"];

    private static readonly string[] LlmPathTokens =
    [
        "chat", "completions", "completion", "embed", "embeddings", "prompt", "inference", "generate"
    ];

    private static readonly Regex OpenApiArrayWithoutMaxItems = new(
        @"""type""\s*:\s*""array""(?:(?!""maxItems"").){0,400}?""items""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
        matchTimeout: TimeSpan.FromSeconds(2));

    public static List<NetworkEntry> FilterEntries(
        IReadOnlyList<NetworkEntry> all,
        string origin,
        IReadOnlyList<string>? explicitUrls)
    {
        IEnumerable<NetworkEntry> q = all
            .Where(e => !e.IsTrowserGenerated)
            .Where(e => !AvailabilityDiscovery.IsStaticAsset(e))
            .Where(e => e.StatusCode is > 0 and < 500);

        if (explicitUrls is { Count: > 0 })
        {
            var set = new HashSet<string>(
                explicitUrls.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()),
                StringComparer.OrdinalIgnoreCase);
            q = q.Where(e => set.Any(u => UrlMatchesScope(e.Url, u)));
        }
        else
        {
            q = q.Where(e =>
                Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)
                && string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase));
        }

        return q.OrderBy(e => e.Id).ToList();
    }

    public static string NormalizeUrlKey(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.ToLowerInvariant();
        return $"{uri.AbsolutePath.ToLowerInvariant()}|{uri.Query}";
    }

    public static IEnumerable<CostlyOperationsProbe.CostlyFinding> RunCheck(string checkId, ScanContext ctx)
    {
        return checkId.ToLowerInvariant() switch
        {
            "large-response" => LargeResponse(ctx),
            "pagination" => Pagination(ctx),
            "heavy-route" => HeavyRoute(ctx),
            "slow-sync" => SlowSync(ctx),
            "bulk-input" => BulkInput(ctx),
            "expansion" => Expansion(ctx),
            "upload-surface" => UploadSurface(ctx),
            "traffic-shape" => TrafficShape(ctx),
            "nested-payload" => NestedPayload(ctx),
            "recipient-fanout" => RecipientFanout(ctx),
            "date-range" => DateRange(ctx),
            "filter-depth" => FilterDepth(ctx),
            "spec-limits" => [],
            _ => []
        };
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> LargeResponse(ScanContext ctx)
    {
        const int smallRequestBytes = 8192;
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            var respBytes = EstimateResponseBytes(e);
            var reqBytes = e.RequestBody?.Length ?? 0;
            var (wrapper, listLen) = TryExtractListSize(e.ResponseBody);
            var rootArrayLen = TryJsonArrayLength(e.ResponseBody);
            var effectiveLen = listLen ?? rootArrayLen;

            var nearCaptureCap = e.ResponseBody is { Length: >= 95_000 };
            var sizeHit = respBytes >= LargeResponseMediumBytes
                          || nearCaptureCap
                          || (effectiveLen >= ListHighCount && respBytes >= ListSignalFloorBytes)
                          || (effectiveLen >= ListMediumCount && respBytes >= LargeResponseMediumBytes / 4);
            if (!sizeHit) continue;
            if (reqBytes > smallRequestBytes && respBytes < reqBytes * 3 && effectiveLen == null) continue;

            var severity = respBytes >= LargeResponseHighBytes
                           || nearCaptureCap
                           || (effectiveLen >= ListHighCount && respBytes >= LargeResponseMediumBytes)
                ? "high"
                : "medium";
            var confidence = effectiveLen.HasValue || respBytes >= LargeResponseMediumBytes || nearCaptureCap
                ? "observed"
                : "inferred";
            count++;
            yield return Finding(
                "large-response", "costly-large-response", severity, confidence,
                effectiveLen.HasValue
                    ? $"Large list payload ({wrapper ?? "array"}[{effectiveLen}])"
                    : "Large response relative to small request",
                e, wrapper,
                $"Response ~{respBytes} B (request ~{reqBytes} B)" +
                (effectiveLen.HasValue ? $"; list size {effectiveLen}" : "") +
                (nearCaptureCap ? "; body hit capture cap — may be larger" : "") + ".",
                effectiveLen.HasValue ? $"{wrapper}[{effectiveLen}]" : $"bytes≈{respBytes}",
                "Paginate or stream large collections; cap response size server-side.");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> Pagination(ScanContext ctx)
    {
        var count = 0;
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            var (wrapper, listLen) = TryExtractListSize(e.ResponseBody);
            var rootLen = TryJsonArrayLength(e.ResponseBody);
            var len = listLen ?? rootLen;
            if (len is null or < MissingPageMinCount) continue;

            var respBytes = EstimateResponseBytes(e);
            if (respBytes < ListSignalFloorBytes && len < ListHighCount) continue;

            var mergeKey = AttackSurfaceMapper.EndpointMergeKeyFromUrl(e.Url);
            if (!seenKeys.Add($"{mergeKey}|missing-page")) continue;

            var queryParams = ParseQueryValues(e.Url).Select(kv => kv.Key).ToList();
            var bodyParams = ShallowJsonPropertyNames(e.RequestBody);
            var hasPaging = queryParams.Concat(bodyParams).Any(IsPagingParam);

            if (!hasPaging)
            {
                count++;
                var severity = len >= ListHighCount || respBytes >= LargeResponseMediumBytes ? "high" : "medium";
                yield return Finding(
                    "pagination", "costly-missing-pagination", severity, "observed",
                    "List response without paging parameter in captured request",
                    e, wrapper,
                    $"Returned ~{len} rows/items (~{respBytes} B) with no limit/page/cursor in URL or JSON body.",
                    $"{wrapper ?? "array"}[{len}]",
                    "Require paging (limit/cursor) with a safe default and hard maximum.");
            }
        }

        foreach (var ep in ctx.Surface.Endpoints)
        {
            if (count >= ctx.MaxCandidates) yield break;
            var rep = FindRepresentativeEntry(ctx, ep.Url);
            if (rep == null) continue;

            foreach (var (name, value) in ParseQueryValues(rep.Url).Where(kv => IsPageSizeParam(kv.Key)))
            {
                if (!int.TryParse(value, out var n) || n < 25) continue;
                var sev = n >= 100 ? "high" : "medium";
                var category = n >= 100 ? "costly-unbounded-page" : "costly-page-size-honored";
                count++;
                yield return Finding(
                    "pagination", category, sev, "observed",
                    $"Captured request used a large page size ({name}={n})",
                    rep, name,
                    n >= 100
                        ? $"Server returned 2xx with {name}={n}. Check whether a maximum is enforced above this."
                        : $"Server returned 2xx with {name}={n}. This shows a raised page size, not that no maximum exists.",
                    $"{name}={value}",
                    "Enforce a server-side maximum page size and a safe default.");
            }
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> HeavyRoute(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            var path = uri.AbsolutePath.ToLowerInvariant();
            var pathHit = HeavyPathTokens.Any(t => path.Contains(t, StringComparison.Ordinal));
            var ct = e.ContentType.ToLowerInvariant();
            var typeHit = ct.Contains("csv") || ct.Contains("spreadsheet") || ct.Contains("pdf")
                          || ct.Contains("octet-stream") || ct.Contains("zip");
            var disp = GetHeader(e, "Content-Disposition");
            var dispHit = disp.Contains("attachment", StringComparison.OrdinalIgnoreCase);

            if (!pathHit && !typeHit && !dispHit) continue;
            count++;
            yield return Finding(
                "heavy-route", "costly-heavy-route", "high",
                typeHit || dispHit ? "observed" : "inferred",
                "Export, render, or heavy download route",
                e, null,
                "Route or response shape suggests expensive synchronous generation or large download.",
                string.IsNullOrEmpty(disp) ? ct : disp,
                "Move heavy work to async jobs; rate-limit and cap export size.");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> SlowSync(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess && x.DurationMs.HasValue))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (e.ResourceType is not ("XHR" or "Fetch" or "Document" or "EventSource")) continue;
            if (e.DurationMs!.Value < ctx.SlowThresholdMs) continue;
            count++;
            yield return Finding(
                "slow-sync", "costly-slow-sync", "medium", "observed",
                $"Slow API call ({e.DurationMs.Value:F0} ms) — consider async job",
                e, null,
                $"Captured {e.Method} took {e.DurationMs.Value:F0} ms (threshold {ctx.SlowThresholdMs} ms).",
                $"{e.DurationMs.Value:F0}ms",
                "Offload long work to background jobs; return 202 + status URL for heavy operations.");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> BulkInput(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x is { IsSuccess: true, Method: "POST" or "PUT" or "PATCH" }))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            var path = uri.AbsolutePath.ToLowerInvariant();
            var pathBulk = BulkPathTokens.Any(t => path.Contains(t, StringComparison.Ordinal));

            var repeatedIds = ParseQueryValues(e.Url)
                .Count(kv => kv.Key.Equals("id", StringComparison.OrdinalIgnoreCase)
                             || kv.Key.Equals("ids", StringComparison.OrdinalIgnoreCase)) > 1;

            var jsonArrayKeys = ShallowJsonArrayCounts(e.RequestBody);
            var bigArray = jsonArrayKeys.FirstOrDefault(kv => kv.Value >= 3);
            var graphqlBatch = LooksLikeGraphQlBatchBody(e.RequestBody);
            var recipientArray = jsonArrayKeys.FirstOrDefault(kv =>
                RecipientFieldNames.Any(r => kv.Key.Equals(r, StringComparison.OrdinalIgnoreCase))
                && kv.Value >= 2);

            if (!pathBulk && !repeatedIds && bigArray.Key == null && !graphqlBatch && recipientArray.Key == null) continue;
            count++;
            yield return Finding(
                "bulk-input", "costly-bulk-input", "high",
                bigArray.Key != null || repeatedIds || graphqlBatch || recipientArray.Key != null ? "observed" : "inferred",
                graphqlBatch ? "GraphQL batch-style body in one HTTP request" : "Bulk or multi-id input on one request",
                e, recipientArray.Key ?? bigArray.Key ?? (graphqlBatch ? "query" : "ids"),
                pathBulk
                    ? "Batch/bulk route accepts operations in one request."
                    : graphqlBatch
                        ? "Multiple GraphQL operations in one POST — cost multiplies per request."
                        : recipientArray.Key != null
                            ? "Many recipients in one notify/send request."
                            : "Multiple ids or a large id array in one request.",
                graphqlBatch ? "graphql-batch-body" : bigArray.Key != null ? $"{bigArray.Key}[{bigArray.Value}]" : e.Url,
                "Cap batch size and id count per request server-side.");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> Expansion(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            foreach (var (name, value) in ParseQueryValues(e.Url))
            {
                var isExpansion = ExpansionParamNames.Any(p => name.Equals(p, StringComparison.OrdinalIgnoreCase))
                                  || name.StartsWith("$", StringComparison.OrdinalIgnoreCase)
                                  || name.Equals("$filter", StringComparison.OrdinalIgnoreCase)
                                  || name.Equals("filter", StringComparison.OrdinalIgnoreCase);
                if (!isExpansion) continue;
                if (value == "*" || value.Split(',').Length >= 4
                    || (name.Contains("filter", StringComparison.OrdinalIgnoreCase) && value.Length >= 40))
                {
                    count++;
                    yield return Finding(
                        "expansion", "costly-expansion", "medium", "observed",
                        "Costly expand/include parameter",
                        e, name,
                        $"Parameter {name} may pull large related graphs ({Trunc(value, 80)}).",
                        $"{name}={Trunc(value, 120)}",
                        "Limit expand depth/count; default to minimal field sets.");
                }
            }

            foreach (var name in ImageDimParams)
            {
                var val = ParseQueryValues(e.Url).FirstOrDefault(kv =>
                    kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
                if (val == null || !int.TryParse(val, out var dim) || dim < 256) continue;
                count++;
                yield return Finding(
                    "expansion", "costly-image-dimensions", "medium", "observed",
                    "Large image dimension parameter in traffic",
                    e, name,
                    $"{name}={dim} was honored (2xx) — dimension cap may be missing.",
                    $"{name}={val}",
                    "Cap image dimensions and quality server-side.");
            }
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> UploadSurface(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            var pathHit = UploadPathTokens.Any(t => uri.AbsolutePath.Contains(t, StringComparison.OrdinalIgnoreCase));
            var ct = e.ContentType.ToLowerInvariant();
            var archiveHit = ct.Contains("zip") || ct.Contains("gzip") || ct.Contains("spreadsheet")
                               || ct.Contains("ms-excel") || ct.Contains("octet-stream");
            if (!pathHit && !archiveHit) continue;
            count++;
            yield return Finding(
                "upload-surface", "costly-upload-surface", archiveHit ? "high" : "medium", "observed",
                archiveHit ? "Upload accepted expandable/archive content-type" : "Upload or import route observed",
                e, null,
                archiveHit
                    ? "Archive/spreadsheet uploads can expand to large in-memory structures server-side."
                    : "File upload/import paths can accept large payloads per request.",
                string.IsNullOrEmpty(ct) ? uri.AbsolutePath : ct,
                "Enforce size/type limits server-side.",
                relatedProbe: "file-upload-scan");
        }

        if (ctx.Spa?.InputFields == null) yield break;
        if (ctx.UrlScope is { Count: > 0 })
        {
            var page = ctx.Spa.PageUrl ?? "";
            if (!ctx.UrlScope.Any(u => UrlMatchesScope(page, u)))
                yield break;
        }

        foreach (var field in ctx.Spa.InputFields)
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (!string.Equals(field.Type, "file", StringComparison.OrdinalIgnoreCase)) continue;
            count++;
            yield return Finding(
                "upload-surface", "costly-upload-surface", "medium", "inferred",
                "File input on page (upload surface)",
                new NetworkEntry { Url = ctx.Spa.PageUrl ?? ctx.Origin, Method = "GET", StatusCode = 200 },
                field.Name ?? field.Id,
                "DOM exposes file upload — large files may be accepted per request.",
                field.Label ?? field.Name,
                "Validate size and type on the server; consider client accept hints.",
                relatedProbe: "file-upload-scan");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> TrafficShape(ScanContext ctx)
    {
        var count = 0;
        foreach (var ep in ctx.Surface.Endpoints.Where(ep => ep.RequestCount >= 5))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (IsTransportPolling(ep.Url)) continue;

            var merge = AttackSurfaceMapper.EndpointMergeKeyFromUrl(ep.Url);
            var matches = ctx.Entries
                .Where(e => AttackSurfaceMapper.EndpointMergeKeyFromUrl(e.Url) == merge)
                .ToList();
            if (matches.Count < 5) continue;
            if (matches.Any(e => IsTransportPolling(e.Url))) continue;

            var distinct = matches.Select(LogicalRequestKey).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (distinct < 5) continue;

            count++;
            var sample = matches[0];
            yield return Finding(
                "traffic-shape", "costly-n-plus-one", "medium", "observed",
                "Repeated calls to different resource URLs (possible N+1)",
                sample,
                null,
                $"{distinct} different URLs under {ep.UrlTemplate} ({matches.Count} requests). One call per id is more expensive than a batch or an include on the list.",
                $"distinctUrls={distinct}",
                "Offer a batch or include-on-list read so the client does not fan out one request per id.");
        }

        foreach (var e in ctx.Entries)
        {
            if (count >= ctx.MaxCandidates) yield break;
            var upgrade = GetHeader(e, "Upgrade");
            if (!upgrade.Contains("websocket", StringComparison.OrdinalIgnoreCase)) continue;
            count++;
            yield return Finding(
                "traffic-shape", "costly-long-lived-stream", "medium", "inferred",
                "WebSocket upgrade observed",
                e, null,
                "Long-lived connections can carry sustained server work.",
                upgrade,
                "Cap message size/rate; audit subscription fan-out.",
                relatedProbe: "websocket-audit");
        }

        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (!e.ContentType.Contains("event-stream", StringComparison.OrdinalIgnoreCase)) continue;
            count++;
            yield return Finding(
                "traffic-shape", "costly-long-lived-stream", "medium", "observed",
                "Server-sent events (SSE) stream",
                e, null,
                "Long-lived text/event-stream responses hold connections and ongoing work.",
                e.ContentType,
                "Cap stream duration and payload rate; use polling with backoff where appropriate.",
                relatedProbe: "sse-audit");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> NestedPayload(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (e.ContentType.Contains("html", StringComparison.OrdinalIgnoreCase)) continue;
            var body = e.RequestBody ?? e.ResponseBody;
            if (string.IsNullOrEmpty(body) || body.Length < EmbeddedPayloadMinChars) continue;
            if (body.TrimStart().StartsWith('<')) continue;
            if (!TryFindEmbeddedPayload(body, out var path, out var kind, out var length)) continue;

            count++;
            var dataUrl = kind == "data-url";
            yield return Finding(
                "nested-payload", "costly-nested-payload", "medium", "observed",
                dataUrl ? "Data-URL embedded in JSON" : "Base64-like string embedded in JSON",
                e, path,
                dataUrl
                    ? $"JSON field {path} carries a data-URL ({length} chars). Inline files bypass upload limits."
                    : $"JSON field {path} is a {length}-character base64-like string. Inline files are costly to parse and store.",
                $"{path} length={length}",
                "Cap embedded payload size; store files separately with a size limit.");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> RecipientFanout(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x is { IsSuccess: true, Method: "POST" or "PUT" or "PATCH" }))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (string.IsNullOrEmpty(e.RequestBody) || !e.RequestBody.TrimStart().StartsWith('{')) continue;

            foreach (var (name, len) in ShallowJsonArrayCounts(e.RequestBody))
            {
                if (!RecipientFieldNames.Any(r => name.Equals(r, StringComparison.OrdinalIgnoreCase))) continue;
                if (len < 2) continue;
                count++;
                yield return Finding(
                    "recipient-fanout", "costly-recipient-fanout", "high", "observed",
                    $"Many recipients in one request ({name}[{len}])",
                    e, name,
                    "Notification/email/SMS fan-out in a single API call can be expensive per request.",
                    $"{name}[{len}]",
                    "Cap recipient count and queue delivery asynchronously.");
            }
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> DateRange(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (count >= ctx.MaxCandidates) yield break;
            var pairs = ParseQueryValues(e.Url).ToList();
            var fromVal = pairs.FirstOrDefault(p => p.Key.Equals("from", StringComparison.OrdinalIgnoreCase)
                                                    || p.Key.Equals("start", StringComparison.OrdinalIgnoreCase)
                                                    || p.Key.Equals("startDate", StringComparison.OrdinalIgnoreCase)).Value;
            var toVal = pairs.FirstOrDefault(p => p.Key.Equals("to", StringComparison.OrdinalIgnoreCase)
                                                  || p.Key.Equals("end", StringComparison.OrdinalIgnoreCase)
                                                  || p.Key.Equals("endDate", StringComparison.OrdinalIgnoreCase)).Value;
            if (string.IsNullOrEmpty(fromVal) || string.IsNullOrEmpty(toVal)) continue;

            if (TryParseLooseDate(fromVal, out var start) && TryParseLooseDate(toVal, out var end))
            {
                var days = (end - start).TotalDays;
                if (days < 90) continue;
                count++;
                yield return Finding(
                    "date-range", "costly-date-range", "medium", "observed",
                    $"Wide date range on query ({days:F0} days)",
                    e, "from/to",
                    "Report/search endpoints over long windows can return or aggregate large datasets.",
                    $"{fromVal} → {toVal}",
                    "Cap maximum report window server-side; require async export for long ranges.");
            }
            else if (fromVal.Length > 8 && toVal.Length > 8)
            {
                count++;
                yield return Finding(
                    "date-range", "costly-date-range", "low", "inferred",
                    "Date-range parameters on query (window not verified)",
                    e, "from/to",
                    "from/to (or start/end) on reports may allow wide windows.",
                    $"{Trunc(fromVal, 40)} → {Trunc(toVal, 40)}",
                    "Validate and cap date range length.");
            }
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> FilterDepth(ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x is { IsSuccess: true, Method: "POST" or "PUT" or "PATCH" }))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (string.IsNullOrEmpty(e.RequestBody) || !e.RequestBody.TrimStart().StartsWith('{')) continue;
            var depth = JsonBoolTreeDepth(e.RequestBody);
            if (depth < 4) continue;
            count++;
            yield return Finding(
                "filter-depth", "costly-filter-depth", "medium", "observed",
                $"Deep filter/group tree in JSON (depth {depth})",
                e, "filter",
                "Complex and/or/aggregation trees can be expensive to evaluate per request.",
                $"depth={depth}",
                "Limit filter depth and complexity; reject deeply nested bool trees.");
        }
    }

    public static IEnumerable<ConfirmCandidate> PageSizeConfirmCandidates(ScanContext ctx)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            foreach (var (name, value) in ParseQueryValues(e.Url).Where(kv => IsPageSizeParam(kv.Key)))
            {
                if (!int.TryParse(value, out var current) || current <= 0) current = 10;
                var probeVal = Math.Min(Math.Max(current * 2, current + 20), 100);
                if (probeVal <= current) continue;

                var baselineUrl = SetQueryParam(e.Url, name, current.ToString());
                var probeUrl = SetQueryParam(e.Url, name, probeVal.ToString());
                var key = $"{e.Method}|{baselineUrl}|{name}";
                if (!seen.Add(key)) continue;

                yield return new ConfirmCandidate
                {
                    Url = e.Url,
                    BaselineUrl = baselineUrl,
                    ProbeUrl = probeUrl,
                    Method = e.Method,
                    BodyTemplate = e.RequestBody,
                    Headers = CopyHeaders(e.RequestHeaders),
                    ParamName = name,
                    BaselineValue = current.ToString(),
                    ProbeValue = probeVal.ToString(),
                    Kind = "step",
                    SourceNetworkEntryId = e.Id
                };
            }

            if (!e.Method.Equals("GET", StringComparison.OrdinalIgnoreCase)) continue;
            if (ParseQueryValues(e.Url).Any(kv => IsPagingParam(kv.Key))) continue;
            var (wrapper, listLen) = TryExtractListSize(e.ResponseBody);
            var len = listLen ?? TryJsonArrayLength(e.ResponseBody);
            if (len is null or < MissingPageMinCount) continue;
            var injectUrl = SetQueryParam(e.Url, "limit", "50");
            var injectKey = $"{e.Method}|inject|{e.Url}";
            if (!seen.Add(injectKey)) continue;
            yield return new ConfirmCandidate
            {
                Url = e.Url,
                BaselineUrl = e.Url,
                ProbeUrl = injectUrl,
                Method = e.Method,
                Headers = CopyHeaders(e.RequestHeaders),
                ParamName = "limit",
                BaselineValue = "",
                ProbeValue = "50",
                Evidence = wrapper == null ? $"array[{len}]" : $"{wrapper}[{len}]",
                Kind = "inject",
                SourceNetworkEntryId = e.Id
            };
        }
    }

    public static IEnumerable<ConfirmCandidate> ImageEdgeConfirmCandidates(ScanContext ctx)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess && x.Method == "GET"))
        {
            foreach (var param in ImageDimParams)
            {
                var existing = ParseQueryValues(e.Url)
                    .FirstOrDefault(kv => kv.Key.Equals(param, StringComparison.OrdinalIgnoreCase)).Value;
                if (existing == null || !int.TryParse(existing, out var n) || n <= 0 || n >= 256) continue;
                var baseline = n;
                var probe = Math.Min(Math.Max(baseline * 4, baseline + 64), 256);
                if (probe <= baseline) continue;

                var baselineUrl = SetQueryParam(e.Url, param, baseline.ToString());
                var probeUrl = SetQueryParam(e.Url, param, probe.ToString());
                var key = baselineUrl + probeUrl;
                if (!seen.Add(key)) continue;

                yield return new ConfirmCandidate
                {
                    BaselineUrl = baselineUrl,
                    ProbeUrl = probeUrl,
                    ParamName = param,
                    BaselineValue = baseline.ToString(),
                    ProbeValue = probe.ToString(),
                    SourceNetworkEntryId = e.Id
                };
            }
        }
    }

    public static IEnumerable<ConfirmCandidate> MultiIdConfirmCandidates(ScanContext ctx)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            var ids = ParseQueryValues(e.Url)
                .Where(kv => kv.Key.Equals("ids", StringComparison.OrdinalIgnoreCase)
                             || kv.Key.Equals("id", StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .ToList();
            if (ids.Count == 0) continue;
            var first = ids[0].Split(',')[0].Trim();
            if (string.IsNullOrEmpty(first)) continue;
            var second = first + "1";
            if (ids[0].Contains(',')) continue;

            var baselineUrl = SetQueryParam(e.Url, "ids", first);
            var probeUrl = SetQueryParam(e.Url, "ids", $"{first},{second}");
            var key = baselineUrl;
            if (!seen.Add(key)) continue;

            yield return new ConfirmCandidate
            {
                BaselineUrl = baselineUrl,
                ProbeUrl = probeUrl,
                Method = e.Method,
                Headers = CopyHeaders(e.RequestHeaders),
                ParamName = "ids",
                Evidence = $"ids={first} vs ids={first},{second}",
                SourceNetworkEntryId = e.Id
            };
        }
    }

    internal static bool IsPageSizeParam(string name) =>
        PageSizeParamNames.Any(p => name.Equals(p, StringComparison.OrdinalIgnoreCase));

    internal static bool IsPagingParam(string name) =>
        IsPageSizeParam(name)
        || OffsetParamNames.Any(p => name.Equals(p, StringComparison.OrdinalIgnoreCase))
        || name.Equals("max", StringComparison.OrdinalIgnoreCase);

    internal static bool LooksLikeLlmRoute(string path) =>
        LlmPathTokens.Any(t => path.Contains(t, StringComparison.OrdinalIgnoreCase));

    internal static bool LooksLikeSsrfFetchParam(string name) =>
        SsrfFetchParams.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase));

    internal static bool LooksLikeGraphQl(NetworkEntry e) =>
        e.Url.Contains("/graphql", StringComparison.OrdinalIgnoreCase)
        || e.ContentType.Contains("graphql", StringComparison.OrdinalIgnoreCase)
        || (e.RequestBody?.Contains("query", StringComparison.OrdinalIgnoreCase) == true
            && e.RequestBody.Contains("{", StringComparison.Ordinal));

    internal static bool OpenApiBodyLooksUnbounded(string? body) =>
        !string.IsNullOrEmpty(body)
        && body.Contains("openapi", StringComparison.OrdinalIgnoreCase)
        && OpenApiArrayWithoutMaxItems.IsMatch(body);

    private static CostlyOperationsProbe.CostlyFinding Finding(
        string checkId,
        string category,
        string severity,
        string confidence,
        string title,
        NetworkEntry e,
        string? parameter,
        string detail,
        string? evidence,
        string remediation,
        string? relatedProbe = null) => new()
    {
        CheckId = checkId,
        Category = category,
        Severity = severity,
        Confidence = confidence,
        Title = title,
        Endpoint = e.Url,
        Method = e.Method,
        Parameter = parameter,
        Detail = detail,
        Evidence = evidence,
        Remediation = remediation,
        RelatedProbe = relatedProbe,
        NetworkEntryId = e.Id
    };

    private static bool IsTransportPolling(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        var path = uri.AbsolutePath;
        if (path.Contains("socket.io", StringComparison.OrdinalIgnoreCase)
            || path.Contains("sockjs", StringComparison.OrdinalIgnoreCase))
            return true;
        var query = uri.Query;
        return query.Contains("transport=polling", StringComparison.OrdinalIgnoreCase)
               || query.Contains("EIO=", StringComparison.OrdinalIgnoreCase);
    }

    private static string LogicalRequestKey(NetworkEntry e)
    {
        if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri))
            return e.Method + " " + e.Url;
        var query = string.Join("&", ParseQueryValues(e.Url)
            .Where(kv => !CacheBusterParamNames.Any(p => p.Equals(kv.Key, StringComparison.OrdinalIgnoreCase)))
            .Select(kv => kv.Key + "=" + kv.Value));
        return e.Method.ToUpperInvariant() + " " + uri.AbsolutePath + "?" + query;
    }

    private static bool TryFindEmbeddedPayload(string body, out string path, out string kind, out int length)
    {
        path = "";
        kind = "";
        length = 0;
        try
        {
            using var doc = JsonDocument.Parse(body);
            return WalkEmbedded(doc.RootElement, "$", ref path, ref kind, ref length, 0);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool WalkEmbedded(JsonElement el, string path, ref string foundPath, ref string kind, ref int length, int depth)
    {
        if (depth > 8) return false;
        switch (el.ValueKind)
        {
            case JsonValueKind.String:
                var s = el.GetString() ?? "";
                if (s.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase)
                    || s.StartsWith("data:application/", StringComparison.OrdinalIgnoreCase))
                {
                    foundPath = path;
                    kind = "data-url";
                    length = s.Length;
                    return s.Length >= 500;
                }

                if (!LooksLikeEmbeddedBase64(s)) return false;
                foundPath = path;
                kind = "base64";
                length = s.Length;
                return true;
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    if (WalkEmbedded(prop.Value, path + "." + prop.Name, ref foundPath, ref kind, ref length, depth + 1))
                        return true;
                }
                return false;
            case JsonValueKind.Array:
                var i = 0;
                foreach (var item in el.EnumerateArray())
                {
                    if (i >= 20) break;
                    if (WalkEmbedded(item, path + "[" + i + "]", ref foundPath, ref kind, ref length, depth + 1))
                        return true;
                    i++;
                }
                return false;
            default:
                return false;
        }
    }

    private static bool LooksLikeEmbeddedBase64(string s)
    {
        if (s.Length < EmbeddedPayloadMinChars) return false;
        if (s.Contains(' ') || s.Contains('\n') || s.Contains('\r')) return false;
        var ok = 0;
        foreach (var c in s)
        {
            if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9'
                or '+' or '/' or '=' or '-' or '_')
                ok++;
        }

        return ok >= (int)(s.Length * 0.98);
    }

    private static long EstimateResponseBytes(NetworkEntry e)
    {
        if (e.ContentLengthBytes is > 0) return e.ContentLengthBytes.Value;
        if (!string.IsNullOrEmpty(e.ResponseBody)) return e.ResponseBody.Length;
        return 0;
    }

    private static int? TryJsonArrayLength(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                return doc.RootElement.GetArrayLength();
        }
        catch (JsonException) { }

        return null;
    }

    private static (string? wrapper, int? length) TryExtractListSize(string? body)
    {
        if (string.IsNullOrWhiteSpace(body) || !body.TrimStart().StartsWith('{')) return (null, null);
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return (null, null);
            foreach (var name in ListWrapperPropertyNames)
            {
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (!prop.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
                    if (prop.Value.ValueKind == JsonValueKind.Array)
                        return (prop.Name, prop.Value.GetArrayLength());
                }
            }
        }
        catch (JsonException) { }

        return (null, null);
    }

    private static NetworkEntry? FindRepresentativeEntry(ScanContext ctx, string epUrl)
    {
        var key = AttackSurfaceMapper.EndpointMergeKeyFromUrl(epUrl);
        return ctx.Entries.FirstOrDefault(e =>
            AttackSurfaceMapper.EndpointMergeKeyFromUrl(e.Url) == key);
    }

    private static List<string> ShallowJsonPropertyNames(string? body)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(body) || !body.TrimStart().StartsWith('{')) return list;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return list;
            foreach (var prop in doc.RootElement.EnumerateObject())
                list.Add(prop.Name);
        }
        catch (JsonException) { }

        return list;
    }

    private static bool LooksLikeGraphQlBatchBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        if (t.StartsWith('[') && t.Contains("\"query\"", StringComparison.OrdinalIgnoreCase))
            return true;
        if (t.Contains("\"operations\"", StringComparison.OrdinalIgnoreCase)
            && t.Contains("\"query\"", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static bool TryParseLooseDate(string value, out DateTime dt)
    {
        dt = default;
        if (DateTime.TryParse(value, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out dt))
            return true;
        return DateTime.TryParse(value, out dt);
    }

    private static int JsonBoolTreeDepth(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return WalkDepth(doc.RootElement, 0, 8);
        }
        catch (JsonException)
        {
            return 0;
        }
    }

    private static int WalkDepth(JsonElement el, int depth, int max)
    {
        if (depth >= max) return depth;
        var local = depth;
        if (el.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in el.EnumerateObject())
            {
                var name = prop.Name.ToLowerInvariant();
                if (name is "and" or "or" or "$and" or "$or" or "filter" or "must" or "should")
                    local = Math.Max(local, depth + 1);
                local = Math.Max(local, WalkDepth(prop.Value, depth + 1, max));
            }
        }
        else if (el.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in el.EnumerateArray())
                local = Math.Max(local, WalkDepth(item, depth + 1, max));
        }

        return local;
    }

    private static List<KeyValuePair<string, int>> ShallowJsonArrayCounts(string? body)
    {
        var list = new List<KeyValuePair<string, int>>();
        if (string.IsNullOrWhiteSpace(body) || !body.TrimStart().StartsWith('{')) return list;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return list;
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.Array)
                    list.Add(new KeyValuePair<string, int>(prop.Name, prop.Value.GetArrayLength()));
            }
        }
        catch (JsonException) { }

        return list;
    }

    private static IEnumerable<KeyValuePair<string, string>> ParseQueryValues(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Query))
            yield break;
        foreach (var segment in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = segment.IndexOf('=');
            var name = eq >= 0 ? Uri.UnescapeDataString(segment[..eq]) : Uri.UnescapeDataString(segment);
            var value = eq >= 0 ? Uri.UnescapeDataString(segment[(eq + 1)..]) : "";
            yield return new KeyValuePair<string, string>(name, value);
        }
    }

    private static string SetQueryParam(string url, string param, string value)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;
        var pairs = ParseQueryValues(url).ToList();
        var replaced = false;
        for (var i = 0; i < pairs.Count; i++)
        {
            if (!pairs[i].Key.Equals(param, StringComparison.OrdinalIgnoreCase)) continue;
            pairs[i] = new KeyValuePair<string, string>(pairs[i].Key, value);
            replaced = true;
        }

        if (!replaced)
            pairs.Add(new KeyValuePair<string, string>(param, value));

        var qs = string.Join("&", pairs.Select(p =>
            $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        return $"{uri.GetLeftPart(UriPartial.Path)}?{qs}";
    }

    private static string GetHeader(NetworkEntry e, string name)
    {
        if (e.ResponseHeaders.TryGetValue(name, out var v)) return v;
        return e.ResponseHeaders.TryGetValue(name.ToLowerInvariant(), out v) ? v : "";
    }

    private static bool UrlMatchesScope(string entryUrl, string scopeUrl)
    {
        if (entryUrl.Equals(scopeUrl, StringComparison.OrdinalIgnoreCase)) return true;
        if (!Uri.TryCreate(entryUrl, UriKind.Absolute, out var a)
            || !Uri.TryCreate(scopeUrl, UriKind.Absolute, out var b))
            return false;
        return string.Equals(a.AbsolutePath, b.AbsolutePath, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, string> CopyHeaders(Dictionary<string, string> source)
    {
        var copy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in source)
        {
            if (kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            copy[kv.Key] = kv.Value;
        }

        return copy;
    }

    private static string Trunc(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
