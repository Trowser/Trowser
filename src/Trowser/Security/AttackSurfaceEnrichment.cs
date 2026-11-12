using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.RepresentationModel;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Adds OpenAPI/Swagger ingestion (traffic + lightweight GET probes) and heuristic API URLs from bundles.
/// </summary>
public static class AttackSurfaceEnrichment
{
    public sealed record Options(
        bool IncludeOpenApiFromNetwork = true,
        bool IncludeOpenApiProbes = true,
        bool IncludeJsBundleHints = true,
        bool IncludeDevArtifactProbes = true,
        int MaxProbeOrigins = 6,
        int MaxScripts = 24,
        int MaxBytesPerScript = 524_288,
        int MaxJsHintPaths = 200,
        int HttpTimeoutMs = 12_000,
        int MaxWordPressRestRoutes = 8000);

    private static readonly string[] DevArtifactRelativePaths =
    [
        "/.env", "/.env.example", "/.env.local", "/.env.production",
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/composer.json", "/composer.lock",
        "/webpack.config.js", "/webpack.mix.js", "/Gruntfile.js", "/gulpfile.js",
        "/.git/config", "/.gitignore", "/.svn/entries",
        "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
        "/.github/workflows/ci.yml", "/.github/workflows/deploy.yml",
        "/.gitlab-ci.yml", "/Jenkinsfile", "/azure-pipelines.yml",
        "/README.md", "/CHANGELOG.md"
    ];

    private static readonly string[] ProbeSpecRelativePaths =
    [
        "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
        "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/docs",
        "/api/swagger.json", "/api/swagger/json", "/swagger/json",
        "/api/swagger/v1/swagger.json", "/api/openapi.json",
        "/api/openapi.yaml", "/swagger-resources", "/.well-known/openapi.json",
        "/q/openapi.yaml", "/wp-json", "/wp-json/"
    ];

    private static readonly HashSet<string> HttpVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "get", "put", "post", "delete", "options", "head", "patch", "trace"
    };

    private static readonly Regex PathBraceParams = new(@"\{([^/}]+)}", RegexOptions.Compiled);

    private static readonly string[] JsBundleStaticSuffixes =
    [
        ".js", ".css", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2",
        ".ttf", ".eot", ".wasm", ".ts", ".tsx"
    ];

    private static readonly Regex[] JsHintPatterns =
    [
        new Regex(@"fetch\s*\(\s*[""'](?<u>(?:https?:)?\/[^""']+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"axios\.(?:get|post|put|delete|patch|request)\s*\(\s*[""'](?<u>(?:https?:)?\/[^""']+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"(?<![/\w])(?<u>/api/[a-zA-Z0-9_./\-{}]{1,240})", RegexOptions.Compiled),
        new Regex(@"(?<![/\w])(?<u>/rest/[a-zA-Z0-9_./\-{}]{1,240})", RegexOptions.Compiled),
        new Regex(@"baseURL\s*:\s*[""'](?<u>[^""']{2,320})[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"apiUrl\s*:\s*[""'](?<u>[^""']{2,320})[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"(?<![/\w])(?<u>/v\d(?:/[\w\-./{}]*)?)", RegexOptions.Compiled),
        new Regex(@"(?<![/\w])(?<u>/graphql)(?:[\s""')])", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"(?<![/\w])(?<u>/wp-json/[a-zA-Z0-9_./\-{}]{1,480})", RegexOptions.Compiled)
    ];

    /// <summary>WordPress REST route keys embed PCRE named capture groups, e.g. (?P:name:...).</summary>
    private static readonly Regex WordPressNamedPathParam =
        new(@"\(\?P<(\w+)>[^\)]*\)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static async Task RunAsync(
        AttackSurfaceResult result,
        AutomationContext ctx,
        List<NetworkEntry> entries,
        string? navigatedUrl,
        Options options,
        CancellationToken ct = default)
    {
        if (!options.IncludeOpenApiFromNetwork && !options.IncludeOpenApiProbes &&
            !options.IncludeJsBundleHints && !options.IncludeDevArtifactProbes)
            return;

        result.Enrichment ??= new AttackSurfaceEnrichmentReport { Enabled = true };
        var report = result.Enrichment;
        report.Enabled = true;

        var maxWpRoutes = Math.Clamp(options.MaxWordPressRestRoutes, 64, 50_000);

        var pageUri = SafePageUri(navigatedUrl);

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Clamp(options.HttpTimeoutMs, 3_000, 60_000))
        };

        var mergeMap = BuildMergeMap(result.Endpoints);
        var addedCandidates = new List<AttackSurfaceEndpoint>();

        if (options.IncludeOpenApiFromNetwork)
        {
            foreach (var e in entries.Where(x => x is { StatusCode: >= 200 and < 300 }
                                                 && x.ResponseBody is { Length: > 40 }))
            {
                ct.ThrowIfCancellationRequested();
                if (!LooksLikePotentialSpecBody(e.Url, e.ContentType, e.ResponseBody!)
                    && !LooksLikeWordPressRestIndex(e.Url, e.ContentType, e.ResponseBody!))
                    continue;

                report.NetworkLogSpecBodiesExamined++;
                if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var docUri))
                    docUri = pageUri;

                if (TryParseOpenApiBody(e.ResponseBody!, docUri, maxWpRoutes, out var ops,
                        out var viaTag,
                        out var parseErr))
                {
                    foreach (var o in ops)
                        o.DiscoveredVia.Add(viaTag);
                    addedCandidates.AddRange(ops);

                    if (string.Equals(viaTag, "wordpress-rest", StringComparison.Ordinal))
                        report.WordPressRestIndexesParsed++;
                    else
                    {
                        report.OpenApiSpecsFromNetworkLog++;
                        report.OpenApiSpecsParsed++;
                    }

                    report.OpenApiSpecSources.Add($"network-log:{ShortUrl(e.Url)}");
                }
                else if (!string.IsNullOrEmpty(parseErr))
                    report.OpenApiErrors.Add($"{ShortUrl(e.Url)}: {parseErr}");
            }
        }

        if (options.IncludeOpenApiProbes)
        {
            foreach (var origin in CollectProbeOrigins(pageUri, entries, options.MaxProbeOrigins))
            {
                ct.ThrowIfCancellationRequested();
                var cookieHeader = await ctx.GetCookieHeaderForUrl(origin).ConfigureAwait(false);
                foreach (var rel in ProbeSpecRelativePaths)
                {
                    ct.ThrowIfCancellationRequested();
                    var full = origin.TrimEnd('/') + rel;
                    report.OpenApiProbesAttempted++;
                    try
                    {
                        using var req = new HttpRequestMessage(HttpMethod.Get, full);
                        req.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} AttackSurface");
                        req.Headers.TryAddWithoutValidation("Accept",
                            "application/json, application/yaml, text/yaml, */*");
                        if (!string.IsNullOrEmpty(cookieHeader))
                            req.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

                        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                            .ConfigureAwait(false);
                        if ((int)resp.StatusCode is < 200 or >= 300)
                            continue;

                        var media = resp.Content.Headers.ContentType?.MediaType ?? "";
                        if (media.Contains("html", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var body = await ReadBodyCapped(resp, 2_000_000, ct).ConfigureAwait(false);
                        if (body.Length < 40)
                            continue;

                        var docProbe = new Uri(full);
                        if (!TryParseOpenApiBody(body, docProbe, maxWpRoutes, out var opsOut,
                                out var probeVia,
                                out var probeErr))
                        {
                            if (!string.IsNullOrEmpty(probeErr))
                                report.OpenApiErrors.Add($"{ShortUrl(full)}: {probeErr}");
                            continue;
                        }

                        foreach (var o in opsOut)
                            o.DiscoveredVia.Add(probeVia);
                        addedCandidates.AddRange(opsOut);

                        if (string.Equals(probeVia, "wordpress-rest", StringComparison.Ordinal))
                            report.WordPressRestIndexesParsed++;
                        else
                            report.OpenApiSpecsParsed++;

                        report.OpenApiSpecSources.Add($"probe:{ShortUrl(full)}");
                    }
                    catch (Exception ex)
                    {
                        report.OpenApiErrors.Add($"{ShortUrl(full)}: {ex.Message}");
                    }
                }
            }
        }

        if (options.IncludeJsBundleHints)
            await CollectJsHintsAsync(ctx, pageUri, options, report, addedCandidates, ct).ConfigureAwait(false);

        if (options.IncludeDevArtifactProbes)
            await RunDevArtifactProbesAsync(ctx, pageUri, entries, options, report, addedCandidates, ct)
                .ConfigureAwait(false);

        report.EndpointsAddedBeforeMerge = addedCandidates.Count;
        MergeCandidates(result.Endpoints, mergeMap, addedCandidates);

        var mapper = new AttackSurfaceMapper();
        mapper.AttachRefreshedSummary(result, entries);
    }

    private static Uri SafePageUri(string? navigatedUrl)
    {
        if (!string.IsNullOrWhiteSpace(navigatedUrl) &&
            Uri.TryCreate(navigatedUrl.Trim(), UriKind.Absolute, out var u))
            return u;
        return new Uri("https://localhost/", UriKind.Absolute);
    }

    private static Dictionary<string, AttackSurfaceEndpoint> BuildMergeMap(List<AttackSurfaceEndpoint> endpoints)
    {
        var map = new Dictionary<string, AttackSurfaceEndpoint>(StringComparer.OrdinalIgnoreCase);
        foreach (var ep in endpoints)
        {
            map[AttackSurfaceMapper.EndpointMergeKeyFromUrl(ep.Url)] = ep;
        }

        return map;
    }

    private static void MergeCandidates(
        List<AttackSurfaceEndpoint> endpoints,
        Dictionary<string, AttackSurfaceEndpoint> mergeMap,
        List<AttackSurfaceEndpoint> candidates)
    {
        foreach (var c in candidates)
        {
            var key = AttackSurfaceMapper.EndpointMergeKeyFromUrl(c.Url);
            if (mergeMap.TryGetValue(key, out var existing))
            {
                foreach (var m in c.Methods)
                    existing.Methods.Add(m);
                foreach (var v in c.DiscoveredVia)
                    existing.DiscoveredVia.Add(v);

                foreach (var p in c.Parameters.Path.Where(p =>
                             !existing.Parameters.Path.Contains(p, StringComparer.OrdinalIgnoreCase)))
                    existing.Parameters.Path.Add(p);

                foreach (var q in c.Parameters.Query.Where(q =>
                             !existing.Parameters.Query.Contains(q, StringComparer.OrdinalIgnoreCase)))
                    existing.Parameters.Query.Add(q);

                continue;
            }

            endpoints.Add(c);
            mergeMap[key] = c;
        }
    }

    private static async Task RunDevArtifactProbesAsync(
        AutomationContext ctx,
        Uri pageUri,
        List<NetworkEntry> entries,
        Options options,
        AttackSurfaceEnrichmentReport report,
        List<AttackSurfaceEndpoint> addedCandidates,
        CancellationToken ct)
    {
        using var devHandler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var devHttp = new HttpClient(devHandler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Clamp(options.HttpTimeoutMs, 3_000, 60_000))
        };

        foreach (var origin in CollectProbeOrigins(pageUri, entries, options.MaxProbeOrigins))
        {
            ct.ThrowIfCancellationRequested();
            var cookieHeader = await ctx.GetCookieHeaderForUrl(origin).ConfigureAwait(false);
            foreach (var rel in DevArtifactRelativePaths)
            {
                ct.ThrowIfCancellationRequested();
                report.DevArtifactProbesAttempted++;
                var full = origin.TrimEnd('/') + rel;
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, full);
                    req.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} AttackSurface");
                    req.Headers.TryAddWithoutValidation("Accept", "*/*");
                    if (!string.IsNullOrEmpty(cookieHeader))
                        req.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

                    using var resp =
                        await devHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                            .ConfigureAwait(false);
                    var code = (int)resp.StatusCode;
                    if (code == 404)
                        continue;

                    var body = await ReadBodyCapped(resp, 65_536, ct).ConfigureAwait(false);
                    var media = resp.Content.Headers.ContentType?.MediaType ?? "";

                    if (!IsPlausibleDevArtifactHit(rel, media, body))
                        continue;

                    var ep = CreateSyntheticEndpoint(origin, rel,
                        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "GET" });
                    ep.DiscoveredVia.Add("dev-artifact-probe");
                    ep.Auth = code == 401
                        ? new AttackSurfaceAuth { Required = true, Type = "http-401" }
                        : code == 403
                            ? new AttackSurfaceAuth { Required = true, Type = "http-403" }
                            : new AttackSurfaceAuth { Required = false, Type = "none (dev-artifact)" };

                    var snippet = body;
                    if (snippet.Length > 800)
                        snippet = snippet[..800] + "…";
                    if (media.Contains("html", StringComparison.OrdinalIgnoreCase) && snippet.Length > 400)
                        snippet = snippet[..400] + "…";

                    ep.ResponsePatterns["dev-artifact-get"] = new AttackSurfaceResponsePattern
                    {
                        Description = $"Development/sensitive path probe — HTTP {code}",
                        BodySnippet = string.IsNullOrWhiteSpace(snippet) ? null : snippet.Trim(),
                        BodyLength = body.Length,
                        Count = 1
                    };

                    ep.TestPriority = code is >= 200 and < 300 && IsHighRiskDevArtifactPath(rel)
                        ? "high"
                        : code is 401 or 403 ? "medium" : "low";

                    addedCandidates.Add(ep);
                    report.DevArtifactHits++;
                }
                catch (Exception ex)
                {
                    report.OpenApiErrors.Add($"dev-artifact {ShortUrl(full)}: {ex.Message}");
                }
            }
        }
    }

    private static bool IsHighRiskDevArtifactPath(string rel)
    {
        var r = rel.ToLowerInvariant();
        if (r.Contains(".env")) return true;
        if (r.Contains(".git/")) return true;
        if (r.Contains("docker-compose") || r.Contains("dockerfile")) return true;
        if (r.Contains(".svn")) return true;
        if (r.Contains("composer.json") || r.Contains("package.json") || r.Contains("package-lock") ||
            r.Contains("yarn.lock"))
            return true;
        return false;
    }

    private static List<string> CollectProbeOrigins(Uri pageUri, List<NetworkEntry> entries, int maxOrigins)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in EnumerateDistinctOrigins(pageUri, entries))
        {
            if (set.Count >= maxOrigins)
                break;
            _ = set.Add(u);
        }

        return set.ToList();
    }

    private static IEnumerable<string> EnumerateDistinctOrigins(Uri pageUri, List<NetworkEntry> entries)
    {
        if (pageUri.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            yield return pageUri.GetLeftPart(UriPartial.Authority);

        foreach (var e in entries)
        {
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u))
                continue;
            if (!u.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                continue;
            yield return u.GetLeftPart(UriPartial.Authority);
        }
    }

    private static bool LooksLikePotentialSpecBody(string url, string contentType, string body)
    {
        var trim = body.TrimStart();
        var u = url.ToLowerInvariant();
        var pathLooks =
            u.Contains("openapi", StringComparison.OrdinalIgnoreCase)
            || u.Contains("swagger", StringComparison.OrdinalIgnoreCase)
            || u.Contains("api-docs", StringComparison.OrdinalIgnoreCase)
            || u.EndsWith("/openapi.json", StringComparison.OrdinalIgnoreCase)
            || u.EndsWith("/swagger.json", StringComparison.OrdinalIgnoreCase);

        var jsonish =
            contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
            contentType.Contains("yaml", StringComparison.OrdinalIgnoreCase) ||
            trim.StartsWith('{');

        var markers =
            trim.Contains("\"paths\"", StringComparison.OrdinalIgnoreCase)
            && (trim.Contains("\"openapi\"", StringComparison.OrdinalIgnoreCase)
                || trim.Contains("\"swagger\":", StringComparison.OrdinalIgnoreCase));

        return jsonish && markers && (pathLooks || trim.Contains("\"paths\"", StringComparison.OrdinalIgnoreCase));
    }

    private static bool LooksLikeWordPressRestIndex(string url, string contentType, string body)
    {
        if (!url.Contains("wp-json", StringComparison.OrdinalIgnoreCase))
            return false;

        var trim = body.TrimStart();
        if (trim.Length < 60 || !trim.StartsWith('{'))
            return false;

        if (!trim.Contains("\"routes\"", StringComparison.Ordinal))
            return false;

        return contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
               contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase) ||
               string.IsNullOrWhiteSpace(contentType);
    }

    /// <remarks><paramref name="discoveredViaTag"/> is applied by caller unless already set internally.</remarks>
    private static bool TryParseOpenApiBody(
        string payload,
        Uri documentUri,
        int maxWordPressRestRoutes,
        out List<AttackSurfaceEndpoint> endpoints,
        out string discoveredViaTag,
        out string? error)
    {
        endpoints = new List<AttackSurfaceEndpoint>();
        error = null;
        discoveredViaTag = "openapi-json";

        var trim = payload.TrimStart();
        try
        {
            if (trim.StartsWith('{'))
            {
                using var jd = JsonDocument.Parse(payload);
                var root = jd.RootElement;

                if (TryExpandJsonOpenApi(documentUri, root, endpoints, out error))
                    return true;

                discoveredViaTag = "wordpress-rest";
                if (TryExpandWordPressRoutes(documentUri, root, endpoints, maxWordPressRestRoutes, out var wpErr))
                {
                    error = null;
                    return true;
                }

                discoveredViaTag = "openapi-json";
                error = string.IsNullOrEmpty(error)
                    ? wpErr
                    : string.IsNullOrEmpty(wpErr)
                        ? error
                        : $"{error} | {wpErr}";
                return false;
            }

            if (trim.StartsWith("openapi:", StringComparison.OrdinalIgnoreCase)
                || trim.StartsWith("swagger:", StringComparison.OrdinalIgnoreCase))
            {
                discoveredViaTag = "openapi-yaml";
                return YamlExpandOpenApi(payload, documentUri, endpoints, out error);
            }

            error = "expected JSON object or openapi/swagger YAML";
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryExpandJsonOpenApi(
        Uri documentUri,
        JsonElement root,
        List<AttackSurfaceEndpoint> endpoints,
        out string? error)
    {
        error = null;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("paths", out var pathsEl) || pathsEl.ValueKind != JsonValueKind.Object)
        {
            error = "missing paths object";
            return false;
        }

        bool isSwagger2 = root.TryGetProperty("swagger", out var sw) &&
                          sw.ValueKind == JsonValueKind.String &&
                          sw.GetString()!.StartsWith("2", StringComparison.Ordinal);

        foreach (var baseUrl in ResolveServerBases(documentUri, root, isSwagger2))
            endpoints.AddRange(ExpandOperationsFromPaths(baseUrl, pathsEl));

        if (endpoints.Count == 0)
            error = "paths contains no HTTP operations";

        return endpoints.Count > 0;
    }

    private static string ResolveWordPressRestBase(Uri documentUri)
    {
        var path = documentUri.AbsolutePath;
        var idx = path.IndexOf("/wp-json", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
            return path.Substring(0, idx + "/wp-json".Length);

        return "/wp-json";
    }

    private static string NormalizeWordPressRouteTemplate(string routeKey) =>
        WordPressNamedPathParam.Replace(routeKey ?? "", m => "{" + m.Groups[1].Value + "}");

    private static bool TryExpandWordPressRoutes(
        Uri documentUri,
        JsonElement root,
        List<AttackSurfaceEndpoint> endpoints,
        int maxRoutes,
        out string? error)
    {
        error = null;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("routes", out var routes) || routes.ValueKind != JsonValueKind.Object)
        {
            error = "missing WordPress routes object";
            return false;
        }

        if (!root.TryGetProperty("namespaces", out var nsProp) ||
            nsProp.ValueKind != JsonValueKind.Array ||
            nsProp.GetArrayLength() == 0)
        {
            error = "missing WordPress namespaces array";
            return false;
        }

        var authorityBase = documentUri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        var restBasePrefix = ResolveWordPressRestBase(documentUri);
        var restBase = $"{authorityBase}{restBasePrefix}".TrimEnd('/');

        var before = endpoints.Count;

        foreach (var routeProp in routes.EnumerateObject())
        {
            if (endpoints.Count - before >= maxRoutes)
                break;

            var rawKey = routeProp.Name;
            if (string.IsNullOrEmpty(rawKey) || rawKey == "/")
                continue;

            if (routeProp.Value.ValueKind != JsonValueKind.Object)
                continue;

            if (!routeProp.Value.TryGetProperty("methods", out var methEl) ||
                methEl.ValueKind != JsonValueKind.Array)
                continue;

            var methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in methEl.EnumerateArray())
            {
                if (m.ValueKind != JsonValueKind.String)
                    continue;

                var s = m.GetString();
                if (string.IsNullOrEmpty(s) || !HttpVerbs.Contains(s))
                    continue;

                methods.Add(s.Trim().ToUpperInvariant());
            }

            if (methods.Count == 0)
                continue;

            var pathTpl = NormalizeWordPressRouteTemplate(rawKey);
            if (!pathTpl.StartsWith('/'))
                pathTpl = "/" + pathTpl;

            var ep = CreateSyntheticEndpoint(restBase, pathTpl, methods);
            ep.Auth = new AttackSurfaceAuth { Required = false, Type = "none (wordpress-rest)" };
            endpoints.Add(ep);
        }

        if (endpoints.Count <= before)
        {
            error = "WordPress routes contained no usable method entries";
            return false;
        }

        return true;
    }

    private static IEnumerable<AttackSurfaceEndpoint> ExpandOperationsFromPaths(string baseUrl, JsonElement pathsEl)
    {
        foreach (var pathProp in pathsEl.EnumerateObject())
        {
            var apiPath = pathProp.Name;
            if (pathProp.Value.ValueKind != JsonValueKind.Object)
                continue;

            var methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var op in pathProp.Value.EnumerateObject())
            {
                if (HttpVerbs.Contains(op.Name))
                    methods.Add(op.Name.Trim().ToUpperInvariant());
            }

            if (methods.Count > 0)
                yield return CreateSyntheticEndpoint(baseUrl, apiPath, methods);
        }
    }

    private static List<string> ResolveServerBases(Uri documentUri, JsonElement root, bool isSwagger2)
    {
        if (isSwagger2)
        {
            var hostPart = "";
            if (root.TryGetProperty("host", out var hEl) && hEl.ValueKind == JsonValueKind.String)
                hostPart = hEl.GetString()!.Trim();

            if (string.IsNullOrWhiteSpace(hostPart))
                hostPart = documentUri.IsDefaultPort
                    ? documentUri.Host
                    : $"{documentUri.Host}:{documentUri.Port}";

            var basePath = "/";
            if (root.TryGetProperty("basePath", out var bpEl) && bpEl.ValueKind == JsonValueKind.String &&
                !string.IsNullOrEmpty(bpEl.GetString()))
                basePath = bpEl.GetString()!;

            var schemes = new List<string>();
            if (root.TryGetProperty("schemes", out var schEl) && schEl.ValueKind == JsonValueKind.Array)
                schemes.AddRange(schEl.EnumerateArray().Select(j => j.GetString()).Where(s => !string.IsNullOrEmpty(s))!.Select(s => s!));

            if (schemes.Count == 0)
                schemes.Add(documentUri.Scheme);

            return schemes.Select(schn =>
                    $"{(string.IsNullOrEmpty(schn) ? documentUri.Scheme : schn.Trim().ToLowerInvariant())}" +
                    $"://{hostPart.Trim()}{SwaggerBasePathNormalize(basePath)}")
                .Select(s => s.TrimEnd('/'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        if (!root.TryGetProperty("servers", out var srvEl) || srvEl.ValueKind != JsonValueKind.Array)
            return [documentUri.GetLeftPart(UriPartial.Authority).TrimEnd('/')];


        var bases = srvEl
            .EnumerateArray()
            .Where(svr => svr.ValueKind == JsonValueKind.Object &&
                          svr.TryGetProperty("url", out var uEl) &&
                          uEl.ValueKind == JsonValueKind.String)
            .Select(svr => svr.GetProperty("url").GetString()!)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Select(u => ResolveServerAgainstDocument(documentUri, u!).TrimEnd('/'))
            .Where(u => !string.IsNullOrEmpty(u))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return bases.Count > 0 ? bases : [documentUri.GetLeftPart(UriPartial.Authority).TrimEnd('/')];
    }

    private static string SwaggerBasePathNormalize(string basePath)
    {
        if (string.IsNullOrEmpty(basePath) || basePath == "/")
            return "";
        return basePath.StartsWith('/') ? basePath : "/" + basePath;
    }

    private static string ResolveServerAgainstDocument(Uri documentUri, string serverUrl)
    {
        var s = serverUrl.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var abs))
            return abs.ToString().TrimEnd('/');
        try
        {
            var authority = documentUri.GetLeftPart(UriPartial.Authority);
            var rooted = authority.TrimEnd('/') + (s.StartsWith('/') ? "" : "/") + s;
            return new Uri(rooted).ToString().TrimEnd('/');
        }
        catch
        {
            return documentUri.GetLeftPart(UriPartial.Authority).TrimEnd('/') + "/" + s.TrimStart('/');
        }
    }

    private static bool YamlExpandOpenApi(string yaml, Uri documentUri, List<AttackSurfaceEndpoint> acc,
        out string? error)
    {
        error = null;
        try
        {
            using var reader = new StringReader(yaml);
            var ys = new YamlStream();
            ys.Load(reader);
            var root = ys.Documents.FirstOrDefault()?.RootNode as YamlMappingNode;
            if (root?.Children.TryGetValue(new YamlScalarNode("paths"), out var pn) != true ||
                pn is not YamlMappingNode pathsMap)
            {
                error = "YAML: paths missing";
                return false;
            }

            foreach (var (pathScalar, node) in pathsMap.Children)
            {
                if (pathScalar is not YamlScalarNode pk)
                    continue;
                var apiPath = pk.Value ?? "";
                if (node is not YamlMappingNode opMap)
                    continue;

                var methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var (methScalar, _) in opMap.Children)
                {
                    if (methScalar is not YamlScalarNode mk || string.IsNullOrEmpty(mk.Value))
                        continue;
                    if (!HttpVerbs.Contains(mk.Value))
                        continue;
                    methods.Add(mk.Value.Trim().ToUpperInvariant());
                }

                if (methods.Count == 0)
                    continue;

                foreach (var baseUrl in ResolveYamlServerBases(root, documentUri))
                    acc.Add(CreateSyntheticEndpoint(baseUrl, apiPath, methods));
            }

            if (acc.Count == 0)
                error = "YAML: no operations in paths";
            return acc.Count > 0;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static List<string> ResolveYamlServerBases(YamlMappingNode root, Uri docUri)
    {
        if (root.Children.ContainsKey(new YamlScalarNode("swagger")))
        {
            var hostField = YamlString(root, "host");
            var hostAuthority = string.IsNullOrWhiteSpace(hostField)
                ? (docUri.IsDefaultPort ? docUri.Host : $"{docUri.Host}:{docUri.Port}")
                : hostField!.Trim();

            var basePath = YamlString(root, "basePath") ?? "/";
            var schemes = YamlStringSequence(root, "schemes");
            if (schemes.Count == 0)
                schemes = [docUri.Scheme];

            return schemes.Select(schn =>
                    $"{(string.IsNullOrEmpty(schn) ? docUri.Scheme : schn.Trim().ToLowerInvariant())}://{hostAuthority}{SwaggerBasePathNormalize(basePath)}")
                .Select(s => s.TrimEnd('/'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        if (root.Children.TryGetValue(new YamlScalarNode("servers"), out var sn) &&
            sn is YamlSequenceNode seqNode)
        {
            var servers = seqNode.Children
                .OfType<YamlMappingNode>()
                .Select(m => YamlStringFromMap(m, "url"))
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u => ResolveServerAgainstDocument(docUri, u!).TrimEnd('/'))
                .Where(u => !string.IsNullOrEmpty(u))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return servers.Count > 0 ? servers : [docUri.GetLeftPart(UriPartial.Authority).TrimEnd('/')];
        }

        return [docUri.GetLeftPart(UriPartial.Authority).TrimEnd('/')];
    }

    private static string? YamlString(YamlMappingNode root, string key)
    {
        if (!root.Children.TryGetValue(new YamlScalarNode(key), out var n) || n is not YamlScalarNode sn)
            return null;
        return string.IsNullOrWhiteSpace(sn.Value) ? null : sn.Value!;
    }

    private static List<string> YamlStringSequence(YamlMappingNode root, string key)
    {
        if (!root.Children.TryGetValue(new YamlScalarNode(key), out var n) || n is not YamlSequenceNode seq)
            return [];
        var r = new List<string>();
        foreach (var c in seq.Children)
        {
            if (c is YamlScalarNode s && !string.IsNullOrWhiteSpace(s.Value))
                r.Add(s.Value!);
        }

        return r;
    }

    private static string? YamlStringFromMap(YamlMappingNode m, string key)
    {
        if (!m.Children.TryGetValue(new YamlScalarNode(key), out var v) || v is not YamlScalarNode sv)
            return null;
        return sv.Value;
    }

    private static AttackSurfaceEndpoint CreateSyntheticEndpoint(string baseUrl, string pathTemplate,
        HashSet<string> methods)
    {
        var ep = CreateEndpoint(baseUrl, pathTemplate);
        foreach (var m in methods)
            ep.Methods.Add(m);

        ep.RequestCount = 0;
        ep.TestPriority = AttackSurfaceMapper.EstimatePriorityWithoutTraffic(ep);
        return ep;
    }

    private static AttackSurfaceEndpoint CreateEndpoint(string baseUrl, string pathTemplate)
    {
        pathTemplate ??= "";
        // Avoid host + absolute URL doubling when pathTemplate is already a full URL.
        if (Uri.TryCreate(pathTemplate, UriKind.Absolute, out var abs))
        {
            pathTemplate = abs.AbsolutePath + abs.Query;
        }

        var rel = pathTemplate.StartsWith('/') ? pathTemplate : "/" + pathTemplate;
        var displayUrl = baseUrl.TrimEnd('/') + rel;

        var pathParams = new List<string>();
        foreach (Match m in PathBraceParams.Matches(rel))
            pathParams.Add(m.Groups[1].Value);

        return new AttackSurfaceEndpoint
        {
            Url = displayUrl,
            UrlTemplate = AttackSurfaceMapper.TemplatizePath(rel),
            Methods = [],
            Parameters = new AttackSurfaceParameters
            {
                Path = pathParams.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p).ToList()
            },
            Auth = new AttackSurfaceAuth { Required = false, Type = "none (openapi)" },
            ResponsePatterns = new Dictionary<string, AttackSurfaceResponsePattern>()
        };
    }

    private static async Task CollectJsHintsAsync(
        AutomationContext ctx,
        Uri pageUri,
        Options options,
        AttackSurfaceEnrichmentReport report,
        List<AttackSurfaceEndpoint> targets,
        CancellationToken ct)
    {
        List<string> scriptUrls;
        try
        {
            scriptUrls = await JsBundleScripts.ListExternalScriptsAsync(ctx).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            report.JsErrors.Add("script discovery: " + ex.Message);
            return;
        }

        if (scriptUrls.Count == 0)
            return;

        if (scriptUrls.Count > options.MaxScripts)
            scriptUrls = scriptUrls.Take(options.MaxScripts).ToList();

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Clamp(options.HttpTimeoutMs, 3_000, 60_000))
        };

        var seenMergeKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var scriptUrl in scriptUrls)
        {
            ct.ThrowIfCancellationRequested();
            report.JsScriptsFetched++;
            string text;
            try
            {
                var cookieHeader = await ctx.GetCookieHeaderForUrl(scriptUrl).ConfigureAwait(false);
                using var req = new HttpRequestMessage(HttpMethod.Get, scriptUrl);
                req.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} AttackSurface-js");
                if (!string.IsNullOrEmpty(cookieHeader))
                    req.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

                using var resp =
                    await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                text = resp.IsSuccessStatusCode
                    ? await ReadBodyCapped(resp, Math.Clamp(options.MaxBytesPerScript, 8192, 2_000_000), ct)
                        .ConfigureAwait(false)
                    : "";
            }
            catch (Exception ex)
            {
                report.JsErrors.Add(ShortUrl(scriptUrl) + ": " + ex.Message);
                continue;
            }

            if (string.IsNullOrEmpty(text))
                continue;

            if (!Uri.TryCreate(scriptUrl, UriKind.Absolute, out var scriptUri))
                scriptUri = pageUri;

            foreach (var raw in JsHintPatterns.SelectMany(rx => ExtractMatches(rx, text)))
            {
                if (seenMergeKeys.Count >= options.MaxJsHintPaths)
                    break;

                if (!TryNormalizeJsHint(raw, pageUri, scriptUri, out var absolute))
                    continue;

                var key = AttackSurfaceMapper.EndpointMergeKeyFromUrl(absolute.ToString());
                if (!seenMergeKeys.Add(key))
                    continue;

                var origin = absolute.GetLeftPart(UriPartial.Authority).TrimEnd('/');
                var hintMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "GET" };
                var ep = CreateSyntheticEndpoint(origin, absolute.AbsolutePath, hintMethods);
                ep.Auth = new AttackSurfaceAuth { Required = false, Type = "none (js-bundle-hint)" };
                ep.DiscoveredVia.Add("js-bundle");
                targets.Add(ep);
                report.JsHintUrlsExtracted++;
            }

            if (seenMergeKeys.Count >= options.MaxJsHintPaths)
                break;
        }
    }

    private static IEnumerable<string> ExtractMatches(Regex rx, string text)
    {
        foreach (Match m in rx.Matches(text))
        {
            if (!m.Success)
                continue;
            var v = m.Groups["u"].Value;
            if (!string.IsNullOrWhiteSpace(v))
                yield return v;
        }
    }

    private static bool TryNormalizeJsHint(string raw, Uri pageUri, Uri scriptOrigin, out Uri absolute)
    {
        absolute = null!;
        var s = raw.Trim();
        if (s.StartsWith("//", StringComparison.Ordinal))
            s = pageUri.Scheme + ":" + s;

        if (Uri.TryCreate(s, UriKind.Absolute, out var fully))
        {
            if (!fully.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                return false;
            return LooksLikeApiCandidate(fully, out absolute);
        }

        if (!s.StartsWith('/'))
            return false;

        var bases = new[] { scriptOrigin.GetLeftPart(UriPartial.Authority), pageUri.GetLeftPart(UriPartial.Authority) };
        foreach (var b in bases.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(b.TrimEnd('/') + s, UriKind.Absolute, out var relAbs))
                continue;
            return LooksLikeApiCandidate(relAbs, out absolute);
        }

        return false;
    }

    private static bool LooksLikeApiCandidate(Uri uri, out Uri absolute)
    {
        absolute = uri;
        var path = uri.AbsolutePath;
        var pl = path.ToLowerInvariant();
        foreach (var ext in JsBundleStaticSuffixes)
        {
            if (pl.EndsWith(ext))
                return false;
        }

        var hit =
            pl.Contains("/api", StringComparison.Ordinal) ||
            (pl.StartsWith("/v") && Regex.IsMatch(pl, @"^/v\d/")) ||
            pl.StartsWith("/graphql") ||
            pl.StartsWith("/wp-json") ||
            pl.StartsWith("/jsonapi/") ||
            pl.StartsWith("/rest/") ||
            pl.StartsWith("/rpc/") ||
            pl.StartsWith("/trpc/");
        hit &= path.Length is >= 2 and <= 520;
        return hit;
    }

    private static async Task<string> ReadBodyCapped(HttpResponseMessage resp, int maxBytes,
        CancellationToken ct)
    {
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[maxBytes + 1];
        var n = 0;
        int read;
        while (n <= maxBytes && (read = await stream.ReadAsync(buffer.AsMemory(n, buffer.Length - n), ct)) > 0)
            n += read;

        if (n >= maxBytes)
            return Encoding.UTF8.GetString(buffer, 0, maxBytes);

        return Encoding.UTF8.GetString(buffer, 0, n);
    }

    private static bool IsPlausibleDevArtifactHit(string relPath, string mediaType, string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return false;

        var rel = relPath.ToLowerInvariant();
        var expectsJson = rel.Contains("package.json") || rel.Contains("package-lock")
            || rel.Contains("composer.json") || rel.Contains("composer.lock")
            || rel.Contains("openapi.json") || rel.Contains("swagger.json");
        var expectsYaml = rel.EndsWith(".yaml") || rel.EndsWith(".yml");
        var expectsEnv = rel.Contains(".env");
        var expectsGit = rel.Contains(".git/");
        var expectsPlainText = expectsEnv || rel.EndsWith(".lock") || rel.Contains("requirements");

        if (mediaType.Contains("html", StringComparison.OrdinalIgnoreCase))
        {
            if (expectsJson || expectsYaml || expectsEnv || expectsGit || expectsPlainText)
                return false;
            if (LooksLikeHtmlDocument(body) && !rel.EndsWith(".md"))
                return false;
        }

        if (LooksLikeHtmlDocument(body) && (expectsJson || expectsYaml || expectsEnv || expectsGit))
            return false;

        if (expectsJson && !LooksLikeJsonDocument(body))
            return false;

        if (expectsYaml && !LooksLikeYamlDocument(body))
            return false;

        if (expectsEnv && LooksLikeHtmlDocument(body))
            return false;

        if (expectsGit && !body.Contains("[core]", StringComparison.Ordinal)
            && !body.Contains("repositoryformatversion", StringComparison.OrdinalIgnoreCase)
            && LooksLikeHtmlDocument(body))
            return false;

        return true;
    }

    private static bool LooksLikeHtmlDocument(string body)
    {
        var trimmed = body.TrimStart();
        if (trimmed.StartsWith("<!DOCTYPE html", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase))
            return true;

        var lower = body.ToLowerInvariant();
        return lower.Contains("<head") && lower.Contains("<body");
    }

    private static bool LooksLikeJsonDocument(string body)
    {
        var trimmed = body.TrimStart();
        return trimmed.StartsWith('{') || trimmed.StartsWith('[');
    }

    private static bool LooksLikeYamlDocument(string body)
    {
        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return true;

        return trimmed.Contains(':') && !LooksLikeHtmlDocument(body);
    }

    private static string ShortUrl(string url) =>
        url.Length > 180 ? url.Substring(0, 177) + "…" : url;
}
