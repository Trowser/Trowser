using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Same-origin link/form crawler (BFS) to populate the network log before security scans — lighter than Monkey Trowser.
/// </summary>
public static class LightSiteCrawler
{
    public sealed class CrawlOptions
    {
        public int MaxDepth { get; set; } = 2;
        public int MaxPages { get; set; } = 30;
        public bool FollowLinks { get; set; } = true;
        public bool EnumerateForms { get; set; } = true;
        /// <summary>When true, GET-navigate form action URLs (still no POST submissions).</summary>
        public bool VisitFormActions { get; set; } = true;
        public int DelayMs { get; set; } = 200;

        /// <summary>
        /// SPA mode: extract routerLink/hash routes from DOM and click navigation elements to discover client-side routes.
        /// </summary>
        public bool SpaMode { get; set; }

        /// <summary>Max click interactions per page when <see cref="SpaMode"/> is enabled.</summary>
        public int MaxInteractionsPerPage { get; set; } = 20;

        /// <summary>Wait after each click for XHR/navigation to settle (ms).</summary>
        public int WaitAfterInteractionMs { get; set; } = 400;

        /// <summary>
        /// Host allowed for navigation and link discovery. Defaults to the current page host.
        /// Uses <see cref="SecurityHostScope"/> matching (loopback aliases collapse).
        /// </summary>
        public string? AllowedHost { get; set; }

        /// <summary>Glob patterns that must match for a path to be visited (empty = allow all).</summary>
        public List<string> IncludePaths { get; set; } = [];

        /// <summary>Glob patterns to never visit (e.g. <c>/admin/*</c>).</summary>
        public List<string> ExcludePaths { get; set; } = [];

        /// <summary>Optional regex patterns matched against path+query.</summary>
        public List<string> ExcludeUrlPatterns { get; set; } = [];

        /// <summary>
        /// When true (default), skip logout/sign-out/SLO-style paths and logout-looking SPA controls
        /// so crawl does not terminate the browser session.
        /// </summary>
        public bool ExcludeLogout { get; set; } = true;
    }

    public sealed class CrawlResult
    {
        public int PagesVisited { get; set; }
        public int LinksDiscovered { get; set; }
        public int FormActionsDiscovered { get; set; }
        public int InteractionsPerformed { get; set; }
        public int NetworkEntriesAfter { get; set; }
        public int ElapsedMs { get; set; }
        public bool StoppedEarly { get; set; }
        public List<string> VisitedUrls { get; set; } = [];
        public List<string> SkippedUrls { get; set; } = [];
        public List<string> Errors { get; set; } = [];
        public bool ExcludeLogout { get; set; }
    }

    public static async Task<CrawlResult> RunAsync(
        AutomationContext ctx,
        CrawlOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new CrawlResult { ExcludeLogout = options.ExcludeLogout };
        var startUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(startUrl) || !Uri.TryCreate(startUrl, UriKind.Absolute, out var startUri))
        {
            result.Errors.Add("No valid page URL loaded — navigate first.");
            result.ElapsedMs = (int)sw.ElapsedMilliseconds;
            return result;
        }

        var allowedHost = options.AllowedHost ?? startUri.Host;
        var origin = BuildScopedOrigin(startUri, allowedHost);
        var extractUrlsJs = BuildExtractUrlsJs(allowedHost);

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skipped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<(string Path, int Depth)>();
        var startPath = BuildPathFromUri(startUri, options.SpaMode);
        if (string.IsNullOrEmpty(startPath)) startPath = "/";

        if (SecurityHostScope.Matches(startUri.Host, allowedHost))
        {
            if (IsExcluded(options, startPath, skipped, result))
            {
                result.Errors.Add(
                    $"Start path '{startPath}' is excluded — starting from origin root instead.");
                TryEnqueue(options, "/", 0, queue, visited, skipped, result);
            }
            else
            {
                queue.Enqueue((startPath, 0));
                visited.Add(NormalizePath(startPath, options.SpaMode));
            }
        }
        else
        {
            result.Errors.Add(
                $"Current page host '{startUri.Host}' is outside scope host '{allowedHost}' — starting from origin root.");
            TryEnqueue(options, "/", 0, queue, visited, skipped, result);
        }

        var entriesBefore = ctx.Network.Entries.Count;

        try
        {
            while (queue.Count > 0 && result.PagesVisited < options.MaxPages)
            {
                ct.ThrowIfCancellationRequested();
                var (path, depth) = queue.Dequeue();
                if (IsExcluded(options, path, skipped, result))
                    continue;

                var target = origin + path;

                if (Uri.TryCreate(target, UriKind.Absolute, out var targetUri)
                    && !SecurityHostScope.Matches(targetUri.Host, allowedHost))
                {
                    continue;
                }

                try
                {
                    await ctx.Navigate(target);
                    if (!await IsCurrentHostInScopeAsync(ctx, allowedHost))
                    {
                        result.Errors.Add($"{path}: navigation left scope host '{allowedHost}'");
                        await TryReturnToOriginAsync(ctx, origin, result, path);
                        continue;
                    }

                    result.PagesVisited++;
                    result.VisitedUrls.Add(target);

                    if (depth >= options.MaxDepth || !options.FollowLinks)
                        continue;

                    await EnqueueDiscoveredPaths(
                        ctx, options, allowedHost, extractUrlsJs, depth, queue, visited, skipped, result);

                    if (options.SpaMode)
                        await DiscoverViaInteractions(
                            ctx, options, allowedHost, origin, extractUrlsJs, depth, queue, visited, skipped, result, target);
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"{path}: {ex.Message}");
                }

                if (options.DelayMs > 0)
                    await Task.Delay(options.DelayMs, ct);
            }
        }
        catch (OperationCanceledException)
        {
            result.StoppedEarly = true;
            result.Errors.Add("Crawl stopped early (timeout or cancellation).");
        }

        result.NetworkEntriesAfter = ctx.Network.Entries.Count;
        result.ElapsedMs = (int)sw.ElapsedMilliseconds;
        return result;
    }

    private static string BuildScopedOrigin(Uri startUri, string allowedHost)
    {
        // Accept host, host:port, or full origin — UriBuilder rejects "localhost:3010" as a hostname.
        var host = SecurityHostScope.NormalizeHostFilter(allowedHost);
        if (string.IsNullOrWhiteSpace(host))
            host = startUri.Host;

        var port = startUri.IsDefaultPort ? -1 : startUri.Port;
        if (!SecurityHostScope.Matches(startUri.Host, host))
            port = -1;

        // If the filter carried an explicit non-default port, prefer it when the start URL host matches.
        if (TryParseHostPort(allowedHost, out var filterPort)
            && SecurityHostScope.Matches(startUri.Host, host)
            && filterPort > 0)
            port = filterPort;

        var builder = new UriBuilder(startUri.Scheme, host, port > 0 ? port : -1);
        return builder.Uri.GetLeftPart(UriPartial.Authority);
    }

    private static bool TryParseHostPort(string hostFilter, out int port)
    {
        port = -1;
        var t = hostFilter.Trim();
        if (t.Contains("://", StringComparison.Ordinal)
            && Uri.TryCreate(t, UriKind.Absolute, out var absolute))
        {
            port = absolute.IsDefaultPort ? -1 : absolute.Port;
            return port > 0;
        }

        var lastColon = t.LastIndexOf(':');
        if (lastColon > 0 && t.IndexOf(':') == lastColon
            && int.TryParse(t.AsSpan(lastColon + 1), out var parsed)
            && parsed > 0)
        {
            port = parsed;
            return true;
        }

        return false;
    }

    private static string BuildExtractUrlsJs(string allowedHost)
    {
        var hostJson = JsonSerializer.Serialize(allowedHost.ToLowerInvariant());
        return $$"""
            (() => {
              const allowedHost = {{hostJson}};
              const hostMatches = (hostname) => {
                const h = (hostname || '').toLowerCase();
                if (h === allowedHost) return true;
                const loopback = (x) => x === 'localhost' || x === '::1' || x.startsWith('127.');
                if (loopback(allowedHost) && loopback(h)) return true;
                return false;
              };
              const out = { links: [], forms: [] };
              const add = (arr, raw) => {
                if (!raw || raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw.startsWith('tel:')) return;
                try {
                  const u = new URL(raw, location.href);
                  if (!hostMatches(u.hostname)) return;
                  let p = u.pathname + u.search;
                  if (u.hash && u.hash.startsWith('#/')) p += u.hash;
                  if (p && p !== '/') arr.push(p);
                } catch {}
              };
              document.querySelectorAll('a[href]').forEach(a => add(out.links, a.getAttribute('href')));
              document.querySelectorAll('form[action]').forEach(f => {
                const m = (f.getAttribute('method') || 'GET').toUpperCase();
                add(out.forms, f.getAttribute('action') || location.pathname);
                out.forms.push('__method__:' + m);
              });
              document.querySelectorAll('[routerlink], [routerLink], [ng-reflect-router-link]').forEach(el => {
                const rl = el.getAttribute('routerlink') || el.getAttribute('routerLink')
                  || el.getAttribute('ng-reflect-router-link');
                if (rl) add(out.links, rl.startsWith('/') ? rl : '/' + rl);
              });
              document.querySelectorAll('a[href^="#/"]').forEach(a => add(out.links, a.getAttribute('href')));
              out.links = [...new Set(out.links)];
              out.forms = [...new Set(out.forms.filter(x => !x.startsWith('__method__:')))];
              return JSON.stringify(out);
            })()
            """;
    }

    private static bool IsExcluded(
        CrawlOptions options,
        string path,
        HashSet<string> skipped,
        CrawlResult result)
    {
        if (SecurityPathExclusion.IsPathAllowed(
                path,
                options.IncludePaths,
                options.ExcludePaths,
                options.ExcludeUrlPatterns,
                options.ExcludeLogout))
            return false;

        var norm = NormalizePath(path, options.SpaMode);
        if (skipped.Add(norm))
            result.SkippedUrls.Add(norm);
        return true;
    }

    private static void TryEnqueue(
        CrawlOptions options,
        string path,
        int depth,
        Queue<(string Path, int Depth)> queue,
        HashSet<string> visited,
        HashSet<string> skipped,
        CrawlResult result)
    {
        var norm = NormalizePath(path, options.SpaMode);
        if (IsExcluded(options, norm, skipped, result))
            return;
        if (visited.Add(norm))
            queue.Enqueue((norm, depth));
    }

    private static async Task EnqueueDiscoveredPaths(
        AutomationContext ctx,
        CrawlOptions options,
        string allowedHost,
        string extractUrlsJs,
        int depth,
        Queue<(string Path, int Depth)> queue,
        HashSet<string> visited,
        HashSet<string> skipped,
        CrawlResult result)
    {
        if (!await IsCurrentHostInScopeAsync(ctx, allowedHost))
            return;

        var json = await ctx.ExecuteJs(extractUrlsJs);
        if (string.IsNullOrWhiteSpace(json))
            return;

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("links", out var linksEl) && linksEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var link in linksEl.EnumerateArray())
            {
                var p = link.GetString();
                if (string.IsNullOrWhiteSpace(p)) continue;
                result.LinksDiscovered++;
                TryEnqueue(options, p, depth + 1, queue, visited, skipped, result);
            }
        }

        if (options.EnumerateForms && options.VisitFormActions
            && root.TryGetProperty("forms", out var formsEl) && formsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var form in formsEl.EnumerateArray())
            {
                var p = form.GetString();
                if (string.IsNullOrWhiteSpace(p)) continue;
                result.FormActionsDiscovered++;
                TryEnqueue(options, p, depth + 1, queue, visited, skipped, result);
            }
        }
    }

    private static async Task DiscoverViaInteractions(
        AutomationContext ctx,
        CrawlOptions options,
        string allowedHost,
        string origin,
        string extractUrlsJs,
        int depth,
        Queue<(string Path, int Depth)> queue,
        HashSet<string> visited,
        HashSet<string> skipped,
        CrawlResult result,
        string pageUrl)
    {
        if (!await IsCurrentHostInScopeAsync(ctx, allowedHost))
            return;

        List<Dictionary<string, object>> elements;
        try
        {
            elements = await ctx.GetInteractiveElements();
        }
        catch (Exception ex)
        {
            result.Errors.Add($"spa-interaction snapshot: {ex.Message}");
            return;
        }

        var clickables = elements
            .Where(el => IsClickable(el) && !IsExternalAnchor(el, allowedHost))
            .Where(el => !ShouldSkipClick(options, el, skipped, result))
            .Take(options.MaxInteractionsPerPage)
            .ToList();

        foreach (var el in clickables)
        {
            if (result.PagesVisited + queue.Count >= options.MaxPages)
                break;

            var selector = GetSelector(el);
            if (string.IsNullOrEmpty(selector)) continue;

            var urlBefore = await SafeGetUrl(ctx) ?? pageUrl;
            try
            {
                await ctx.Click(selector);
                result.InteractionsPerformed++;
            }
            catch (Exception ex)
            {
                result.Errors.Add($"click {DescribeElement(el)}: {ex.Message}");
                continue;
            }

            if (options.WaitAfterInteractionMs > 0)
                await Task.Delay(options.WaitAfterInteractionMs);

            var urlAfter = await SafeGetUrl(ctx);
            if (urlAfter != null && NormalizeUrl(urlAfter) != NormalizeUrl(urlBefore))
            {
                if (Uri.TryCreate(urlAfter, UriKind.Absolute, out var afterUri)
                    && SecurityHostScope.Matches(afterUri.Host, allowedHost))
                {
                    var path = BuildPathFromUri(afterUri, options.SpaMode);
                    result.LinksDiscovered++;
                    if (IsExcluded(options, path, skipped, result))
                    {
                        // Click reached an excluded URL (e.g. logout) — leave immediately.
                    }
                    else
                    {
                        TryEnqueue(options, path, depth + 1, queue, visited, skipped, result);
                    }
                }
                else if (urlAfter != null
                         && Uri.TryCreate(urlAfter, UriKind.Absolute, out var offScopeUri)
                         && !SecurityHostScope.Matches(offScopeUri.Host, allowedHost))
                {
                    result.Errors.Add($"click {DescribeElement(el)}: left scope ({offScopeUri.Host})");
                }

                try
                {
                    await ctx.Navigate(pageUrl);
                    await Task.Delay(Math.Min(options.WaitAfterInteractionMs, 500));
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"return to {pageUrl}: {ex.Message}");
                    return;
                }
            }

            if (await IsCurrentHostInScopeAsync(ctx, allowedHost))
            {
                await EnqueueDiscoveredPaths(
                    ctx, options, allowedHost, extractUrlsJs, depth, queue, visited, skipped, result);
            }
        }
    }

    private static bool ShouldSkipClick(
        CrawlOptions options,
        Dictionary<string, object> el,
        HashSet<string> skipped,
        CrawlResult result)
    {
        var href = GetProp(el, "href");
        if (!string.IsNullOrWhiteSpace(href) && IsExcluded(options, href, skipped, result))
            return true;

        if (!options.ExcludeLogout)
            return false;

        var label = GetProp(el, "label");
        var text = GetProp(el, "text");
        if (SecurityPathExclusion.LooksLikeLogoutLabel(label)
            || SecurityPathExclusion.LooksLikeLogoutLabel(text))
        {
            var key = "label:" + (string.IsNullOrEmpty(label) ? text : label);
            if (skipped.Add(key))
                result.SkippedUrls.Add(key);
            return true;
        }

        return false;
    }

    private static bool IsExternalAnchor(Dictionary<string, object> el, string allowedHost)
    {
        if (!GetTag(el).Equals("a", StringComparison.OrdinalIgnoreCase))
            return false;

        var href = GetProp(el, "href");
        if (string.IsNullOrWhiteSpace(href))
            return false;

        if (!Uri.TryCreate(href, UriKind.Absolute, out var uri))
            return false;

        return !SecurityHostScope.Matches(uri.Host, allowedHost);
    }

    private static async Task<bool> IsCurrentHostInScopeAsync(AutomationContext ctx, string allowedHost)
    {
        var current = await SafeGetUrl(ctx);
        return current != null
               && Uri.TryCreate(current, UriKind.Absolute, out var uri)
               && SecurityHostScope.Matches(uri.Host, allowedHost);
    }

    private static async Task TryReturnToOriginAsync(
        AutomationContext ctx,
        string origin,
        CrawlResult result,
        string path)
    {
        try
        {
            await ctx.Navigate(origin + "/");
        }
        catch (Exception ex)
        {
            result.Errors.Add($"{path}: failed to return to scope origin: {ex.Message}");
        }
    }

    private static string BuildPathFromUri(Uri uri, bool spaMode)
    {
        var path = uri.PathAndQuery;
        if (spaMode && uri.Fragment.StartsWith("#/", StringComparison.Ordinal))
            path += uri.Fragment;
        return path;
    }

    private static string NormalizePath(string path, bool spaMode)
    {
        if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (Uri.TryCreate(path, UriKind.Absolute, out var uri))
                return NormalizePath(BuildPathFromUri(uri, spaMode), spaMode);
        }

        if (!path.StartsWith('/')) path = "/" + path;

        var hashIdx = path.IndexOf('#');
        if (hashIdx >= 0)
        {
            if (spaMode && path[hashIdx..].StartsWith("#/", StringComparison.Ordinal))
                return path;
            path = path[..hashIdx];
        }

        return path;
    }

    private static async Task<string?> SafeGetUrl(AutomationContext ctx)
    {
        try { return await ctx.GetCurrentUrl(); }
        catch { return null; }
    }

    private static string NormalizeUrl(string url)
    {
        var idx = url.IndexOf('#');
        if (idx >= 0) url = url[..idx];
        return url.TrimEnd('/');
    }

    private static bool IsClickable(Dictionary<string, object> el)
    {
        var tag = GetTag(el);
        var type = GetProp(el, "type");
        var enabled = GetBoolProp(el, "enabled", true);
        var visible = GetBoolProp(el, "visible", false);
        var refNum = GetIntProp(el, "ref", -1);

        if (!enabled || !visible || refNum < 0) return false;

        return tag is "button" or "a" ||
               (tag == "input" && type is "button" or "submit" or "reset");
    }

    private static string? GetSelector(Dictionary<string, object> el) =>
        el.TryGetValue("selector", out var s) ? s?.ToString() : null;

    private static string GetTag(Dictionary<string, object> el) =>
        GetProp(el, "tag").ToLowerInvariant();

    private static string GetProp(Dictionary<string, object> el, string key) =>
        el.TryGetValue(key, out var v) && v != null ? v.ToString() ?? "" : "";

    private static bool GetBoolProp(Dictionary<string, object> el, string key, bool defaultValue)
    {
        if (!el.TryGetValue(key, out var v) || v == null) return defaultValue;
        if (v is bool b) return b;
        if (v is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.True) return true;
            if (je.ValueKind == JsonValueKind.False) return false;
        }
        return bool.TryParse(v.ToString(), out var parsed) ? parsed : defaultValue;
    }

    private static int GetIntProp(Dictionary<string, object> el, string key, int defaultValue)
    {
        if (!el.TryGetValue(key, out var v) || v == null) return defaultValue;
        if (v is int i) return i;
        if (v is long l) return (int)l;
        if (v is JsonElement je && je.ValueKind == JsonValueKind.Number)
            return je.GetInt32();
        return int.TryParse(v.ToString(), out var parsed) ? parsed : defaultValue;
    }

    private static string DescribeElement(Dictionary<string, object> el)
    {
        var label = GetProp(el, "label");
        var tag = GetTag(el);
        return string.IsNullOrEmpty(label) ? tag : $"{tag} '{label}'";
    }
}
