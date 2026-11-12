using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Discovers JSON API paths from page JavaScript and probes POST+JSON variants of
/// GET forms / url-encoded requests that carry CSRF tokens.
/// </summary>
public sealed class JsonApiCsrfProber
{
    public sealed class ProbeOptions
    {
        public bool IncludeJsScan { get; set; } = true;
        public bool IncludeGetFormJsonPost { get; set; } = true;
        public bool IncludeNetworkJsonVariants { get; set; } = true;
        public bool IncludeViewSourceScan { get; set; } = true;
        public int MaxProbes { get; set; } = 10;
        public int MaxExternalScripts { get; set; } = 5;
        public string? HostFilter { get; set; }
    }

    public sealed class Hint
    {
        public string Source { get; set; } = "";
        public string Url { get; set; } = "";
        public string Method { get; set; } = "POST";
        public string? Evidence { get; set; }
    }

    public sealed class ProbeResult
    {
        public List<Hint> Hints { get; set; } = [];
        public List<CsrfScenario> Scenarios { get; set; } = [];
        public int ProbesRun { get; set; }
    }

    private static readonly Regex[] JsApiPatterns =
    [
        new(@"fetch\s*\(\s*[""'](?<u>(?:https?:)?\/[^""']+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"axios\.(?:post|put|patch|delete|request)\s*\(\s*[""'](?<u>(?:https?:)?\/[^""']+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"XMLHttpRequest[^;]{0,120}\.open\s*\(\s*[""'](?:POST|PUT|PATCH|DELETE)[""']\s*,\s*[""'](?<u>(?:https?:)?\/[^""']+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\.(?:post|put|patch|delete)\s*\(\s*[""'](?<u>(?:https?:)?\/[^""']+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"(?<![/\w])(?<u>/api/[a-zA-Z0-9_./\-{}]{1,240})", RegexOptions.Compiled),
        new(@"(?<![/\w])(?<u>/v\d(?:/[\w\-./{}]*)?)", RegexOptions.Compiled),
        new(@"Content-Type\s*:\s*[""']application/json[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    private static readonly Regex SourceApiPathPattern = new(
        @"(?:fetch|axios|XMLHttpRequest|POST|PUT|PATCH)[^\n]{0,200}?(?<u>/[a-zA-Z0-9_./\-{}]{4,240})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private const string PageScanJs = """
        (function(){
          try {
            var out = { pageUrl: location.href, inlineScripts: [], scriptUrls: [], viewSourceLinks: [] };
            document.querySelectorAll('script:not([src])').forEach(function(s) {
              var t = s.textContent || '';
              if (t.length > 0) out.inlineScripts.push(t.substring(0, 80000));
            });
            document.querySelectorAll('script[src]').forEach(function(s) {
              if (s.src) out.scriptUrls.push(s.src);
            });
            document.querySelectorAll('a[href]').forEach(function(a) {
              var h = (a.getAttribute('href') || '').toLowerCase();
              if (/view_source|showsource|view-source|source\.php|viewsources/.test(h))
                out.viewSourceLinks.push(new URL(a.getAttribute('href'), location.href).href);
            });
            return JSON.stringify(out);
          } catch (e) {
            return JSON.stringify({ error: e.message || String(e), inlineScripts: [], scriptUrls: [], viewSourceLinks: [] });
          }
        })()
        """;

    private const string GetFormsJs = """
        (function(){
          try {
            var forms = [];
            document.querySelectorAll('form').forEach(function(f, idx) {
              var method = (f.getAttribute('method') || f.method || 'get').trim().toUpperCase();
              if (method && method !== 'GET') return;
              var action = f.action || location.href;
              var fields = [];
              f.querySelectorAll('input, select, textarea, button').forEach(function(el) {
                var tag = (el.tagName || '').toLowerCase();
                var type = (el.getAttribute('type') || el.type || '').toLowerCase();
                if (type === 'hidden' || type === 'text' || type === 'password' || type === 'email' ||
                    type === 'number' || type === 'submit' || type === 'button' || type === 'checkbox' ||
                    tag === 'select' || tag === 'textarea' || tag === 'button') {
                  fields.push({
                    name: el.getAttribute('name') || el.name || '',
                    type: type || tag,
                    value: (el.value || el.getAttribute('value') || '').substring(0, 200)
                  });
                }
              });
              forms.push({ action: action, fields: fields });
            });
            return JSON.stringify({ pageUrl: location.href, forms: forms });
          } catch (e) {
            return JSON.stringify({ error: e.message || String(e), forms: [] });
          }
        })()
        """;

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public JsonApiCsrfProber(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    private sealed class ProbeBudget
    {
        public int Remaining { get; set; }
        public ProbeBudget(int max) => Remaining = max;
        public bool TryConsume(int count = 1)
        {
            if (Remaining <= 0) return false;
            Remaining -= count;
            return true;
        }
    }

    public async Task<ProbeResult> RunAsync(
        IReadOnlyList<NetworkEntry> entries,
        ProbeOptions options,
        CancellationToken ct = default)
    {
        var result = new ProbeResult();
        var budget = new ProbeBudget(Math.Clamp(options.MaxProbes, 1, 50));
        var pageUri = await ResolvePageUriAsync();

        if (options.IncludeJsScan)
            await CollectJsHintsAsync(pageUri, options, result, ct);

        if (options.IncludeViewSourceScan)
            await CollectViewSourceHintsAsync(pageUri, options, result, ct);

        if (options.IncludeNetworkJsonVariants)
            CollectNetworkJsonHints(entries, options, pageUri, result);

        string? pageTokenName = null;
        string? pageTokenValue = null;
        if (options.IncludeGetFormJsonPost || result.Hints.Count > 0)
            (pageTokenName, pageTokenValue) = await ExtractPageCsrfTokenAsync();

        if (options.IncludeGetFormJsonPost && budget.Remaining > 0)
            await ProbeGetFormsAsJsonPostAsync(options, pageUri, result, budget, ct);

        if (budget.Remaining > 0)
            await ProbeNetworkJsonVariantsAsync(entries, options, pageUri, result, budget, ct);

        if (budget.Remaining > 0 && pageTokenValue != null)
            await ProbeDiscoveredHintsAsync(options, pageUri, pageTokenName, pageTokenValue, result, budget, ct);

        result.ProbesRun = Math.Clamp(options.MaxProbes, 1, 50) - budget.Remaining;
        return result;
    }

    private async Task<Uri?> ResolvePageUriAsync()
    {
        var pageUrl = await _ctx.GetCurrentUrl();
        return Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri) ? uri : null;
    }

    private async Task CollectJsHintsAsync(Uri? pageUri, ProbeOptions options, ProbeResult result, CancellationToken ct)
    {
        var json = await _ctx.ExecuteJs(PageScanJs);
        if (string.IsNullOrWhiteSpace(json)) return;

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out _)) return;

        if (root.TryGetProperty("inlineScripts", out var scripts) && scripts.ValueKind == JsonValueKind.Array)
        {
            foreach (var script in scripts.EnumerateArray())
            {
                ct.ThrowIfCancellationRequested();
                var text = script.GetString();
                if (string.IsNullOrEmpty(text)) continue;
                AddHintsFromText(text, "inline-script", pageUri, result);
            }
        }

        if (root.TryGetProperty("scriptUrls", out var urls) && urls.ValueKind == JsonValueKind.Array)
        {
            var fetched = 0;
            foreach (var urlEl in urls.EnumerateArray())
            {
                if (fetched >= options.MaxExternalScripts) break;
                ct.ThrowIfCancellationRequested();
                var scriptUrl = urlEl.GetString();
                if (string.IsNullOrEmpty(scriptUrl) || pageUri == null) continue;
                if (!Uri.TryCreate(scriptUrl, UriKind.Absolute, out var scriptUri)) continue;
                if (!SecurityHostScope.Matches(scriptUri.Host, pageUri.Host)) continue;

                try
                {
                    var resp = await _ctx.Fetch(scriptUrl, "GET", null, null, 8000);
                    using var respDoc = JsonDocument.Parse(resp);
                    if (!respDoc.RootElement.TryGetProperty("body", out var bodyEl)) continue;
                    var body = bodyEl.GetString();
                    if (string.IsNullOrEmpty(body)) continue;
                    fetched++;
                    AddHintsFromText(body, $"script:{scriptUri.AbsolutePath}", pageUri, result);
                }
                catch { /* skip unreachable scripts */ }
            }
        }

        if (root.TryGetProperty("viewSourceLinks", out var viewLinks) && viewLinks.ValueKind == JsonValueKind.Array)
        {
            foreach (var linkEl in viewLinks.EnumerateArray())
            {
                var link = linkEl.GetString();
                if (!string.IsNullOrEmpty(link))
                    TryAddHint(result, new Hint { Source = "view-source-link", Url = link, Method = "GET", Evidence = "Page links to server-side source viewer" });
            }
        }
    }

    private async Task CollectViewSourceHintsAsync(Uri? pageUri, ProbeOptions options, ProbeResult result, CancellationToken ct)
    {
        var existing = result.Hints.Where(h => h.Source is "view-source-link" or "view-source").Select(h => h.Url).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var link in existing)
        {
            ct.ThrowIfCancellationRequested();
            if (options.HostFilter != null && Uri.TryCreate(link, UriKind.Absolute, out var linkUri)
                && !SecurityHostScope.Matches(linkUri.Host, options.HostFilter))
                continue;

            try
            {
                var resp = await _ctx.Fetch(link, "GET", null, null, 10000);
                using var doc = JsonDocument.Parse(resp);
                if (!doc.RootElement.TryGetProperty("body", out var bodyEl)) continue;
                var body = bodyEl.GetString();
                if (string.IsNullOrEmpty(body)) continue;

                AddHintsFromText(body, "view-source", pageUri, result);
                foreach (Match m in SourceApiPathPattern.Matches(body))
                {
                    var path = m.Groups["u"].Value;
                    if (path.Length < 4) continue;
                    TryAddHint(result, new Hint
                    {
                        Source = "view-source",
                        Url = ResolveUrl(path, pageUri),
                        Method = "POST",
                        Evidence = $"Server source references API path {path}"
                    });
                }
            }
            catch { /* skip */ }
        }
    }

    private static void CollectNetworkJsonHints(
        IReadOnlyList<NetworkEntry> entries, ProbeOptions options, Uri? pageUri, ProbeResult result)
    {
        foreach (var entry in entries)
        {
            if (entry.StatusCode is < 200 or >= 400) continue;
            if (options.HostFilter != null && !SecurityHostScope.Matches(entry.Host, options.HostFilter))
                continue;

            var reqCt = GetRequestContentType(entry);
            if (reqCt.Contains("json", StringComparison.OrdinalIgnoreCase)
                && entry.Method is "POST" or "PUT" or "PATCH" or "DELETE")
            {
                TryAddHint(result, new Hint
                {
                    Source = "network-json",
                    Url = entry.Url,
                    Method = entry.Method,
                    Evidence = "Captured mutating request with application/json"
                });
            }
        }
    }

    private async Task<(string? Name, string? Value)> ExtractPageCsrfTokenAsync()
    {
        var tokens = await CsrfDomScraper.ScrapeAsync(_ctx);
        foreach (var (name, value) in tokens)
        {
            if (CsrfTokenHeuristics.IsCsrfFieldCandidate(name, "hidden", value))
                return (name, value);
        }

        return (null, null);
    }

    private async Task ProbeGetFormsAsJsonPostAsync(
        ProbeOptions options, Uri? pageUri, ProbeResult result, ProbeBudget budget, CancellationToken ct)
    {
        var json = await _ctx.ExecuteJs(GetFormsJs);
        if (string.IsNullOrWhiteSpace(json)) return;

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out _)) return;
        if (!root.TryGetProperty("forms", out var forms) || forms.ValueKind != JsonValueKind.Array)
            return;

        foreach (var form in forms.EnumerateArray())
        {
            if (budget.Remaining <= 0) break;
            ct.ThrowIfCancellationRequested();

            var action = form.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";
            if (!Uri.TryCreate(action, UriKind.Absolute, out var actionUri)) continue;
            if (options.HostFilter != null && !SecurityHostScope.Matches(actionUri.Host, options.HostFilter))
                continue;

            var fields = ParseFields(form);
            var csrfField = fields.FirstOrDefault(f =>
                CsrfTokenHeuristics.IsCsrfFieldCandidate(f.Name, f.Type, f.Value));
            if (csrfField == null || string.IsNullOrEmpty(csrfField.Value)) continue;
            if (!FormLooksMutating(actionUri, fields)) continue;

            var fieldMap = BuildFieldMap(fields);
            await RunJsonPostProbeSuiteAsync(
                actionUri.GetLeftPart(UriPartial.Path),
                fieldMap,
                csrfField.Name,
                csrfField.Value,
                "get-form-json-post",
                $"GET form at {actionUri.AbsolutePath} probed as POST application/json",
                result,
                budget,
                ct);
        }
    }

    private async Task ProbeNetworkJsonVariantsAsync(
        IReadOnlyList<NetworkEntry> entries, ProbeOptions options, Uri? pageUri, ProbeResult result, ProbeBudget budget, CancellationToken ct)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (budget.Remaining <= 0) break;
            ct.ThrowIfCancellationRequested();
            if (entry.StatusCode is < 200 or >= 400) continue;
            if (options.HostFilter != null && !SecurityHostScope.Matches(entry.Host, options.HostFilter))
                continue;

            Dictionary<string, string>? fieldMap = null;
            string? csrfName = null;
            string? csrfValue = null;
            string targetUrl;
            string sourceTag;

            if (entry.Method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrEmpty(entry.Url)
                && Uri.TryCreate(entry.Url, UriKind.Absolute, out var getUri))
            {
                fieldMap = ParseQueryString(getUri.Query);
                if (fieldMap.Count == 0) continue;
                foreach (var kv in fieldMap)
                {
                    if (CsrfTokenHeuristics.IsCsrfFieldCandidate(kv.Key, "hidden", kv.Value))
                    {
                        csrfName = kv.Key;
                        csrfValue = kv.Value;
                        break;
                    }
                }
                if (csrfName == null) continue;
                targetUrl = getUri.GetLeftPart(UriPartial.Path);
                sourceTag = "network-get-json-post";
            }
            else if (entry.Method is "POST" or "PUT" or "PATCH"
                     && !string.IsNullOrEmpty(entry.RequestBody)
                     && !entry.RequestBody.TrimStart().StartsWith('{'))
            {
                fieldMap = CsrfTokenHeuristics.EnumerateBodyFields(entry.RequestBody)
                    .ToDictionary(kv => kv.Name, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
                foreach (var kv in fieldMap)
                {
                    if (CsrfTokenHeuristics.IsCsrfFieldCandidate(kv.Key, null, kv.Value))
                    {
                        csrfName = kv.Key;
                        csrfValue = kv.Value;
                        break;
                    }
                }
                if (csrfName == null) continue;
                targetUrl = entry.Url;
                sourceTag = "network-form-json-post";
            }
            else continue;

            var dedup = $"{sourceTag}|{targetUrl}|{csrfName}";
            if (!seen.Add(dedup)) continue;

            await RunJsonPostProbeSuiteAsync(
                targetUrl,
                fieldMap!,
                csrfName!,
                csrfValue!,
                sourceTag,
                $"Captured {entry.Method} request probed as POST application/json alternative",
                result,
                budget,
                ct);
        }
    }

    private async Task ProbeDiscoveredHintsAsync(
        ProbeOptions options, Uri? pageUri, string? tokenName, string? tokenValue,
        ProbeResult result, ProbeBudget budget, CancellationToken ct)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var hint in result.Hints.Where(h => h.Method is "POST" or "PUT" or "PATCH"))
        {
            if (budget.Remaining <= 0) break;
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(tokenValue) || string.IsNullOrEmpty(tokenName)) break;

            var url = hint.Url;
            if (options.HostFilter != null && Uri.TryCreate(url, UriKind.Absolute, out var hintUri)
                && !SecurityHostScope.Matches(hintUri.Host, options.HostFilter))
                continue;
            if (!seen.Add(url)) continue;

            var fieldMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [tokenName] = tokenValue
            };

            await RunJsonPostProbeSuiteAsync(
                url,
                fieldMap,
                tokenName,
                tokenValue,
                "json-api-discovered",
                $"JS/source-discovered path probed with page CSRF token ({hint.Source})",
                result,
                budget,
                ct);
        }
    }

    private async Task RunJsonPostProbeSuiteAsync(
        string url,
        Dictionary<string, string> fieldMap,
        string csrfFieldName,
        string csrfFieldValue,
        string sourceTag,
        string descriptionPrefix,
        ProbeResult result,
        ProbeBudget budget,
        CancellationToken ct)
    {
        if (!budget.TryConsume()) return;
        ct.ThrowIfCancellationRequested();

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json, text/plain, */*",
        };

        var baselineBody = SerializeJson(fieldMap);
        var (baselineStatus, baselineResponseBody) = await PostJsonWithBodyAsync(url, headers, baselineBody);
        if (baselineStatus is 404 or 405 or 415 or 501)
        {
            result.Scenarios.Add(new CsrfScenario
            {
                Url = url,
                Path = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.PathAndQuery : url,
                Method = "POST",
                TestType = "json-api-not-accepted",
                Severity = "info",
                Description = $"{descriptionPrefix}. POST application/json returned HTTP {baselineStatus} — JSON API path may not exist at this URL.",
                OriginalStatus = baselineStatus,
                TestStatus = baselineStatus,
                Vulnerable = false,
                TokenLocation = $"body: {csrfFieldName}",
            });
            return;
        }

        _log($"  [JSON API probe] POST {url} baseline → {baselineStatus}", "#888888");

        if (!budget.TryConsume()) return;
        var withoutToken = new Dictionary<string, string>(fieldMap, StringComparer.OrdinalIgnoreCase);
        withoutToken.Remove(csrfFieldName);
        var (missingStatus, missingResponseBody) = await PostJsonWithBodyAsync(url, headers, SerializeJson(withoutToken));
        var missingEval = CsrfProbeResponseEvaluator.EvaluateMissingTokenProbe(
            baselineStatus, baselineResponseBody, missingStatus, missingResponseBody);
        result.Scenarios.Add(new CsrfScenario
        {
            Url = url,
            Path = Uri.TryCreate(url, UriKind.Absolute, out var pu) ? pu.PathAndQuery : url,
            Method = "POST",
            TestType = missingEval.Vulnerable ? "json-api-missing-token" : "json-api-missing-token-inconclusive",
            Severity = missingEval.Severity,
            Description = $"{descriptionPrefix}. POST JSON without CSRF field \"{csrfFieldName}\" {missingEval.Summary}",
            OriginalStatus = baselineStatus,
            TestStatus = missingStatus,
            Vulnerable = missingEval.Vulnerable,
            TokenLocation = $"body: {csrfFieldName}",
        });

        if (!budget.TryConsume()) return;
        var headerOnly = new Dictionary<string, string>(fieldMap, StringComparer.OrdinalIgnoreCase);
        headerOnly.Remove(csrfFieldName);
        var headerProbeHeaders = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
        {
            ["X-CSRF-Token"] = csrfFieldValue
        };
        var (headerStatus, headerResponseBody) = await PostJsonWithBodyAsync(url, headerProbeHeaders, SerializeJson(headerOnly));
        if (headerStatus >= 200 && headerStatus < 300)
        {
            var headerEval = CsrfProbeResponseEvaluator.EvaluateMissingTokenProbe(
                baselineStatus, baselineResponseBody, headerStatus, headerResponseBody);
            result.Scenarios.Add(new CsrfScenario
            {
                Url = url,
                Path = Uri.TryCreate(url, UriKind.Absolute, out var hu) ? hu.PathAndQuery : url,
                Method = "POST",
                TestType = "json-api-header-token-only",
                Severity = headerEval.Vulnerable ? "medium" : "low",
                Description = $"{descriptionPrefix}. POST JSON with CSRF token only in X-CSRF-Token header (not in JSON body). {headerEval.Summary}",
                OriginalStatus = baselineStatus,
                TestStatus = headerStatus,
                Vulnerable = false,
                TokenLocation = "header: X-CSRF-Token",
            });
        }
    }

    private async Task<(int Status, string Body)> PostJsonWithBodyAsync(
        string url, Dictionary<string, string> headers, string jsonBody)
    {
        try
        {
            headers.Remove("Cookie");
            headers.Remove("cookie");
            var responseJson = await _ctx.Fetch(url, "POST", headers, jsonBody, 10000);
            using var doc = JsonDocument.Parse(responseJson);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = root.TryGetProperty("body", out var bodyEl)
                ? bodyEl.ValueKind == JsonValueKind.String ? bodyEl.GetString() ?? "" : bodyEl.GetRawText()
                : "";
            return (status, body);
        }
        catch
        {
            return (0, "");
        }
    }

    private static void AddHintsFromText(string text, string source, Uri? pageUri, ProbeResult result)
    {
        foreach (var pattern in JsApiPatterns)
        {
            foreach (Match m in pattern.Matches(text))
            {
                if (!m.Success) continue;
                var raw = m.Groups.Count > 1 && m.Groups["u"].Success ? m.Groups["u"].Value : m.Value;
                if (string.IsNullOrWhiteSpace(raw) || raw.Length < 2) continue;
                if (raw.StartsWith("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;

                TryAddHint(result, new Hint
                {
                    Source = source,
                    Url = ResolveUrl(raw, pageUri),
                    Method = "POST",
                    Evidence = TruncateEvidence(m.Value)
                });
            }
        }
    }

    private static void TryAddHint(ProbeResult result, Hint hint)
    {
        if (result.Hints.Any(h => h.Url.Equals(hint.Url, StringComparison.OrdinalIgnoreCase)
                                  && h.Source.Equals(hint.Source, StringComparison.OrdinalIgnoreCase)))
            return;
        result.Hints.Add(hint);
    }

    private static string ResolveUrl(string raw, Uri? pageUri)
    {
        if (Uri.TryCreate(raw, UriKind.Absolute, out var abs))
            return abs.ToString();
        if (pageUri == null)
            return raw;
        if (Uri.TryCreate(pageUri, raw, out var rel))
            return rel.ToString();
        return new Uri(pageUri, raw.StartsWith('/') ? raw : "/" + raw).ToString();
    }

    private static string SerializeJson(Dictionary<string, string> fields) =>
        JsonSerializer.Serialize(fields);

    private static Dictionary<string, string> BuildFieldMap(List<FormField> fields)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in fields)
        {
            if (string.IsNullOrEmpty(f.Name)) continue;
            map[f.Name] = f.Value;
        }
        return map;
    }

    private static List<FormField> ParseFields(JsonElement formEl)
    {
        var list = new List<FormField>();
        if (!formEl.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Array)
            return list;
        foreach (var f in fields.EnumerateArray())
        {
            list.Add(new FormField
            {
                Name = f.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                Type = f.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "",
                Value = f.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "",
            });
        }
        return list;
    }

    private static bool FormLooksMutating(Uri actionUri, List<FormField> fields)
    {
        if (fields.Any(f => f.Type.Equals("password", StringComparison.OrdinalIgnoreCase)))
            return true;
        foreach (var seg in actionUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (seg.Contains("password", StringComparison.OrdinalIgnoreCase)
                || seg.Contains("change", StringComparison.OrdinalIgnoreCase)
                || seg.Contains("admin", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return fields.Any(f => f.Type is "submit" or "button"
            && (f.Name.Contains("change", StringComparison.OrdinalIgnoreCase)
                || f.Value.Contains("change", StringComparison.OrdinalIgnoreCase)));
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var q = query.TrimStart('?');
        if (string.IsNullOrEmpty(q)) return map;
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var key = eq >= 0 ? Uri.UnescapeDataString(part[..eq]) : Uri.UnescapeDataString(part);
            var val = eq >= 0 ? Uri.UnescapeDataString(part[(eq + 1)..]) : "";
            if (!string.IsNullOrEmpty(key))
                map[key] = val;
        }
        return map;
    }

    private static string GetRequestContentType(NetworkEntry entry)
    {
        foreach (var h in entry.RequestHeaders)
        {
            if (h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                return h.Value;
        }
        return "";
    }

    private static string TruncateEvidence(string s) =>
        s.Length <= 120 ? s : s[..117] + "...";

    private sealed class FormField
    {
        public string Name { get; init; } = "";
        public string Type { get; init; } = "";
        public string Value { get; init; } = "";
    }
}
