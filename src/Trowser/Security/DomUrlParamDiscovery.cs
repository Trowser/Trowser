using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Scans inline scripts for URL parameter names used with location.hash/search/href parsing.
/// Helps hash-based DOM XSS traces prefix payloads correctly (e.g. DVWA <c>default=</c>).
/// </summary>
public static class DomUrlParamDiscovery
{
    public sealed record Result(
        IReadOnlyList<string> ParamNames,
        string? PreferredHashParam,
        string? PreferredQueryParam,
        string? SourceHint,
        bool UsesRawHashFragment = false);

    public static async Task<Result?> DiscoverAsync(AutomationContext context)
    {
        try
        {
            var json = await context.ExecuteJs(BuildDiscoveryScript());
            if (string.IsNullOrWhiteSpace(json)) return null;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err))
                return null;

            var names = new List<string>();
            if (root.TryGetProperty("params", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in arr.EnumerateArray())
                {
                    var name = item.GetString();
                    if (!string.IsNullOrWhiteSpace(name))
                        names.Add(name);
                }
            }

            var usesRawHash = root.TryGetProperty("usesRawHashFragment", out var ur)
                              && ur.ValueKind == JsonValueKind.True;

            if (names.Count == 0 && !usesRawHash) return null;

            var hashParam = root.TryGetProperty("preferredHashParam", out var hp) && hp.ValueKind == JsonValueKind.String
                ? hp.GetString()
                : null;
            var queryParam = root.TryGetProperty("preferredQueryParam", out var qp) && qp.ValueKind == JsonValueKind.String
                ? qp.GetString()
                : null;
            var hint = root.TryGetProperty("sourceHint", out var sh) && sh.ValueKind == JsonValueKind.String
                ? sh.GetString()
                : null;

            return new Result(names, hashParam, queryParam, hint, usesRawHash);
        }
        catch
        {
            return null;
        }
    }

    internal static string BuildDiscoveryScript() => """
        (function() {
            try {
                var names = [];
                var hashHints = {};
                var queryHints = {};
                var scripts = document.querySelectorAll('script:not([src])');
                var patterns = [
                    /indexOf\s*\(\s*["']([^"']+)=["']/gi,
                    /lastIndexOf\s*\(\s*["']([^"']+)=["']/gi,
                    /(?:get|has)\s*\(\s*["']([^"']+)["']\s*\)/gi,
                    /getParameter\s*\(\s*["']([^"']+)["']/gi,
                    /match\s*\(\s*\/\^\?\?([^=\/]+)=/gi,
                    /[?&](tpl|template|layout|partial|view|render|html|content|sandbox|theme|skin|module|component)=/gi
                ];

                function addName(name, kind) {
                    if (!name || name.length > 64) return;
                    if (names.indexOf(name) === -1) names.push(name);
                    if (kind === 'hash') hashHints[name] = (hashHints[name] || 0) + 1;
                    if (kind === 'query') queryHints[name] = (queryHints[name] || 0) + 1;
                }

                function classify(content, name) {
                    var lower = content.toLowerCase();
                    var idx = lower.indexOf(name.toLowerCase() + '=');
                    if (idx < 0) return;
                    var window = content.substring(Math.max(0, idx - 120), Math.min(content.length, idx + 120)).toLowerCase();
                    var usesSearch = window.indexOf('location.search') >= 0 || window.indexOf('urlsearchparams') >= 0
                        || window.indexOf('getparameter') >= 0;
                    var usesHash = window.indexOf('location.hash') >= 0 || window.indexOf('document.location.hash') >= 0;
                    var usesHrefIndexOf = window.indexOf('indexof') >= 0 && window.indexOf('location.href') >= 0;

                    if (usesHash || (usesHrefIndexOf && !usesSearch)) {
                        addName(name, 'hash');
                    } else if (usesSearch) {
                        addName(name, 'query');
                    } else if (window.indexOf('location.href') >= 0 || window.indexOf('document.location') >= 0) {
                        addName(name, 'hash');
                    }
                }

                for (var si = 0; si < scripts.length; si++) {
                    var content = scripts[si].textContent || '';
                    if (content.length < 8) continue;
                    for (var pi = 0; pi < patterns.length; pi++) {
                        var re = patterns[pi];
                        re.lastIndex = 0;
                        var m;
                        while ((m = re.exec(content)) !== null) {
                            var name = m[1];
                            addName(name, null);
                            classify(content, name);
                        }
                    }
                }

                function pick(hints) {
                    var best = null, bestScore = -1;
                    for (var k in hints) {
                        if (hints[k] > bestScore) { bestScore = hints[k]; best = k; }
                    }
                    return best;
                }

                var preferredHashParam = pick(hashHints);
                var preferredQueryParam = pick(queryHints);
                if (!preferredHashParam && !preferredQueryParam && names.length === 1) {
                    var only = names[0];
                    var all = '';
                    for (var si2 = 0; si2 < scripts.length; si2++) all += scripts[si2].textContent || '';
                    if (/location\.(?:hash|href)|document\.location/i.test(all))
                        preferredHashParam = only;
                }

                var sourceHint = null;
                if (preferredHashParam) sourceHint = 'location.hash/href indexOf("' + preferredHashParam + '=")';
                else if (preferredQueryParam) sourceHint = 'location.search param "' + preferredQueryParam + '"';

                var allScript = '';
                for (var si3 = 0; si3 < scripts.length; si3++) allScript += scripts[si3].textContent || '';
                var usesRawHashFragment = /location\.hash|document\.location\.hash/i.test(allScript)
                    && !preferredHashParam && names.length === 0;

                return JSON.stringify({
                    params: names,
                    preferredHashParam: preferredHashParam,
                    preferredQueryParam: preferredQueryParam,
                    sourceHint: sourceHint,
                    usesRawHashFragment: usesRawHashFragment
                });
            } catch (e) {
                return JSON.stringify({ error: e.message || String(e) });
            }
        })()
        """;
}
