using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Fetch externalized script assets referenced on the current page and scan for
/// hardcoded credentials, internal URLs, and debug/tuning hints (complements source-maps / framework flags).
/// </summary>
public static class JavaScriptStaticAudit
{
    public sealed class JsAssetFinding
    {
        public string Url { get; init; } = "";
        public int ByteLength { get; init; }
        public string? Error { get; init; }
        public List<JsContentHit> Hits { get; init; } = [];
        /// <summary>UTF-8 text scanned (for downstream harvest passes).</summary>
        internal string? ScannedText { get; init; }
    }

    public sealed class JsContentHit
    {
        public string Category { get; init; } = "";
        public string? Pattern { get; init; }
        public int Offset { get; init; }
        public string Snippet { get; init; } = "";
    }

    public sealed class JsAuditResult
    {
        public int ScriptsDiscovered { get; init; }
        public int ScriptsFetched { get; init; }
        public List<string> Summary { get; init; } = [];
        public List<JsAssetFinding> Assets { get; init; } = [];

        public string Format(bool includeDetails = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== JavaScript Static Audit (script[src] bundles) ===");
            sb.AppendLine($"Discovered: {ScriptsDiscovered}, Fetched: {ScriptsFetched}");
            sb.AppendLine();
            foreach (var line in Summary)
                sb.AppendLine(line);
            sb.AppendLine();

            foreach (var asset in Assets)
            {
                sb.AppendLine($"--- {asset.Url} ---");
                if (asset.Error != null)
                {
                    sb.AppendLine($"  Error: {asset.Error}");
                    sb.AppendLine();
                    continue;
                }

                sb.AppendLine($"  Bytes read: {asset.ByteLength}");
                if (asset.Hits.Count == 0)
                {
                    sb.AppendLine("  (no heuristic hits)");
                    sb.AppendLine();
                    continue;
                }

                var hits = includeDetails
                    ? asset.Hits
                    : asset.Hits.Where(h => h.Category != "truncation").ToList();

                foreach (var h in hits)
                {
                    sb.AppendLine($"  [{h.Category}] offset {h.Offset}");
                    if (h.Pattern != null)
                        sb.AppendLine($"    pattern: {h.Pattern}");
                    sb.AppendLine($"    {h.Snippet}");
                }

                sb.AppendLine();
            }

            return sb.ToString().TrimEnd();
        }
    }

    private static readonly Regex CredentialLike = new(
        @"(?i)(?:password|passwd|api[_-]?key|apikey|secret|access_token|refresh_token|auth_token|bearer|client_secret)\s*[=:]\s*['""]([^'""\r\n]{2,200})['""]",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    /// <summary>Private IPs, loopback, and *.local hostnames in URLs (heuristic; may have FPs on minified public URLs).</summary>
    private static readonly Regex InternalUrl = new(
        @"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[\w.-]+\.local)(?::\d+)?(?:/[^\s'"")]+)?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));

    private static readonly Regex Email = new(
        @"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly string[] DebugHints =
    [
        "ng.probe", "enableDebugTools", "ngDevMode", "NG_DEV_MODE",
        "REDUX_DEVTOOLS", "__REDUX_DEVTOOLS__", "__VUE_DEVTOOLS", "__VUE__",
        "localhost:4", "webpack:///./", "sourceURL=", "debugger;",
        "testingUsername", "testingPassword", "testUser", "testPassword", "DUMMY_PASSWORD", "DUMMY_SECRET"
    ];

    public static async Task<JsAuditResult> RunAsync(
        AutomationContext ctx,
        int maxScripts = 32,
        int maxBytesPerFile = 524_288,
        bool sameOriginOnly = false,
        int timeoutMs = 20_000,
        CancellationToken ct = default)
    {
        maxScripts = Math.Clamp(maxScripts, 1, 80);
        maxBytesPerFile = Math.Clamp(maxBytesPerFile, 8_192, 2_000_000);

        var listJson = await ctx.ExecuteJs(
            """
            (function(){
              var list = [];
              var seen = Object.create(null);
              try {
                document.querySelectorAll('script[src]').forEach(function(s) {
                  try {
                    var u = new URL(s.getAttribute('src'), location.href).href;
                    if (!seen[u]) { seen[u] = true; list.push(u); }
                  } catch(e) {}
                });
              } catch(e) {}
              return JSON.stringify({ href: location.href, scripts: list });
            })()
            """);
        ct.ThrowIfCancellationRequested();

        string pageHref;
        List<string> domScriptUrls;
        using (var doc = JsonDocument.Parse(listJson))
        {
            var r = doc.RootElement;
            pageHref = r.GetProperty("href").GetString() ?? "";
            domScriptUrls = r.GetProperty("scripts").EnumerateArray()
                .Select(x => x.GetString() ?? "")
                .Where(s => s.Length > 0 && LooksLikeScriptAssetUrl(s))
                .ToList();
        }

        if (!Uri.TryCreate(pageHref, UriKind.Absolute, out var pageUri))
            pageUri = null;

        if (sameOriginOnly && pageUri != null)
        {
            domScriptUrls = domScriptUrls.Where(u => Uri.TryCreate(u, UriKind.Absolute, out var a) && string.Equals(a.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        var unique = new List<string>();
        var order = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in domScriptUrls)
        {
            if (order.Add(u))
                unique.Add(u);
        }

        var fromDom = unique.Count;

        foreach (var u in CollectScriptUrlsFromNetwork(ctx, pageUri, sameOriginOnly))
        {
            if (!LooksLikeScriptAssetUrl(u)) continue;
            if (order.Add(u))
                unique.Add(u);
        }

        var discovered = unique.Count;
        var mergedFromNetwork = discovered - fromDom;

        if (maxScripts < unique.Count)
            unique = unique.Take(maxScripts).ToList();

        var assets = new List<JsAssetFinding>();
        var summary = new List<string>();
        foreach (var u in unique.Where(u => u.Contains(".development.js", StringComparison.OrdinalIgnoreCase)))
            summary.Add($"Production smell: script URL contains .development.js — {u}");

        if (discovered == 0)
        {
            summary.Add("No script URLs found from script[src] or the network log (inline scripts and dynamic imports are not enumerated).");
            return new JsAuditResult
            {
                ScriptsDiscovered = 0,
                ScriptsFetched = 0,
                Summary = summary,
                Assets = assets
            };
        }

        if (mergedFromNetwork > 0)
            summary.Add($"{mergedFromNetwork} script URL(s) merged from network log (script-like responses on the scoped origin).");

        if (unique.Count < discovered)
            summary.Add($"Capped to {maxScripts} scripts ({discovered} unique discovered).");

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(Math.Clamp(timeoutMs, 3_000, 120_000)) };

        foreach (var u in unique)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var msg = new HttpRequestMessage(HttpMethod.Get, u);
                using var resp = await http.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!resp.IsSuccessStatusCode)
                {
                    assets.Add(new JsAssetFinding
                    {
                        Url = u,
                        Error = $"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}"
                    });
                    continue;
                }

                var stream = await resp.Content.ReadAsStreamAsync(ct);
                var buffer = new byte[maxBytesPerFile + 1];
                var n = 0;
                int read;
                var cap = maxBytesPerFile + 1;
                while (n < cap && (read = await stream.ReadAsync(buffer.AsMemory(n, cap - n), ct)) > 0)
                {
                    n += read;
                }
                if (n > maxBytesPerFile)
                {
                    buffer = buffer.AsSpan(0, maxBytesPerFile).ToArray();
                    n = maxBytesPerFile;
                }
                var text = Encoding.UTF8.GetString(buffer, 0, n);
                var hits = ScanContent(text);
                if (n >= maxBytesPerFile)
                {
                    hits.Add(new JsContentHit
                    {
                        Category = "truncation",
                        Snippet = $"Content truncated to {maxBytesPerFile} bytes; patterns later in the file are not scanned."
                    });
                }
                assets.Add(new JsAssetFinding
                {
                    Url = u,
                    ByteLength = n,
                    Hits = hits,
                    ScannedText = text
                });
            }
            catch (Exception ex)
            {
                assets.Add(new JsAssetFinding { Url = u, Error = ex.Message });
            }
        }

        var fetched = assets.Count(a => a.Error == null);
        var withHits = assets.Count(a => a.Hits.Count > 0 && a.Hits.Any(h => h.Category != "truncation"));
        if (withHits == 0)
            summary.Add("No high-signal patterns detected in scanned bundles (heuristic scan — review large minified output manually for rare encodings).");
        else
            summary.Add($"Found pattern hits in {withHits} file(s) — see assets[].hits.");

        if (fetched < unique.Count)
            summary.Add("Some fetches may have failed — check assets with error set.");

        return new JsAuditResult
        {
            ScriptsDiscovered = discovered,
            ScriptsFetched = fetched,
            Summary = summary,
            Assets = assets
        };
    }

    /// <summary>
    /// Extensionless script tags (e.g. <c>/app</c>) and <c>.mjs</c> are included — secrets-harvest should not depend on <c>.js</c> in the URL alone.
    /// </summary>
    private static bool LooksLikeScriptAssetUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Contains(".js", StringComparison.OrdinalIgnoreCase);

        var path = uri.AbsolutePath;
        if (path.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase))
            return true;

        var lastSeg = uri.Segments.Length > 0
            ? Uri.UnescapeDataString(uri.Segments[^1].TrimEnd('/'))
            : "";
        if (string.IsNullOrEmpty(lastSeg)) return false;
        return lastSeg.IndexOf('.', StringComparison.Ordinal) < 0;
    }

    private static IEnumerable<string> CollectScriptUrlsFromNetwork(AutomationContext ctx, Uri? pageUri, bool sameOriginOnly)
    {
        foreach (var e in ctx.Network.Entries.OrderByDescending(x => x.Timestamp))
        {
            if (e.StatusCode < 200 || e.StatusCode >= 400)
                continue;
            if (!e.ResourceType.Equals("Script", StringComparison.OrdinalIgnoreCase))
                continue;
            if (string.IsNullOrEmpty(e.Url))
                continue;
            if (!LooksLikeScriptAssetUrl(e.Url))
                continue;
            if (sameOriginOnly && pageUri != null
                && Uri.TryCreate(e.Url, UriKind.Absolute, out var scriptUri)
                && !string.Equals(scriptUri.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;

            yield return e.Url;
        }
    }

    private static List<JsContentHit> ScanContent(string text)
    {
        var hits = new List<JsContentHit>();
        if (string.IsNullOrEmpty(text)) return hits;

        foreach (Match m in CredentialLike.Matches(text))
        {
            var secret = m.Groups.Count > 1 ? m.Groups[1].Value : "";
            if (secret.Length is > 0 and < 2) continue;
            if (SecretsHarvestHeuristics.IsPlaceholderSecretValue(secret)) continue;
            if (SecretsHarvestHeuristics.IsUiLabelSecretValue(secret)) continue;
            if (SecretsHarvestHeuristics.IsWeakCredentialAssignment(null, secret)) continue;
            var snip = Snippet(text, m.Index, 160);
            if (SecretsHarvestHeuristics.IsFalsePositiveSnippet(snip)) continue;
            // Form schema / i18n: "Password:" label next to type=password, not a hardcoded secret.
            if (LooksLikeFormLabelContext(snip, secret)) continue;
            hits.Add(new JsContentHit
            {
                Category = "credential-like-assignment",
                Pattern = m.Value[..Math.Min(80, m.Value.Length)] + (m.Value.Length > 80 ? "…" : ""),
                Offset = m.Index,
                Snippet = RedactSecret(snip)
            });
        }

        foreach (Match m in InternalUrl.Matches(text))
        {
            var snip = Snippet(text, m.Index, 120);
            hits.Add(new JsContentHit
            {
                Category = "internal-or-private-url",
                Pattern = m.Value,
                Offset = m.Index,
                Snippet = snip
            });
        }

        foreach (var hint in DebugHints)
        {
            for (var i = 0; i < text.Length;)
            {
                var p = text.IndexOf(hint, i, StringComparison.Ordinal);
                if (p < 0) break;
                var snip = Snippet(text, p, 120);
                hits.Add(new JsContentHit
                {
                    Category = "debug-or-test-tuning",
                    Pattern = hint,
                    Offset = p,
                    Snippet = snip
                });
                i = p + hint.Length;
            }
        }

        foreach (var hit in AssetSecretsCommentMiner.ScanText(text, "js-bundle"))
        {
            if (hit.Category is "comment-block" or "comment-hygiene")
            {
                if (!CommentBlockContainsSecretToken(hit.Snippet))
                    continue;
            }
            hits.Add(new JsContentHit
            {
                Category = hit.Category,
                Offset = hit.Offset,
                Snippet = hit.Snippet
            });
        }

        // Email and password assignment on same line or close (same 320-char window)
        foreach (Match em in Email.Matches(text))
        {
            var start = Math.Max(0, em.Index - 100);
            var len = Math.Min(320, text.Length - start);
            var win = text.AsSpan(start, len);
            if (win.IndexOf("password", StringComparison.OrdinalIgnoreCase) < 0
                && win.IndexOf("passwd", StringComparison.OrdinalIgnoreCase) < 0
                && win.IndexOf("pwd", StringComparison.OrdinalIgnoreCase) < 0)
                continue;
            if (!HasPasswordAssignmentInWindow(text, start, len))
                continue;
            if (em.Length > 50) continue;
            var sn = Snippet(text, em.Index, 200);
            hits.Add(new JsContentHit
            {
                Category = "email-credential-proximity",
                Pattern = em.Value,
                Offset = em.Index,
                Snippet = RedactSecret(sn)
            });
        }

        // Dedupe by (category, offset/50)
        return hits
            .GroupBy(h => (h.Category, h.Offset / 32))
            .Select(g => g.First())
            .OrderBy(h => h.Offset)
            .Take(200)
            .ToList();
    }

    private static readonly Regex PasswordAssignmentNearEmail = new(
        @"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['""]([^'""\r\n]{2,200})['""]",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    private static bool HasPasswordAssignmentInWindow(string text, int start, int len)
    {
        var window = text.Substring(start, Math.Min(len, text.Length - start));
        var m = PasswordAssignmentNearEmail.Match(window);
        return m.Success
               && !SecretsHarvestHeuristics.IsPlaceholderSecretValue(m.Groups[1].Value)
               && !SecretsHarvestHeuristics.IsUiLabelSecretValue(m.Groups[1].Value)
               && !SecretsHarvestHeuristics.IsWeakCredentialAssignment("password", m.Groups[1].Value);
    }

    /// <summary>Minified form schemas often look like password:"Password" or label:"Password:".</summary>
    private static bool LooksLikeFormLabelContext(string snippet, string secret)
    {
        if (SecretsHarvestHeuristics.IsUiLabelSecretValue(secret)) return true;
        var s = snippet.ToLowerInvariant();
        if (s.Contains("\"type\":\"password\"") || s.Contains("'type':'password'")
            || s.Contains("type:\"password\"") || s.Contains("type:'password'"))
            return true;
        if (s.Contains("\"label\"") || s.Contains("'label'") || s.Contains("placeholder")
            || s.Contains("aria-label") || s.Contains("formcontrolname"))
            return true;
        return false;
    }

    private static string RedactSecret(string s)
    {
        return Regex.Replace(s, @"(?i)['""]([A-Za-z0-9+/=]{8,200})['""]", m =>
        {
            var v = m.Groups[1].Value;
            if (v.Length < 8) return m.Value;
            return m.Value[0] + "…" + v.Length + " chars…" + m.Value[^1];
        });
    }

    private static bool CommentBlockContainsSecretToken(string snippet)
    {
        if (string.IsNullOrEmpty(snippet)) return false;
        return snippet.Contains("password", StringComparison.OrdinalIgnoreCase)
               || snippet.Contains("api_key", StringComparison.OrdinalIgnoreCase)
               || snippet.Contains("apikey", StringComparison.OrdinalIgnoreCase)
               || snippet.Contains("secret", StringComparison.OrdinalIgnoreCase)
               || snippet.Contains("private key", StringComparison.OrdinalIgnoreCase)
               || snippet.Contains("BEGIN RSA PRIVATE KEY", StringComparison.OrdinalIgnoreCase)
               || snippet.Contains("BEGIN OPENSSH PRIVATE KEY", StringComparison.OrdinalIgnoreCase);
    }

    private static string Snippet(string text, int index, int maxLen)
    {
        var start = Math.Max(0, index - 40);
        var end = Math.Min(text.Length, start + maxLen);
        start = Math.Max(0, end - maxLen);
        var slice = text[start..end].Replace('\r', ' ').Replace('\n', ' ');
        if (start > 0) slice = "…" + slice;
        if (end < text.Length) slice = slice + "…";
        return slice.Length > maxLen + 4 ? slice[..(maxLen + 4)] + "…" : slice;
    }
}
