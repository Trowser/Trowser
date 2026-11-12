using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Extracts login credential pairs from js-audit / secrets-harvest sources (JS bundles,
/// page HTML, network responses) for use by <see cref="DefaultCredentialCanary"/>.
/// </summary>
public static class DiscoveredCredentialResolver
{
    public sealed class DiscoveredPair
    {
        public string User { get; init; } = "";
        public string Pass { get; init; } = "";
        public string Source { get; init; } = "";
        public string? Location { get; init; }
    }

    private static readonly Regex CredentialAssignment = new(
        @"(?i)(?<key>password|passwd|pwd|pass|username|user_name|user|email)\s*[=:]\s*['""](?<val>[^'""\r\n]{2,100})['""]",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex EmailPasswordCombo = new(
        @"(?<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}).{0,120}?(?:password|passwd|pwd|pass)\s*[=:]\s*['""](?<pass>[^'""\r\n]{2,100})['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline, TimeSpan.FromSeconds(2));

    private static readonly Regex PasswordOnly = new(
        @"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['""]([^'""\r\n]{3,100})['""]",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex EmailNearPassword = new(
        @"(?<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}).{0,160}?(?:password|passwd|pwd|pass)\s*[=:]\s*['""](?<pass>[^'""\r\n]{2,100})['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline, TimeSpan.FromSeconds(2));

    private static readonly string[] DefaultUsersForPasswordOnly =
    ["admin", "administrator", "root", "user", "test", "guest"];

    public static async Task<List<DiscoveredPair>> ResolveAsync(
        AutomationContext ctx,
        CancellationToken ct = default)
    {
        var pairs = new List<DiscoveredPair>();
        var seenTexts = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in ctx.Network.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(entry.ResponseBody)) continue;
            if (entry.StatusCode is < 200 or >= 400) continue;
            ScanText(entry.ResponseBody, "secrets-harvest/network", entry.Url, pairs, seenTexts);
        }

        foreach (var entry in ctx.Network.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(entry.RequestBody)) continue;
            ScanText(entry.RequestBody, "secrets-harvest/network-request", entry.Url, pairs, seenTexts);
        }

        try
        {
            var html = await ctx.GetPageSource();
            ct.ThrowIfCancellationRequested();
            ScanText(html, "secrets-harvest/page-html", await ctx.GetCurrentUrl(), pairs, seenTexts);
        }
        catch
        {
            // page source optional
        }

        await ScanJsBundlesAsync(ctx, pairs, seenTexts, ct);

        return pairs
            .GroupBy(p => $"{p.User}|{p.Pass}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(20)
            .ToList();
    }

    private static async Task ScanJsBundlesAsync(
        AutomationContext ctx,
        List<DiscoveredPair> pairs,
        HashSet<string> seenTexts,
        CancellationToken ct)
    {
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
              return JSON.stringify(list);
            })()
            """);
        ct.ThrowIfCancellationRequested();

        List<string> urls;
        using (var doc = System.Text.Json.JsonDocument.Parse(listJson))
        {
            urls = doc.RootElement.EnumerateArray()
                .Select(x => x.GetString() ?? "")
                .Where(s => s.Length > 0)
                .Take(12)
                .ToList();
        }

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var text = await http.GetStringAsync(url, ct);
                ScanText(text, "js-audit", url, pairs, seenTexts);
            }
            catch
            {
                // skip failed bundle
            }
        }
    }

    private static void ScanText(
        string text,
        string source,
        string? location,
        List<DiscoveredPair> pairs,
        HashSet<string> seenTexts)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        var capped = text.Length > 600_000 ? text[..600_000] : text;
        var hashKey = capped.Length.ToString() + capped.GetHashCode(StringComparison.Ordinal);
        if (!seenTexts.Add(hashKey)) return;

        foreach (Match m in EmailPasswordCombo.Matches(capped))
            TryAddPair(m.Groups["email"].Value, m.Groups["pass"].Value, source, location, pairs);

        foreach (Match m in EmailNearPassword.Matches(capped))
            TryAddPair(m.Groups["email"].Value, m.Groups["pass"].Value, source, location, pairs);

        ExtractAssignmentPairs(capped, source, location, pairs);
    }

    private static void ExtractAssignmentPairs(
        string text,
        string source,
        string? location,
        List<DiscoveredPair> pairs)
    {
        string? email = null;
        string? username = null;
        string? password = null;

        foreach (Match m in CredentialAssignment.Matches(text))
        {
            var key = m.Groups["key"].Value.ToLowerInvariant();
            var val = m.Groups["val"].Value;
            if (!IsPlausibleCredential(val)) continue;

            if (key is "email" || val.Contains('@'))
                email = val;
            else if (key is "username" or "user_name" or "user")
                username = val;
            else if (key is "password" or "passwd" or "pwd" or "pass")
                password = val;
        }

        if (!string.IsNullOrEmpty(password))
        {
            if (!string.IsNullOrEmpty(email))
                TryAddPair(email, password, source, location, pairs);
            else if (!string.IsNullOrEmpty(username))
                TryAddPair(username, password, source, location, pairs);
            else
            {
                foreach (var user in DefaultUsersForPasswordOnly)
                    TryAddPair(user, password, source, location, pairs);
            }
        }

        foreach (Match m in PasswordOnly.Matches(text))
        {
            var pass = m.Groups[1].Value;
            if (!IsPlausibleCredential(pass)) continue;
            var windowStart = Math.Max(0, m.Index - 200);
            var window = text[windowStart..Math.Min(text.Length, m.Index + 200)];
            var emailMatch = Regex.Match(window,
                @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                RegexOptions.None, TimeSpan.FromSeconds(1));
            if (emailMatch.Success)
                TryAddPair(emailMatch.Value, pass, source, location, pairs);
            else
            {
                foreach (var user in DefaultUsersForPasswordOnly)
                    TryAddPair(user, pass, source, location, pairs);
            }
        }
    }

    private static void TryAddPair(
        string user,
        string pass,
        string source,
        string? location,
        List<DiscoveredPair> pairs)
    {
        user = user.Trim();
        pass = pass.Trim();
        if (user.Length < 2 || pass.Length < 2) return;
        if (!IsPlausibleCredential(pass)) return;
        if (pass.Contains(" chars…", StringComparison.Ordinal)) return;

        pairs.Add(new DiscoveredPair
        {
            User = user,
            Pass = pass,
            Source = source,
            Location = location
        });
    }

    private static bool IsPlausibleCredential(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        if (value.Length < 3 || value.Length > 100) return false;
        return !SecretsHarvestHeuristics.IsPlaceholderSecretValue(value);
    }
}
