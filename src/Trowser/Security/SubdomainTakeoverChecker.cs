using System.Net.Http;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Detects dangling CNAME records that may be vulnerable to subdomain takeover.
/// Collects hostnames from the network log and page links, resolves DNS via
/// Cloudflare DoH, and checks CNAME targets against a known-vulnerable provider catalog.
/// </summary>
public static class SubdomainTakeoverChecker
{
    public sealed class SubdomainTakeoverOptions
    {
        public int MaxHostnames { get; set; } = 20;
        public int TimeoutMs { get; set; } = 15_000;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class SubdomainTakeoverFinding
    {
        public string Host { get; init; } = "";
        public string Cname { get; init; } = "";
        public string Provider { get; init; } = "";
        public string Severity { get; init; } = "high";
        public string Category { get; init; } = "subdomain-takeover";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public string? FingerprintMatch { get; init; }
    }

    public sealed class SubdomainTakeoverResult
    {
        public int HostnamesChecked { get; init; }
        public List<SubdomainTakeoverFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public bool IsClean => Findings.Count == 0;
    }

    private sealed record ProviderFingerprint(
        string Provider,
        string[] CnamePatterns,
        string[] ResponseFingerprints);

    private static readonly ProviderFingerprint[] Catalog =
    [
        new("GitHub Pages",
            ["github.io", "github.map.fastly.net"],
            ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"]),
        new("Amazon S3",
            [".s3.amazonaws.com", ".s3-website", ".s3.dualstack"],
            ["NoSuchBucket", "The specified bucket does not exist"]),
        new("Heroku",
            [".herokudns.com", ".herokussl.com", ".herokuapp.com", "herokucdn.com"],
            ["No such app", "herokucdn.com/error-pages", "There is no app configured at that hostname"]),
        new("Azure",
            [".azurewebsites.net", ".cloudapp.azure.com", ".cloudapp.net", ".trafficmanager.net", ".blob.core.windows.net", ".azurefd.net"],
            ["404 Web Site not found", "The resource you are looking for has been removed"]),
        new("Vercel",
            [".vercel.app", ".now.sh", "cname.vercel-dns.com", "alias.zeit.co"],
            ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND", "This Deployment has been disabled"]),
        new("Fastly",
            [".fastly.net", ".fastlylb.net"],
            ["Fastly error: unknown domain"]),
        new("Netlify",
            [".netlify.app", ".netlify.com", ".bitballoon.com"],
            ["Not Found - Request ID"]),
        new("Shopify",
            [".myshopify.com", "shops.myshopify.com"],
            ["Sorry, this shop is currently unavailable", "Only one step left"]),
        new("Surge.sh",
            [".surge.sh"],
            ["project not found"]),
        new("Tumblr",
            [".tumblr.com", "domains.tumblr.com"],
            ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"]),
        new("WordPress",
            [".wordpress.com"],
            ["Do you want to register"]),
    ];

    private const string DohEndpoint = "https://cloudflare-dns.com/dns-query";

    public static async Task<SubdomainTakeoverResult> RunAsync(
        AutomationContext ctx,
        SubdomainTakeoverOptions options,
        CancellationToken ct = default)
    {
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running subdomain takeover scan.");

        var pageHost = pageUri.Host;
        var hostnames = await CollectHostnamesAsync(ctx, pageHost, options.MaxHostnames, ct);

        if (hostnames.Count == 0)
        {
            return new SubdomainTakeoverResult
            {
                HostnamesChecked = 0,
                Summary = ["No candidate hostnames found in network log or page links."]
            };
        }

        var findings = new List<SubdomainTakeoverFinding>();

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Max(options.TimeoutMs, 3000))
        };

        foreach (var host in hostnames)
        {
            ct.ThrowIfCancellationRequested();
            await CheckHostAsync(ctx, http, host, options, findings, ct);
        }

        if (options.RegisterChainFindings)
            RegisterFindings(ctx, findings);

        var summary = findings.Count == 0
            ? new List<string> { $"Checked {hostnames.Count} hostname(s); no dangling CNAMEs detected." }
            : new List<string> { $"{findings.Count} potential subdomain takeover(s) found across {hostnames.Count} hostname(s)." };

        return new SubdomainTakeoverResult
        {
            HostnamesChecked = hostnames.Count,
            Findings = findings,
            Summary = summary
        };
    }

    private static async Task<List<string>> CollectHostnamesAsync(
        AutomationContext ctx,
        string pageHost,
        int max,
        CancellationToken ct = default)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();

        void TryAdd(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return;
            host = host.Trim().ToLowerInvariant();
            if (host.Length < 4 || !host.Contains('.')) return;
            if (IsIpAddress(host)) return;
            if (seen.Add(host) && result.Count < max)
                result.Add(host);
        }

        foreach (var entry in ctx.Network.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
                TryAdd(uri.Host);
        }

        try
        {
            var links = await ctx.GetLinks();
            foreach (var link in links)
            {
                ct.ThrowIfCancellationRequested();
                if (link.TryGetValue("href", out var href) &&
                    Uri.TryCreate(href, UriKind.Absolute, out var linkUri))
                {
                    TryAdd(linkUri.Host);
                }
            }
        }
        catch
        {
            // Page may not have links or JS may fail; continue with network-only hostnames
        }

        return result;
    }

    private static async Task CheckHostAsync(
        AutomationContext ctx,
        HttpClient http,
        string host,
        SubdomainTakeoverOptions options,
        List<SubdomainTakeoverFinding> findings,
        CancellationToken ct)
    {
        string? cname;
        try
        {
            cname = await ResolveCnameAsync(http, host, ct);
        }
        catch
        {
            return;
        }

        if (string.IsNullOrEmpty(cname))
            return;

        var matched = MatchProvider(cname);
        if (matched == null)
            return;

        var (provider, fingerprint) = matched.Value;
        var hasDanglingResponse = await CheckDanglingResponseAsync(http, host, fingerprint, ct);

        if (!hasDanglingResponse)
            return;

        findings.Add(new SubdomainTakeoverFinding
        {
            Host = host,
            Cname = cname,
            Provider = provider,
            Severity = "high",
            Title = $"Dangling CNAME to {provider}: {host} → {cname}",
            Detail = $"The hostname {host} has a CNAME pointing to {cname} ({provider}), " +
                     "but the target resource appears unclaimed. An attacker could register " +
                     "the resource on the provider and serve arbitrary content on this subdomain.",
            FingerprintMatch = fingerprint.ResponseFingerprints.Length > 0
                ? fingerprint.ResponseFingerprints[0]
                : null
        });
    }

    private static async Task<string?> ResolveCnameAsync(HttpClient http, string host, CancellationToken ct)
    {
        var url = $"{DohEndpoint}?name={Uri.EscapeDataString(host)}&type=CNAME";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/dns-json");

        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
            return null;

        var json = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("Answer", out var answers))
            return null;

        foreach (var answer in answers.EnumerateArray())
        {
            if (answer.TryGetProperty("type", out var type) && type.GetInt32() == 5 &&
                answer.TryGetProperty("data", out var data))
            {
                var cname = data.GetString()?.TrimEnd('.');
                if (!string.IsNullOrEmpty(cname))
                    return cname;
            }
        }

        return null;
    }

    private static (string Provider, ProviderFingerprint Fingerprint)? MatchProvider(string cname)
    {
        var lower = cname.ToLowerInvariant();
        foreach (var fp in Catalog)
        {
            foreach (var pattern in fp.CnamePatterns)
            {
                if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    return (fp.Provider, fp);
            }
        }
        return null;
    }

    private static async Task<bool> CheckDanglingResponseAsync(
        HttpClient http,
        string host,
        ProviderFingerprint fingerprint,
        CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{host}/");
            request.Headers.Host = host;
            using var response = await http.SendAsync(request, ct);

            if (response.StatusCode is System.Net.HttpStatusCode.NotFound)
                return true;

            if (fingerprint.ResponseFingerprints.Length == 0)
                return false;

            var body = await response.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrEmpty(body))
                return false;

            foreach (var fp in fingerprint.ResponseFingerprints)
            {
                if (body.Contains(fp, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch
        {
            // Connection failures to dangling CNAMEs are expected — treat as potentially dangling
            // only if the CNAME already matched a known provider pattern
            return fingerprint.ResponseFingerprints.Length == 0;
        }

        return false;
    }

    private static void RegisterFindings(AutomationContext ctx, List<SubdomainTakeoverFinding> findings)
    {
        foreach (var f in findings)
        {
            ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"subdomain-takeover-{Math.Abs((f.Host + f.Cname).GetHashCode(StringComparison.Ordinal))}",
                Source = "scan",
                Category = f.Category,
                Severity = f.Severity,
                Title = f.Title,
                Endpoint = $"https://{f.Host}/",
                Detail = f.Detail
            });
        }
    }

    private static bool IsIpAddress(string host) =>
        System.Net.IPAddress.TryParse(host, out _);
}
