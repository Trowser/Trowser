using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Multi-URL clickjacking sweep (document + attack-surface sensitive pages).
/// </summary>
public static class ClickjackSweep
{
    public sealed class SweepOptions
    {
        public IReadOnlyList<string>? Urls { get; set; }
        public bool IncludeAttackSurfaceUrls { get; set; } = true;
        public bool IncludeDefaultCandidates { get; set; } = true;
        public int MaxUrls { get; set; } = 12;
        public bool IncludeActiveTest { get; set; }
        public bool IncludeSensitiveOverlayTest { get; set; }
        public int? SensitiveRef { get; set; }
        public int TimeoutMs { get; set; } = 8000;
    }

    public sealed class SweepResult
    {
        public string DocumentUrl { get; init; } = "";
        public ClickjackTester.UrlTestResult Document { get; init; } = new();
        public List<ClickjackTester.UrlTestResult> Endpoints { get; init; } = [];
        public int UrlsSwept => Endpoints.Count(e => !e.IsDocumentBaseline);
        public bool IsClean => !Document.IsVulnerable && Endpoints.All(e => !e.IsVulnerable);
        public int IssueCount =>
            (Document.IsVulnerable ? 1 : 0) + Endpoints.Count(e => e.IsVulnerable);
    }

    private static readonly string[] DefaultCandidates =
    [
        "/login", "/signin", "/auth/login", "/account", "/settings", "/admin",
        "/checkout", "/payment", "/transfer", "/profile"
    ];

    public static async Task<SweepResult> RunAsync(
        AutomationContext ctx,
        SweepOptions options,
        CancellationToken ct = default)
    {
        var documentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(documentUrl) ||
            !Uri.TryCreate(documentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running clickjack sweep.");

        var testOptions = new ClickjackTester.TestOptions
        {
            IncludeActiveTest = options.IncludeActiveTest,
            IncludeSensitiveOverlayTest = options.IncludeSensitiveOverlayTest,
            SensitiveRef = options.SensitiveRef,
            TimeoutMs = options.TimeoutMs
        };

        var document = await ClickjackTester.TestUrlAsync(ctx, documentUrl, true, testOptions, ct);
        var endpoints = new List<ClickjackTester.UrlTestResult> { document };

        var urls = ResolveUrls(ctx, options, pageUri, documentUrl);
        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            if (string.Equals(url, documentUrl, StringComparison.OrdinalIgnoreCase))
                continue;

            var row = await ClickjackTester.TestUrlAsync(ctx, url, false, testOptions, ct);
            endpoints.Add(row);
        }

        return new SweepResult
        {
            DocumentUrl = documentUrl,
            Document = document,
            Endpoints = endpoints
        };
    }

    private static List<string> ResolveUrls(
        AutomationContext ctx,
        SweepOptions options,
        Uri pageUri,
        string documentUrl)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var origin = pageUri.GetLeftPart(UriPartial.Authority);

        if (options.Urls != null)
        {
            foreach (var u in options.Urls)
            {
                if (string.IsNullOrWhiteSpace(u)) continue;
                set.Add(Uri.TryCreate(u, UriKind.Absolute, out _) ? u : origin + u);
            }
        }

        if (options.IncludeDefaultCandidates)
        {
            foreach (var path in DefaultCandidates)
                set.Add(origin + path);
        }

        if (options.IncludeAttackSurfaceUrls)
        {
            var surface = ctx.CheckAttackSurface(hostFilter: pageUri.Host);
            foreach (var ep in surface.Endpoints)
            {
                if (string.IsNullOrWhiteSpace(ep.Url)) continue;
                if (!ClickjackTester.IsSensitivePage(ep.Url) &&
                    !ep.UrlTemplate.Contains("admin", StringComparison.OrdinalIgnoreCase) &&
                    !ep.UrlTemplate.Contains("login", StringComparison.OrdinalIgnoreCase))
                    continue;
                set.Add(ep.Url);
            }
        }

        set.Add(documentUrl);

        return set
            .Where(u => Uri.TryCreate(u, UriKind.Absolute, out var uu) &&
                        string.Equals(uu.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
            .Take(Math.Clamp(options.MaxUrls, 1, 30))
            .ToList();
    }
}
