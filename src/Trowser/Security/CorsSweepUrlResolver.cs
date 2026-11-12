using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Priority-ordered URL list for multi-endpoint CORS sweeps (network log before scaffolds).
/// </summary>
internal static class CorsSweepUrlResolver
{
    internal sealed class ResolveResult
    {
        public List<string> Urls { get; init; } = [];
        public int NetworkUrlsIncluded { get; init; }
        public int CrossOriginNetworkUrlsIncluded { get; init; }
        public int ScaffoldUrlsIncluded { get; init; }
        public List<string> Warnings { get; init; } = [];
        public int SkippedDueToMaxUrls { get; init; }
    }

    internal static ResolveResult Resolve(
        AutomationContext ctx,
        CorsSweep.SweepOptions options,
        string documentOrigin,
        string documentUrl)
    {
        var warnings = new List<string>();
        if (options.Urls is { Count: > 0 })
        {
            var explicitList = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { documentUrl };
            foreach (var u in options.Urls)
            {
                if (string.IsNullOrWhiteSpace(u)) continue;
                var full = NormalizeUrl(u, documentOrigin);
                if (seen.Add(full))
                    explicitList.Add(full);
            }

            var max = Math.Clamp(options.MaxUrls, 1, 30);
            if (explicitList.Count > max)
                warnings.Add($"{explicitList.Count - max} explicit url(s) omitted due to maxUrls={max}.");
            return new ResolveResult
            {
                Urls = explicitList.Take(max).ToList(),
                ScaffoldUrlsIncluded = explicitList.Count,
                Warnings = warnings
            };
        }

        var maxUrls = Math.Clamp(options.MaxUrls, 1, 30);
        var ordered = new List<(string Url, bool FromNetwork, bool CrossOrigin)>();
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { documentUrl };

        void TryAdd(string? u, bool fromNetwork, bool crossOrigin)
        {
            if (string.IsNullOrWhiteSpace(u)) return;
            var full = NormalizeUrl(u, documentOrigin);
            if (!seenUrls.Add(full)) return;
            ordered.Add((full, fromNetwork, crossOrigin));
        }

        if (options.IncludeAttackSurfaceUrls)
        {
            foreach (var entry in ctx.Network.Entries)
            {
                if (entry.IsTrowserGenerated) continue;
                if (entry.Method is not ("GET" or "POST" or "PUT" or "PATCH")) continue;
                if (entry.StatusCode is < 200 or >= 400) continue;
                if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
                if (!IsApiLikePath(uri.AbsolutePath)) continue;

                var entryOrigin = uri.GetLeftPart(UriPartial.Authority);
                var cross = !string.Equals(entryOrigin, documentOrigin, StringComparison.OrdinalIgnoreCase);
                var isFetchLike = IsFetchLike(entry);
                if (cross || isFetchLike || entryOrigin.Equals(documentOrigin, StringComparison.OrdinalIgnoreCase))
                    TryAdd(entry.Url, fromNetwork: true, crossOrigin: cross);
            }

            var mapper = new AttackSurfaceMapper();
            var surface = mapper.Analyze(ctx.Network.Entries, includeAuth: true);
            foreach (var ep in surface.Endpoints)
            {
                var candidate = !string.IsNullOrWhiteSpace(ep.Url) ? ep.Url : ep.UrlTemplate;
                if (string.IsNullOrWhiteSpace(candidate)) continue;
                if (!Uri.TryCreate(candidate, UriKind.Absolute, out var templateUri))
                {
                    if (!IsApiLikeTemplate(candidate) && !ep.Auth.Required) continue;
                    TryAdd(candidate, fromNetwork: false, crossOrigin: false);
                    continue;
                }

                if (!IsApiLikePath(templateUri.AbsolutePath) && !ep.Auth.Required) continue;
                var cross = !string.Equals(templateUri.GetLeftPart(UriPartial.Authority), documentOrigin,
                    StringComparison.OrdinalIgnoreCase);
                TryAdd(candidate, fromNetwork: false, crossOrigin: cross);
            }
        }

        if (options.IncludeDefaultCandidates)
        {
            foreach (var p in CorsSweep.DefaultCandidatePaths)
                TryAdd(p, fromNetwork: false, crossOrigin: false);
        }

        var prioritized = ordered
            .OrderByDescending(t => t.CrossOrigin && t.FromNetwork ? 4 : 0)
            .ThenByDescending(t => t.FromNetwork ? 3 : 0)
            .ThenByDescending(t => t.CrossOrigin ? 2 : 0)
            .ThenBy(t => t.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (prioritized.Count > maxUrls)
        {
            var skipped = prioritized.Skip(maxUrls).ToList();
            var skippedCross = skipped.Count(t => t.CrossOrigin);
            if (skippedCross > 0)
            {
                warnings.Add(
                    $"{skippedCross} cross-origin network URL(s) not probed due to maxUrls={maxUrls} — " +
                    "raise maxUrls or pass urls[] including the API origin.");
            }
            else if (skipped.Count > 0)
            {
                warnings.Add($"{skipped.Count} candidate URL(s) not probed due to maxUrls={maxUrls}.");
            }
        }

        var taken = prioritized.Take(maxUrls).ToList();
        return new ResolveResult
        {
            Urls = taken.Select(t => t.Url).ToList(),
            NetworkUrlsIncluded = taken.Count(t => t.FromNetwork),
            CrossOriginNetworkUrlsIncluded = taken.Count(t => t.FromNetwork && t.CrossOrigin),
            ScaffoldUrlsIncluded = taken.Count(t => !t.FromNetwork),
            Warnings = warnings,
            SkippedDueToMaxUrls = Math.Max(0, prioritized.Count - maxUrls)
        };
    }

    private static string NormalizeUrl(string u, string documentOrigin) =>
        u.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? u
            : documentOrigin + (u.StartsWith('/') ? u : "/" + u);

    private static bool IsFetchLike(NetworkEntry entry)
    {
        var rt = entry.ResourceType ?? "";
        return rt.Equals("Fetch", StringComparison.OrdinalIgnoreCase)
               || rt.Equals("XHR", StringComparison.OrdinalIgnoreCase)
               || rt.Equals("XmlHttpRequest", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsApiLikePath(string path) =>
        path.Contains("/api", StringComparison.OrdinalIgnoreCase)
        || path.Contains("/rest", StringComparison.OrdinalIgnoreCase)
        || path.Contains("graphql", StringComparison.OrdinalIgnoreCase);

    private static bool IsApiLikeTemplate(string template) =>
        template.Contains("/api", StringComparison.OrdinalIgnoreCase)
        || template.Contains("/rest", StringComparison.OrdinalIgnoreCase)
        || template.Contains("graphql", StringComparison.OrdinalIgnoreCase);
}
