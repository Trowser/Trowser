using System.Net.Http;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Single-host result of an RFC 9116 <c>security.txt</c> probe.</summary>
public sealed class SecurityTxtHostResult
{
    /// <summary>DNS hostname of the probed origin.</summary>
    public string Host { get; init; } = "";

    public bool Found { get; init; }

    /// <summary>Canonical URL served (following redirects), when <see cref="Found"/> is true.</summary>
    public string? Url { get; init; }

    /// <summary><c>well-known</c> or <c>root</c> — which path yielded a valid file first.</summary>
    public string? PathKind { get; init; }

    /// <summary>Scheme and authority (<c>https://example.com</c>) for the probe that succeeded or was last attempted.</summary>
    public string? OriginAttempted { get; init; }

    public int? StatusCode { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// RFC 9116 <c>security.txt</c> probes: multi-host helper (<see cref="CheckHostsAsync"/>) vs
/// <see cref="CheckCurrentDocumentHostAsync"/> which only probes the navigated document host.
/// </summary>
public static class SecurityTxtProbe
{
    private static readonly HttpClient SharedClient = new(new HttpClientHandler
    {
        AllowAutoRedirect = true,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    {
        Timeout = TimeSpan.FromSeconds(5),
        MaxResponseContentBufferSize = 65_536
    };

    private static readonly Regex SecurityTxtContactField = new(
        @"^[ \t\f\v]*contact\s*:",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex HtmlSignature = new(
        @"^\s*<(?:!DOCTYPE\b|html\b)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>
    /// Probes RFC 9116 <c>security.txt</c> only for the host of the navigated <paramref name="documentUrl"/>.
    /// Matching origins are taken from captured <paramref name="entries"/> plus the document authority.
    /// Returns an empty list when the URL is missing or not HTTP(S).
    /// </summary>
    public static Task<List<SecurityTxtHostResult>> CheckCurrentDocumentHostAsync(
        List<NetworkEntry> entries,
        string? documentUrl,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(documentUrl) ||
            !Uri.TryCreate(documentUrl.Trim(), UriKind.Absolute, out var pageUri) ||
            !pageUri.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(pageUri.Host))
        {
            return Task.FromResult(new List<SecurityTxtHostResult>());
        }

        var single = new List<string> { pageUri.Host };
        return CheckHostsAsync(single, entries, documentUrl, cancellationToken);
    }

    /// <summary>
    /// For each hostname in <paramref name="hostnames"/>, probes <c>security.txt</c> on origins seen in
    /// <paramref name="entries"/> plus HTTPS/HTTP guesses on default ports when needed.
    /// </summary>
    public static async Task<List<SecurityTxtHostResult>> CheckHostsAsync(
        IEnumerable<string>? hostnames,
        List<NetworkEntry> entries,
        string? pageUrlFallback,
        CancellationToken cancellationToken = default)
    {
        var hnSet = hostnames?.Where(static h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase)
            ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (hnSet.Count == 0 && !string.IsNullOrWhiteSpace(pageUrlFallback))
        {
            if (Uri.TryCreate(pageUrlFallback, UriKind.Absolute, out var pu) &&
                pu.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                hnSet.Add(pu.Host);
            }
        }

        if (hnSet.Count == 0)
            return new List<SecurityTxtHostResult>();

        var originsByHost = CollectOriginsByHost(entries, hnSet);

        foreach (var h in hnSet.Where(h =>
                     !originsByHost.ContainsKey(h) || originsByHost[h].Count == 0))
        {
            originsByHost[h] =
                AppendDefaultTryOrigins(new List<string>(), h);
        }

        if (!string.IsNullOrWhiteSpace(pageUrlFallback) &&
            Uri.TryCreate(pageUrlFallback, UriKind.Absolute, out var pageUri) &&
            pageUri.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            var pageKey = pageUri.Host;
            if (!string.IsNullOrEmpty(pageKey) && hnSet.Contains(pageKey))
            {
                var fullOrigin = $"{pageUri.Scheme}://{pageUri.Authority}";
                if (!originsByHost.TryGetValue(pageKey, out var listOrigins))
                    originsByHost[pageKey] = listOrigins = new List<string>();

                if (!listOrigins.Contains(fullOrigin, StringComparer.OrdinalIgnoreCase))
                    listOrigins.Insert(0, fullOrigin);
            }
        }

        var results = new List<SecurityTxtHostResult>();

        foreach (var hostKey in hnSet.OrderBy(static h => h, StringComparer.OrdinalIgnoreCase))
        {
            originsByHost.TryGetValue(hostKey, out var originsList);
            var originsOrdered = OrderedOrigins(DedupeOrigins(originsList ?? new List<string>()));

            SecurityTxtHostResult? succeeded = null;
            SecurityTxtHostResult? lastTried = null;

            foreach (var origin in originsOrdered)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var probe = await TryOriginAsync(origin, hostKey, cancellationToken).ConfigureAwait(false);
                lastTried = probe;

                if (probe.Found)
                {
                    succeeded = probe;
                    break;
                }
            }

            if (succeeded != null)
            {
                results.Add(succeeded);
            }
            else if (lastTried != null)
            {
                results.Add(new SecurityTxtHostResult
                {
                    Host = hostKey,
                    Found = false,
                    Error = lastTried.Error ??
                            "Could not locate a machine-readable RFC 9116 security.txt on known origins.",
                    StatusCode = lastTried.StatusCode,
                    OriginAttempted = lastTried.OriginAttempted
                });
            }
            else
            {
                results.Add(new SecurityTxtHostResult
                {
                    Host = hostKey,
                    Found = false,
                    Error =
                        "No HTTP(S) origins to probe — browse the application so URIs appear in the network log."
                });
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        return results;
    }

    internal static Dictionary<string, List<string>> CollectOriginsByHost(
        List<NetworkEntry> entries,
        HashSet<string> hostnamesNormalized)
    {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri) ||
                !uri.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                continue;

            var key = uri.Host;
            if (string.IsNullOrEmpty(key) || !hostnamesNormalized.Contains(key))
                continue;

            if (!map.TryGetValue(key, out var lst))
                map[key] = lst = new List<string>();

            var origin = $"{uri.Scheme}://{uri.Authority}";
            if (!lst.Contains(origin, StringComparer.OrdinalIgnoreCase))
                lst.Add(origin);
        }

        return map;
    }

    private static List<string> AppendDefaultTryOrigins(List<string> list, string host)
    {
        var ah = AuthorityHost(host);
        list.Add($"https://{ah}");
        list.Add($"http://{ah}");
        return list;
    }

    private static string AuthorityHost(string hostFromLog)
    {
        if (hostFromLog.StartsWith("[", StringComparison.Ordinal))
            return hostFromLog;
        var needsBrackets =
            hostFromLog.Contains(":", StringComparison.Ordinal) &&
            !hostFromLog.Contains('.', StringComparison.Ordinal);
        return needsBrackets ? $"[{hostFromLog}]" : hostFromLog;
    }

    private static List<string> DedupeOrigins(List<string> origins)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var r = new List<string>();
        foreach (var o in origins)
        {
            if (!string.IsNullOrWhiteSpace(o) && seen.Add(o))
                r.Add(o);
        }

        return r;
    }

    private static List<string> OrderedOrigins(List<string> origins)
    {
        if (origins.Count <= 1)
            return origins;

        return origins
            .OrderByDescending(static o =>
                Uri.TryCreate(o, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps)
            .ThenBy(static o => o, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static async Task<SecurityTxtHostResult> TryOriginAsync(string originBase, string hostKey,
        CancellationToken cancellationToken)
    {
        var wellKnownUrl = $"{originBase.TrimEnd('/')}/.well-known/security.txt";

        SecurityTxtHostResult lastProbe =
            await TryPathAsync(wellKnownUrl, hostKey, originBase,
                cancellationToken).ConfigureAwait(false);
        SecurityTxtHostResult found = lastProbe.Found
            ? lastProbe
            : await TryPathAsync($"{originBase.TrimEnd('/')}/security.txt", hostKey, originBase,
                cancellationToken).ConfigureAwait(false);

        if (found.Found)
            return found;

        var err =
            $"{lastProbe.Error ?? "well-known probe failed"}; {found.Error ?? "root-level probe failed"}";
        var displayHost = OriginHost(hostKey, originBase);
        return new SecurityTxtHostResult
        {
            Host = displayHost,
            Found = false,
            Error = err,
            OriginAttempted = $"{originBase.TrimEnd('/')}",
            StatusCode = found.StatusCode ?? lastProbe.StatusCode
        };
    }

    private static string OriginHost(string hostKeyFallback, string originBase)
    {
        if (!Uri.TryCreate(originBase + "/", UriKind.Absolute, out var o))
            return hostKeyFallback;
        return string.IsNullOrEmpty(o.Host) ? hostKeyFallback : o.Host;
    }

    private static async Task<SecurityTxtHostResult> TryPathAsync(string url,
        string hostFallback,
        string originBase,
        CancellationToken cancellationToken)
    {
        var pathKind = url.Contains("/.well-known/", StringComparison.OrdinalIgnoreCase)
            ? "well-known"
            : "root";

        try
        {
            using var msg = new HttpRequestMessage(HttpMethod.Get, url);
            msg.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} SecurityTxtProbe");

            using var response = await SharedClient
                .SendAsync(msg, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);

            var code = (int)response.StatusCode;
            var snippet = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            const int snippetMax = 16_384;
            if (snippet.Length > snippetMax)
                snippet = snippet[..snippetMax];

            var respondedAs = response.RequestMessage?.RequestUri ?? new Uri(url, UriKind.Absolute);

            var displayHost =
                OriginHost(hostFallback, $"{respondedAs.GetLeftPart(UriPartial.Authority)}/");

            if (code >= 400)
            {
                var fail = $"{pathKind}: HTTP {code}";
                return new SecurityTxtHostResult
                {
                    Host = displayHost,
                    Found = false,
                    StatusCode = code,
                    OriginAttempted = originBase.TrimEnd('/'),
                    Error =
                        $"{fail}{(pathKind == "root" ? " (path /security.txt)" : " (/.well-known/security.txt)")}"
                };
            }

            if (LooksLikeHtml(snippet))
            {
                return new SecurityTxtHostResult
                {
                    Host = displayHost,
                    Found = false,
                    StatusCode = code,
                    OriginAttempted = originBase.TrimEnd('/'),
                    Error =
                        $"{pathKind}: response looks like HTML, not RFC 9116 text{(pathKind == "root" ? " (/security.txt)" : "")}"
                };
            }

            if (!LooksLikeSecurityTxt(snippet))
            {
                return new SecurityTxtHostResult
                {
                    Host = displayHost,
                    Found = false,
                    StatusCode = code,
                    OriginAttempted = originBase.TrimEnd('/'),
                    Error =
                        $"{pathKind}: 200 preview lacks a recognizable Contact field (RFC 9116)"
                };
            }

            var finalAuthority = $"{respondedAs.Scheme}://{respondedAs.Authority}".TrimEnd('/');

            return new SecurityTxtHostResult
            {
                Host = displayHost,
                Found = true,
                Url = respondedAs.ToString(),
                PathKind = pathKind,
                StatusCode = code,
                OriginAttempted = finalAuthority
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var pu = Uri.TryCreate(url, UriKind.Absolute, out var p) ? p : null;

            var displayHostFallback = pu != null ? pu.Host : hostFallback;

            return new SecurityTxtHostResult
            {
                Host = displayHostFallback,
                Found = false,
                Error = $"{pathKind}: {ex.Message}",
                OriginAttempted = pu?.GetLeftPart(UriPartial.Authority).TrimEnd('/'),
                StatusCode = null
            };
        }
    }

    private static bool LooksLikeHtml(string body) =>
        body.Length > 0 && HtmlSignature.IsMatch(body);

    private static bool LooksLikeSecurityTxt(string body) =>
        SecurityTxtContactField.IsMatch(body);
}
