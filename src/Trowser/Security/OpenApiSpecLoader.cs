using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Loads OpenAPI/Swagger document bodies from the network log, explicit URLs, the current page, and well-known paths.
/// </summary>
public static class OpenApiSpecLoader
{
    private static readonly string[] ProbeSpecRelativePaths =
    [
        "/openapi.json", "/openapi.yaml", "/openapi.yml", "/swagger.json", "/swagger/v1/swagger.json",
        "/swagger/v1/swagger.yaml", "/v2/swagger.json", "/v3/swagger.json",
        "/v2/api-docs", "/v3/api-docs", "/v3/api-docs.yaml", "/api-docs", "/api-docs.yaml", "/api/docs",
        "/api/swagger.json", "/api/openapi.json", "/api/v2/openapi.json", "/api/v3/openapi.json",
        "/api/v3/openapi.yaml", "/api/swagger/v1/swagger.json"
    ];

    public sealed class LoadResult
    {
        public List<OpenApiOperationCatalog.SpecDocument> Documents { get; set; } = [];
        public List<string> Errors { get; set; } = [];
        public List<string> FetchAttempts { get; set; } = [];
    }

    public static List<OpenApiOperationCatalog.SpecDocument> CollectFromNetwork(
        IReadOnlyList<NetworkEntry> entries,
        string origin,
        IReadOnlyList<string>? specUrls,
        bool includeSpecsFromNetwork)
    {
        var docs = new List<OpenApiOperationCatalog.SpecDocument>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        IEnumerable<NetworkEntry> q = entries.Where(e => e is { StatusCode: >= 200 and < 300 }
                                                         && e.ResponseBody is { Length: > 40 });

        if (specUrls is { Count: > 0 })
        {
            var set = new HashSet<string>(specUrls.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()),
                StringComparer.OrdinalIgnoreCase);
            q = q.Where(e => set.Any(u => UrlMatches(e.Url, u)));
        }
        else if (includeSpecsFromNetwork)
        {
            q = q.Where(e =>
                Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)
                && (string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase)
                    || OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(e.Url)));
        }
        else
        {
            return docs;
        }

        foreach (var e in q)
        {
            var body = e.ResponseBody!;
            if (!OpenApiSpecHeuristics.BodyLooksLikeOpenApi(e.ContentType, body))
                continue;
            if (seen.Add(e.Url))
                docs.Add(new OpenApiOperationCatalog.SpecDocument { Url = e.Url, Body = body });
        }

        return docs;
    }

    public static async Task<LoadResult> LoadAsync(
        AutomationContext ctx,
        string origin,
        string? navigatedUrl,
        IReadOnlyList<NetworkEntry> entries,
        IReadOnlyList<string>? specUrls,
        bool includeFromNetwork,
        bool includeProbes,
        int httpTimeoutMs,
        CancellationToken ct = default)
    {
        var result = new LoadResult();
        var docs = CollectFromNetwork(entries, origin, specUrls, includeFromNetwork);
        var byUrl = new Dictionary<string, OpenApiOperationCatalog.SpecDocument>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in docs)
            byUrl[d.Url] = d;

        var fetchQueue = new List<string>();

        if (specUrls is { Count: > 0 })
            fetchQueue.AddRange(specUrls.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()));

        if (!string.IsNullOrWhiteSpace(navigatedUrl)
            && Uri.TryCreate(navigatedUrl, UriKind.Absolute, out var pageUri)
            && OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(navigatedUrl))
            fetchQueue.Add(navigatedUrl.Trim());

        if (!string.IsNullOrWhiteSpace(navigatedUrl)
            && Uri.TryCreate(navigatedUrl, UriKind.Absolute, out pageUri))
            fetchQueue.AddRange(OpenApiSpecHeuristics.DeriveSpecUrlsFromSwaggerUiPage(pageUri));

        foreach (var d in docs.Where(d => OpenApiSpecHeuristics.IsLikelyTruncatedJson(d.Body)).ToList())
            fetchQueue.Add(d.Url);

        if (includeProbes && Uri.TryCreate(origin, UriKind.Absolute, out _))
        {
            foreach (var rel in ProbeSpecRelativePaths)
                fetchQueue.Add(origin.TrimEnd('/') + rel);
        }

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Clamp(httpTimeoutMs, 3_000, 120_000))
        };

        foreach (var url in fetchQueue.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            if (byUrl.TryGetValue(url, out var existing)
                && !OpenApiSpecHeuristics.IsLikelyTruncatedJson(existing.Body)
                && OpenApiSpecHeuristics.BodyLooksLikeOpenApi(null, existing.Body))
                continue;

            result.FetchAttempts.Add(url);
            try
            {
                var body = await FetchSpecBodyAsync(ctx, http, url, httpTimeoutMs, ct).ConfigureAwait(false);
                if (body == null)
                    continue;
                if (!OpenApiSpecHeuristics.BodyLooksLikeOpenApi(null, body))
                {
                    if (!IsWellKnownProbe(url))
                        result.Errors.Add($"{ShortUrl(url)}: response is not OpenAPI (wrong content type or shape)");
                    continue;
                }

                byUrl[url] = new OpenApiOperationCatalog.SpecDocument { Url = url, Body = body };
            }
            catch (Exception ex)
            {
                if (OpenApiSpecHeuristics.IsExpectedSpecMiss(ex.Message))
                    continue;
                result.Errors.Add($"{ShortUrl(url)}: {ex.Message}");
            }
        }

        result.Documents = byUrl.Values.ToList();
        return result;
    }

    private static async Task<string?> FetchSpecBodyAsync(
        AutomationContext ctx,
        HttpClient http,
        string url,
        int timeoutMs,
        CancellationToken ct)
    {
        var cookieHeader = await ctx.GetCookieHeaderForUrl(url).ConfigureAwait(false);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} Swaggering");
        req.Headers.TryAddWithoutValidation("Accept",
            "application/json, application/yaml, application/x-yaml, text/yaml, text/plain, */*");
        if (!string.IsNullOrEmpty(cookieHeader))
            req.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token)
            .ConfigureAwait(false);
        if ((int)resp.StatusCode is < 200 or >= 300)
            throw new HttpRequestException($"HTTP {(int)resp.StatusCode}");

        var media = resp.Content.Headers.ContentType?.MediaType ?? "";
        if (media.Contains("html", StringComparison.OrdinalIgnoreCase))
            return null;

        return await ReadBodyCappedAsync(resp, 8_000_000, cts.Token).ConfigureAwait(false);
    }

    private static async Task<string> ReadBodyCappedAsync(HttpResponseMessage resp, int maxBytes, CancellationToken ct)
    {
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream(Math.Min(maxBytes, 256 * 1024));
        var buffer = new byte[81920];
        var total = 0;
        while (total < maxBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, maxBytes - total)), ct)
                .ConfigureAwait(false);
            if (read == 0) break;
            ms.Write(buffer, 0, read);
            total += read;
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static bool UrlMatches(string entryUrl, string scope) =>
        entryUrl.Equals(scope, StringComparison.OrdinalIgnoreCase)
        || (Uri.TryCreate(entryUrl, UriKind.Absolute, out var a)
            && Uri.TryCreate(scope, UriKind.Absolute, out var b)
            && string.Equals(a.AbsolutePath, b.AbsolutePath, StringComparison.OrdinalIgnoreCase));

    private static bool IsWellKnownProbe(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        var path = uri.AbsolutePath;
        foreach (var rel in ProbeSpecRelativePaths)
        {
            if (path.Equals(rel, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string ShortUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.AbsolutePath : url;
}
