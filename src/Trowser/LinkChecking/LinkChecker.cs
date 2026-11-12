using System.Net.Http;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.LinkChecking;

public class LinkChecker
{
    private readonly AutomationContext _context;

    private static readonly HttpClientHandler SharedHandler = new()
    {
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    };

    private static readonly HashSet<string> SkipSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "javascript", "data", "mailto", "tel", "blob"
    };

    public LinkChecker(AutomationContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public async Task<LinkCheckResult> RunAsync(
        string scope = "anchors",
        bool external = true,
        int timeoutMs = 5000,
        int concurrency = 10,
        int delayMs = 100)
    {
        var pageUrl = await _context.GetCurrentUrl();
        if (string.IsNullOrEmpty(pageUrl) || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Cannot check links: no valid URL loaded.");

        // Get the real browser user agent so requests look identical to normal browsing
        var userAgent = await _context.ExecuteJs("navigator.userAgent");

        var client = new HttpClient(SharedHandler, disposeHandler: false)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        client.DefaultRequestHeaders.Add("User-Agent", userAgent);
        client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");

        var rawLinks = await CollectLinksFromPage();
        var filtered = FilterLinks(rawLinks, scope, external, pageUri);
        var checkedLinks = await CheckAllLinks(client, filtered, pageUri, timeoutMs, concurrency, delayMs);

        return new LinkCheckResult
        {
            Url = pageUrl,
            Timestamp = DateTime.Now,
            TotalLinks = rawLinks.Count,
            CheckedCount = checkedLinks.Count(l => l.Status != LinkStatus.Skipped),
            Links = checkedLinks
        };
    }

    private async Task<List<RawLink>> CollectLinksFromPage()
    {
        const string script = @"(function() {
    var links = [];
    var anchors = document.querySelectorAll('a[href]');
    anchors.forEach(function(a) {
        links.push({ url: a.href, original: a.getAttribute('href'), source: 'anchor', text: (a.innerText || '').trim().substring(0, 100) });
    });
    document.querySelectorAll('img[src]').forEach(function(img) {
        links.push({ url: img.src, original: img.getAttribute('src'), source: 'image', text: img.alt || '' });
    });
    document.querySelectorAll('script[src]').forEach(function(s) {
        links.push({ url: s.src, original: s.getAttribute('src'), source: 'script', text: '' });
    });
    document.querySelectorAll('link[rel=""stylesheet""][href]').forEach(function(l) {
        links.push({ url: l.href, original: l.getAttribute('href'), source: 'stylesheet', text: '' });
    });
    document.querySelectorAll('iframe[src]').forEach(function(f) {
        links.push({ url: f.src, original: f.getAttribute('src'), source: 'iframe', text: '' });
    });
    return JSON.stringify(links);
})()";

        var json = await _context.ExecuteJs(script);
        if (string.IsNullOrEmpty(json))
            return new List<RawLink>();

        try
        {
            var items = JsonSerializer.Deserialize<List<RawLink>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            return items ?? new List<RawLink>();
        }
        catch
        {
            return new List<RawLink>();
        }
    }

    private List<LinkToCheck> FilterLinks(List<RawLink> rawLinks, string scope, bool external, Uri pageUri)
    {
        // Filter by scope
        var scoped = scope.ToLowerInvariant() switch
        {
            "anchors" => rawLinks.Where(l => l.Source == "anchor"),
            "resources" => rawLinks.Where(l => l.Source is "image" or "script" or "stylesheet" or "iframe"),
            "all" => rawLinks.AsEnumerable(),
            _ => rawLinks.Where(l => l.Source == "anchor")
        };

        var result = new List<LinkToCheck>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in scoped)
        {
            if (string.IsNullOrWhiteSpace(raw.Url))
                continue;

            var original = raw.Original ?? raw.Url;

            // Skip fragment-only links
            if (original.StartsWith("#"))
            {
                result.Add(new LinkToCheck
                {
                    Url = raw.Url,
                    OriginalUrl = original,
                    Source = raw.Source ?? "anchor",
                    LinkText = raw.Text,
                    Skip = true,
                    SkipReason = "fragment-only"
                });
                continue;
            }

            // Check for skip schemes
            if (Uri.TryCreate(raw.Url, UriKind.Absolute, out var uri) && SkipSchemes.Contains(uri.Scheme))
            {
                result.Add(new LinkToCheck
                {
                    Url = raw.Url,
                    OriginalUrl = original,
                    Source = raw.Source ?? "anchor",
                    LinkText = raw.Text,
                    Skip = true,
                    SkipReason = uri.Scheme
                });
                continue;
            }

            // Filter external if requested
            if (!external && uri != null &&
                !string.Equals(uri.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;

            // Deduplicate by URL
            if (!seen.Add(raw.Url))
                continue;

            result.Add(new LinkToCheck
            {
                Url = raw.Url,
                OriginalUrl = original,
                Source = raw.Source ?? "anchor",
                LinkText = raw.Text,
                Skip = false
            });
        }

        return result;
    }

    private async Task<List<CheckedLink>> CheckAllLinks(HttpClient client, List<LinkToCheck> links, Uri pageUri,
        int timeoutMs, int concurrency, int delayMs)
    {
        var results = new List<CheckedLink>();

        // Add skipped links first
        foreach (var link in links.Where(l => l.Skip))
        {
            results.Add(new CheckedLink
            {
                Url = link.Url,
                OriginalUrl = link.OriginalUrl,
                Source = link.Source,
                Status = LinkStatus.Skipped,
                LinkText = link.LinkText
            });
        }

        // Check remaining links with concurrency limit and delay between requests
        var toCheck = links.Where(l => !l.Skip).ToList();
        using var semaphore = new SemaphoreSlim(Math.Max(1, concurrency));
        var tasks = toCheck.Select(async link =>
        {
            await semaphore.WaitAsync();
            try
            {
                if (delayMs > 0)
                    await Task.Delay(delayMs);
                return await CheckSingleLink(client, link, timeoutMs);
            }
            finally
            {
                semaphore.Release();
            }
        }).ToList();

        var checked_ = await Task.WhenAll(tasks);
        results.AddRange(checked_);
        return results;
    }

    private async Task<CheckedLink> CheckSingleLink(HttpClient client, LinkToCheck link, int timeoutMs)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);

            // Try HEAD first
            var request = new HttpRequestMessage(HttpMethod.Head, link.Url);
            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(request, cts.Token);
            }
            catch (TaskCanceledException)
            {
                return new CheckedLink
                {
                    Url = link.Url,
                    OriginalUrl = link.OriginalUrl,
                    Source = link.Source,
                    Status = LinkStatus.Timeout,
                    Error = $"Request timed out after {timeoutMs}ms",
                    LinkText = link.LinkText
                };
            }

            // If HEAD returns 405/403/404, retry with GET (many servers reject HEAD)
            if (response.StatusCode is System.Net.HttpStatusCode.MethodNotAllowed
                or System.Net.HttpStatusCode.Forbidden
                or System.Net.HttpStatusCode.NotFound)
            {
                response.Dispose();
                using var getCts = new CancellationTokenSource(timeoutMs);
                var getRequest = new HttpRequestMessage(HttpMethod.Get, link.Url);
                try
                {
                    response = await client.SendAsync(getRequest, getCts.Token);
                }
                catch (TaskCanceledException)
                {
                    return new CheckedLink
                    {
                        Url = link.Url,
                        OriginalUrl = link.OriginalUrl,
                        Source = link.Source,
                        Status = LinkStatus.Timeout,
                        Error = $"GET request timed out after {timeoutMs}ms",
                        LinkText = link.LinkText
                    };
                }
            }

            var statusCode = (int)response.StatusCode;
            string? redirectUrl = null;

            if (statusCode is >= 300 and < 400)
            {
                redirectUrl = response.Headers.Location?.ToString();
            }

            var status = statusCode switch
            {
                >= 200 and < 300 => LinkStatus.Ok,
                >= 300 and < 400 => LinkStatus.Redirect,
                _ => LinkStatus.Broken
            };

            response.Dispose();

            return new CheckedLink
            {
                Url = link.Url,
                OriginalUrl = link.OriginalUrl,
                Source = link.Source,
                Status = status,
                StatusCode = statusCode,
                RedirectUrl = redirectUrl,
                LinkText = link.LinkText
            };
        }
        catch (TaskCanceledException)
        {
            return new CheckedLink
            {
                Url = link.Url,
                OriginalUrl = link.OriginalUrl,
                Source = link.Source,
                Status = LinkStatus.Timeout,
                Error = $"Request timed out after {timeoutMs}ms",
                LinkText = link.LinkText
            };
        }
        catch (HttpRequestException ex)
        {
            return new CheckedLink
            {
                Url = link.Url,
                OriginalUrl = link.OriginalUrl,
                Source = link.Source,
                Status = LinkStatus.Error,
                Error = ex.InnerException?.Message ?? ex.Message,
                LinkText = link.LinkText
            };
        }
        catch (Exception ex)
        {
            return new CheckedLink
            {
                Url = link.Url,
                OriginalUrl = link.OriginalUrl,
                Source = link.Source,
                Status = LinkStatus.Error,
                Error = ex.Message,
                LinkText = link.LinkText
            };
        }
    }

    private class RawLink
    {
        public string Url { get; set; } = "";
        public string? Original { get; set; }
        public string? Source { get; set; }
        public string? Text { get; set; }
    }

    private class LinkToCheck
    {
        public string Url { get; set; } = "";
        public string OriginalUrl { get; set; } = "";
        public string Source { get; set; } = "";
        public string? LinkText { get; set; }
        public bool Skip { get; set; }
        public string? SkipReason { get; set; }
    }
}
