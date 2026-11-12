using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Fetches login surfaces and injects CSRF tokens into credential-canary POST bodies.
/// </summary>
public static class LoginCsrfHelper
{
    private static readonly Regex HiddenInputRegex = new(
        @"<input\b[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MetaCsrfRegex = new(
        @"<meta\b[^>]+(?:name=[""'](?:csrf-token|csrf_token|_csrf|xsrf-token)[""'][^>]+content=[""'](?<v>[^""']+)[""']|content=[""'](?<v2>[^""']+)[""'][^>]+name=[""'](?:csrf-token|csrf_token|_csrf|xsrf-token)[""'])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public sealed class PreparedLogin
    {
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string Body { get; init; } = "";
        public bool CsrfApplied { get; init; }
        public string? CsrfField { get; init; }
        public string? CsrfSource { get; init; }
    }

    public static async Task<PreparedLogin> PrepareAsync(
        AutomationContext ctx,
        string loginPostUrl,
        string method,
        Dictionary<string, string>? headers,
        string body,
        int timeoutMs,
        CancellationToken ct = default)
    {
        var headersCopy = headers != null
            ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var (fieldName, tokenValue, source) = await FetchCsrfTokenAsync(ctx, loginPostUrl, timeoutMs, ct);
        if (string.IsNullOrEmpty(fieldName) || string.IsNullOrEmpty(tokenValue))
        {
            return new PreparedLogin { Headers = headersCopy, Body = body };
        }

        var enrichedBody = InjectToken(body, fieldName, tokenValue, headersCopy);
        foreach (var headerName in CsrfTokenHeuristics.KnownHeaderNames)
        {
            if (headersCopy.ContainsKey(headerName))
                headersCopy[headerName] = tokenValue;
        }

        if (!headersCopy.Keys.Any(k => CsrfTokenHeuristics.IsCsrfHeaderName(k)))
            headersCopy["X-CSRF-Token"] = tokenValue;

        return new PreparedLogin
        {
            Headers = headersCopy,
            Body = enrichedBody,
            CsrfApplied = true,
            CsrfField = fieldName,
            CsrfSource = source
        };
    }

    private static async Task<(string? Field, string? Value, string? Source)> FetchCsrfTokenAsync(
        AutomationContext ctx,
        string loginPostUrl,
        int timeoutMs,
        CancellationToken ct)
    {
        if (!Uri.TryCreate(loginPostUrl, UriKind.Absolute, out var postUri))
            return (null, null, null);

        var origin = postUri.GetLeftPart(UriPartial.Authority);
        var candidates = BuildCsrfFetchCandidates(origin, postUri);

        foreach (var getUrl in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var resp = await SecurityProbeHttp.FetchAsync(
                ctx, getUrl, "GET", null, null, timeoutMs, includeBrowserCookies: true, ct);
            if (resp.Status is not (>= 200 and < 400)) continue;

            if (TryExtractFromJson(resp.Body, out var jsonField, out var jsonValue))
                return (jsonField, jsonValue, $"json-get:{getUrl}");

            if (TryExtractFromHtml(resp.Body, out var htmlField, out var htmlValue))
                return (htmlField, htmlValue, $"html-get:{getUrl}");

            var xsrfCookie = SecurityProbeHttp.GetResponseHeader(resp, "Set-Cookie");
            if (!string.IsNullOrEmpty(xsrfCookie)
                && xsrfCookie.Contains("XSRF-TOKEN", StringComparison.OrdinalIgnoreCase))
            {
                var cookieVal = ExtractCookieValue(xsrfCookie, "XSRF-TOKEN");
                if (!string.IsNullOrEmpty(cookieVal))
                    return ("XSRF-TOKEN", cookieVal, $"cookie-get:{getUrl}");
            }
        }

        var domScrape = await CsrfDomScraper.ScrapeDetailedAsync(ctx);
        var binding = CsrfDomScraper.PickFormForTarget(domScrape, loginPostUrl);
        if (binding != null && !string.IsNullOrEmpty(binding.Value))
            return (binding.FieldName, binding.Value, "dom-current-page");

        foreach (var (name, val) in domScrape.Tokens)
            return (name, val, "dom-hidden-field");

        return (null, null, null);
    }

    private static List<string> BuildCsrfFetchCandidates(string origin, Uri postUri)
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? url)
        {
            if (string.IsNullOrWhiteSpace(url) || !seen.Add(url)) return;
            list.Add(url);
        }

        Add(postUri.ToString());
        Add(origin + "/login");
        Add(origin + "/signin");
        Add(origin + "/sign-in");
        Add(origin + "/register");

        var path = postUri.AbsolutePath;
        if (path.Contains("/api/", StringComparison.OrdinalIgnoreCase))
            Add(origin + path.Replace("/api/", "/rest/", StringComparison.OrdinalIgnoreCase));

        return list;
    }

    private static bool TryExtractFromJson(string? body, out string fieldName, out string value)
    {
        fieldName = "";
        value = "";
        if (string.IsNullOrWhiteSpace(body) || !body.TrimStart().StartsWith('{'))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(body);
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (!CsrfTokenHeuristics.IsCsrfFieldCandidate(prop.Name, "hidden", prop.Value.GetString()))
                    continue;
                fieldName = prop.Name;
                value = prop.Value.GetString() ?? prop.Value.GetRawText();
                return !string.IsNullOrEmpty(value);
            }
        }
        catch (JsonException)
        {
        }

        return false;
    }

    private static bool TryExtractFromHtml(string? html, out string fieldName, out string value)
    {
        fieldName = "";
        value = "";
        if (string.IsNullOrWhiteSpace(html) || !html.Contains('<')) return false;

        foreach (Match m in HiddenInputRegex.Matches(html))
        {
            var tag = m.Value;
            var name = ReadHtmlAttribute(tag, "name");
            var val = ReadHtmlAttribute(tag, "value");
            var type = ReadHtmlAttribute(tag, "type");
            if (!CsrfTokenHeuristics.IsCsrfFieldCandidate(name, type, val)) continue;
            fieldName = name;
            value = val;
            return !string.IsNullOrEmpty(value);
        }

        var meta = MetaCsrfRegex.Match(html);
        if (meta.Success)
        {
            value = meta.Groups["v"].Success ? meta.Groups["v"].Value : meta.Groups["v2"].Value;
            fieldName = "_csrf";
            return !string.IsNullOrEmpty(value);
        }

        return false;
    }

    private static string InjectToken(
        string body,
        string fieldName,
        string tokenValue,
        Dictionary<string, string> headers)
    {
        if (CsrfTokenHeuristics.BodyContainsField(body, fieldName))
            return ReplaceBodyField(body, fieldName, tokenValue);

        var contentType = headers.GetValueOrDefault("Content-Type") ?? "";
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase) || body.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    using var stream = new MemoryStream();
                    using (var writer = new Utf8JsonWriter(stream))
                    {
                        writer.WriteStartObject();
                        writer.WriteString(fieldName, tokenValue);
                        foreach (var prop in doc.RootElement.EnumerateObject())
                        {
                            writer.WritePropertyName(prop.Name);
                            prop.Value.WriteTo(writer);
                        }
                        writer.WriteEndObject();
                    }
                    return System.Text.Encoding.UTF8.GetString(stream.ToArray());
                }
            }
            catch (JsonException)
            {
            }
        }

        if (body.Contains('=') && !body.TrimStart().StartsWith('{'))
            return $"{fieldName}={Uri.EscapeDataString(tokenValue)}&{body}";

        return body;
    }

    private static string ReplaceBodyField(string body, string fieldName, string tokenValue)
    {
        if (body.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind != JsonValueKind.Object) return body;
                using var stream = new MemoryStream();
                using (var writer = new Utf8JsonWriter(stream))
                {
                    writer.WriteStartObject();
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        writer.WritePropertyName(prop.Name);
                        if (prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                            writer.WriteStringValue(tokenValue);
                        else
                            prop.Value.WriteTo(writer);
                    }
                    if (!doc.RootElement.TryGetProperty(fieldName, out _))
                        writer.WriteString(fieldName, tokenValue);
                    writer.WriteEndObject();
                }
                return System.Text.Encoding.UTF8.GetString(stream.ToArray());
            }
            catch (JsonException)
            {
                return body;
            }
        }

        var encoded = Uri.EscapeDataString(tokenValue);
        if (body.Contains(fieldName + "=", StringComparison.OrdinalIgnoreCase))
        {
            return Regex.Replace(body,
                Regex.Escape(fieldName) + "=[^&]*",
                fieldName + "=" + encoded,
                RegexOptions.IgnoreCase);
        }

        return $"{fieldName}={encoded}&{body}";
    }

    private static string ReadHtmlAttribute(string tag, string attr)
    {
        var match = Regex.Match(tag, attr + @"=[""'](?<v>[^""']*)[""']", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups["v"].Value : "";
    }

    private static string? ExtractCookieValue(string setCookieHeader, string cookieName)
    {
        foreach (var part in setCookieHeader.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!part.TrimStart().StartsWith(cookieName + "=", StringComparison.OrdinalIgnoreCase))
                continue;
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var semi = part.IndexOf(';');
            return semi > eq ? part[(eq + 1)..semi].Trim() : part[(eq + 1)..].Trim();
        }
        return null;
    }
}
