using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// CSRF refresh, response classification, and third-party captcha detection for insecure-design probes.
/// </summary>
public static class InsecureDesignProbeSupport
{
    public enum ProbeResponseKind
    {
        Accepted,
        CsrfRejected,
        ProperlyRejected,
        Inconclusive,
        Error
    }

    public sealed class PreparedRequest
    {
        public string? Body { get; init; }
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public bool CsrfRefreshed { get; init; }
        public bool TokensFoundOnPage { get; init; }
        public string? CsrfFieldApplied { get; init; }
        public string? CsrfSource { get; init; }
    }

    public sealed class BurstStats
    {
        public int AcceptedCount { get; init; }
        public int CsrfRejectedCount { get; init; }
        public int ProperlyRejectedCount { get; init; }
        public int InconclusiveCount { get; init; }
        public int Total { get; init; }
        public bool AllCsrfBlocked => Total > 0 && CsrfRejectedCount == Total;
        public bool AnyAccepted => AcceptedCount > 0;
    }

    public sealed class ProbeObservation
    {
        public string Category { get; init; } = "probe-inconclusive";
        public string Severity { get; init; } = "info";
        public string Url { get; init; } = "";
        public string Detail { get; init; } = "";
    }

    public sealed class ThirdPartyCaptchaSignal
    {
        public string Provider { get; init; } = "";
        public string Detail { get; init; } = "";
    }

    public static async Task<Dictionary<string, string>> ScrapeCsrfTokensFromPageAsync(AutomationContext ctx) =>
        await CsrfDomScraper.ScrapeAsync(ctx);

    private const string DetectThirdPartyCaptchaJs = """
        (function(){
          try {
            var hits = [];
            function add(provider, detail) {
              hits.push({ provider: provider, detail: detail });
            }
            if (document.querySelector('.g-recaptcha, [data-sitekey]') ||
                document.querySelector('script[src*="google.com/recaptcha"], script[src*="gstatic.com/recaptcha"]'))
              add('recaptcha', 'Google reCAPTCHA widget or script detected in DOM');
            if (document.querySelector('.h-captcha, [data-hcaptcha-sitekey]') ||
                document.querySelector('script[src*="hcaptcha.com"]'))
              add('hcaptcha', 'hCaptcha widget or script detected in DOM');
            if (document.querySelector('.cf-turnstile, [data-turnstile-sitekey]') ||
                document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]'))
              add('turnstile', 'Cloudflare Turnstile widget or script detected in DOM');
            document.querySelectorAll('iframe[src]').forEach(function(f) {
              var src = (f.getAttribute('src') || '').toLowerCase();
              if (src.indexOf('recaptcha') >= 0) add('recaptcha', 'reCAPTCHA iframe: ' + src.substring(0, 120));
              if (src.indexOf('hcaptcha') >= 0) add('hcaptcha', 'hCaptcha iframe: ' + src.substring(0, 120));
            });
            return JSON.stringify({ hits: hits, pageUrl: location.href });
          } catch (e) {
            return JSON.stringify({ error: e.message || String(e), hits: [] });
          }
        })()
        """;

    public static async Task<List<ThirdPartyCaptchaSignal>> DetectThirdPartyCaptchaAsync(AutomationContext ctx)
    {
        var list = new List<ThirdPartyCaptchaSignal>();
        try
        {
            var json = await ctx.ExecuteJs(DetectThirdPartyCaptchaJs);
            if (string.IsNullOrWhiteSpace(json)) return list;

            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("hits", out var hits) || hits.ValueKind != JsonValueKind.Array)
                return list;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var hit in hits.EnumerateArray())
            {
                var provider = hit.TryGetProperty("provider", out var p) ? p.GetString() ?? "" : "";
                var detail = hit.TryGetProperty("detail", out var d) ? d.GetString() ?? "" : "";
                if (string.IsNullOrWhiteSpace(provider) || !seen.Add(provider)) continue;
                list.Add(new ThirdPartyCaptchaSignal { Provider = provider, Detail = detail });
            }
        }
        catch
        {
            // Ignore DOM scan failures.
        }

        return list;
    }

    public static async Task<PreparedRequest> PrepareRequestAsync(
        AutomationContext ctx,
        string? bodyTemplate,
        IReadOnlyDictionary<string, string>? headers,
        string? targetUrl = null,
        bool injectCsrfIfMissing = true,
        CancellationToken ct = default)
    {
        var headersCopy = headers != null
            ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var scrape = await CsrfDomScraper.ScrapeDetailedAsync(ctx);
        var formBinding = CsrfDomScraper.PickFormForTarget(scrape, targetUrl);

        string? fieldName = formBinding?.FieldName;
        string? tokenValue = formBinding?.Value;
        string? source = formBinding != null ? "dom-form-action" : null;

        if (string.IsNullOrEmpty(tokenValue))
        {
            foreach (var (name, val) in scrape.Tokens)
            {
                fieldName = name;
                tokenValue = val;
                source ??= "dom-hidden-field";
                break;
            }
        }

        if (string.IsNullOrEmpty(tokenValue) || string.IsNullOrEmpty(fieldName))
        {
            return new PreparedRequest
            {
                Body = bodyTemplate,
                Headers = headersCopy,
                CsrfRefreshed = false,
                TokensFoundOnPage = scrape.HasTokens
            };
        }

        var body = bodyTemplate;
        var contentType = headersCopy.GetValueOrDefault("Content-Type") ?? "";
        var preferFormEncoded = PreferFormUrlEncoded(contentType, body, formBinding);

        if (!string.IsNullOrEmpty(body) && BodyContainsCsrfField(body))
        {
            body = ReplaceBodyField(body, fieldName, tokenValue);
        }
        else if (injectCsrfIfMissing)
        {
            body = BuildBodyWithCsrf(body, fieldName, tokenValue, formBinding, preferFormEncoded);
            if (preferFormEncoded)
                headersCopy["Content-Type"] = "application/x-www-form-urlencoded";
            else if (string.IsNullOrWhiteSpace(contentType) && body.TrimStart().StartsWith('{'))
                headersCopy["Content-Type"] = "application/json";
        }

        foreach (var headerName in CsrfTokenHeuristics.KnownHeaderNames)
        {
            if (!headersCopy.ContainsKey(headerName)) continue;
            headersCopy[headerName] = tokenValue;
            fieldName ??= headerName;
            source ??= "dom-meta-or-field";
        }

        return new PreparedRequest
        {
            Body = body,
            Headers = headersCopy,
            CsrfRefreshed = BodyContainsCsrfField(body),
            TokensFoundOnPage = scrape.HasTokens,
            CsrfFieldApplied = fieldName,
            CsrfSource = source
        };
    }

    private static bool PreferFormUrlEncoded(string contentType, string? body, CsrfDomScraper.FormBinding? formBinding)
    {
        if (contentType.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.IsNullOrEmpty(body) && body.Contains('=') && !body.TrimStart().StartsWith('{'))
            return true;
        if (formBinding != null)
        {
            if (formBinding.HiddenFields.Count > 0)
                return true;
            if (formBinding.Enctype.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.IsNullOrWhiteSpace(formBinding.Enctype))
                return true;
        }
        return false;
    }

    private static bool BodyContainsCsrfField(string? body) =>
        !string.IsNullOrEmpty(body) && CsrfTokenHeuristics.TryExtractFromBody(body, out _);

    private static string BuildBodyWithCsrf(
        string? bodyTemplate,
        string fieldName,
        string tokenValue,
        CsrfDomScraper.FormBinding? formBinding,
        bool preferFormEncoded)
    {
        if (formBinding?.HiddenFields.Count > 0)
        {
            var fields = new Dictionary<string, string>(formBinding.HiddenFields, StringComparer.OrdinalIgnoreCase);
            fields[fieldName] = tokenValue;
            return EncodeFormUrlEncoded(fields);
        }

        if (preferFormEncoded)
        {
            if (!string.IsNullOrWhiteSpace(bodyTemplate)
                && bodyTemplate.Contains('=')
                && !bodyTemplate.TrimStart().StartsWith('{'))
            {
                return BodyContainsCsrfField(bodyTemplate)
                    ? ReplaceBodyField(bodyTemplate, fieldName, tokenValue)
                    : $"{bodyTemplate.TrimStart().TrimStart('&')}&{fieldName}={Uri.EscapeDataString(tokenValue)}";
            }

            return $"{fieldName}={Uri.EscapeDataString(tokenValue)}";
        }

        if (string.IsNullOrWhiteSpace(bodyTemplate) || bodyTemplate.Trim() is "{}" or "")
        {
            return JsonSerializer.Serialize(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [fieldName] = tokenValue
            });
        }

        if (bodyTemplate.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(bodyTemplate);
                var dict = new Dictionary<string, object?>();
                foreach (var prop in doc.RootElement.EnumerateObject())
                    dict[prop.Name] = prop.Value;
                dict[fieldName] = tokenValue;
                return JsonSerializer.Serialize(dict);
            }
            catch
            {
                return JsonSerializer.Serialize(new Dictionary<string, string> { [fieldName] = tokenValue });
            }
        }

        return ReplaceBodyField(bodyTemplate, fieldName, tokenValue);
    }

    private static string EncodeFormUrlEncoded(IReadOnlyDictionary<string, string> fields) =>
        string.Join("&", fields.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

    public static ProbeResponseKind ClassifyResponse(int status, string? body)
    {
        body ??= "";
        if (IsSuccessStatus(status))
            return ProbeResponseKind.Accepted;

        if (LooksLikeCsrfRejection(status, body))
            return ProbeResponseKind.CsrfRejected;

        if (InsecureDesignDiscovery.LooksLikeProperRejection(status, body))
            return ProbeResponseKind.ProperlyRejected;

        if (status >= 400)
            return ProbeResponseKind.Inconclusive;

        return ProbeResponseKind.Inconclusive;
    }

    public static bool LooksLikeCsrfRejection(int status, string? body)
    {
        body ??= "";
        var lower = body.ToLowerInvariant();

        string[] markers =
        [
            "invalid csrf", "csrf token", "csrf_token", "bad csrf", "csrf mismatch",
            "csrf validation", "csrf expired", "csrf failed", "anti-forgery", "antiforgery",
            "xsrf", "forgery token", "requestverificationtoken", "missing csrf",
            "incorrect csrf", "csrf token is incorrect", "token is incorrect",
            "the token provided", "token mismatch"
        ];

        if (markers.Any(m => lower.Contains(m, StringComparison.Ordinal)))
            return true;

        if (lower.Contains("missing parameter", StringComparison.Ordinal) && lower.Contains("csrf", StringComparison.Ordinal))
            return true;

        // Generic token rejection without the word "csrf" (common on classic PHP labs).
        if ((lower.Contains("token", StringComparison.Ordinal)
             && (lower.Contains("incorrect", StringComparison.Ordinal)
                 || lower.Contains("invalid", StringComparison.Ordinal)
                 || lower.Contains("mismatch", StringComparison.Ordinal)
                 || lower.Contains("expired", StringComparison.Ordinal)))
            && (lower.Contains("form", StringComparison.Ordinal)
                || lower.Contains("request", StringComparison.Ordinal)
                || lower.Contains("security", StringComparison.Ordinal)
                || lower.Contains("user_token", StringComparison.Ordinal)))
            return true;

        if (status == 400 && lower.Contains("csrf", StringComparison.Ordinal))
            return true;

        if (status == 403 && (lower.Contains("csrf", StringComparison.Ordinal) || lower.Contains("xsrf", StringComparison.Ordinal)))
            return true;

        return false;
    }

    /// <summary>
    /// When the response body is empty, infer CSRF gating from request shape on endpoints that normally carry CSRF.
    /// </summary>
    public static bool InferCsrfGate(int status, string? responseBody, string? requestBodySent, bool endpointHadCsrfInTemplate)
    {
        if (LooksLikeCsrfRejection(status, responseBody))
            return true;

        if (!endpointHadCsrfInTemplate || status != 400)
            return false;

        return !RequestBodyHasCsrfField(requestBodySent);
    }

    public static bool RequestBodyHasCsrfField(string? body) =>
        !string.IsNullOrEmpty(body) && CsrfTokenHeuristics.TryExtractFromBody(body, out _);

    public static BurstStats SummarizeBurst(IReadOnlyList<SecurityProbeHttp.FetchResult> results)
    {
        var stats = new int[4];
        foreach (var r in results)
        {
            switch (ClassifyResponse(r.Status, r.Body))
            {
                case ProbeResponseKind.Accepted: stats[0]++; break;
                case ProbeResponseKind.CsrfRejected: stats[1]++; break;
                case ProbeResponseKind.ProperlyRejected: stats[2]++; break;
                default: stats[3]++; break;
            }
        }

        return new BurstStats
        {
            AcceptedCount = stats[0],
            CsrfRejectedCount = stats[1],
            ProperlyRejectedCount = stats[2],
            InconclusiveCount = stats[3],
            Total = results.Count
        };
    }

    public static ProbeObservation CsrfBlockedObservation(string url, BurstStats stats, PreparedRequest prepared)
    {
        string detail;
        if (prepared.CsrfRefreshed)
        {
            detail =
                $"All {stats.Total} concurrent requests rejected by CSRF validation " +
                $"(refreshed field '{prepared.CsrfFieldApplied}' via {prepared.CsrfSource}). " +
                "Race test inconclusive — CSRF may be single-use per token. Navigate to the form page and retry immediately before scan.";
        }
        else if (prepared.TokensFoundOnPage)
        {
            detail =
                $"All {stats.Total} concurrent requests rejected by CSRF validation. " +
                "CSRF token(s) were found in the page DOM but could not be merged into the probe body — " +
                "check Content-Type (expected application/x-www-form-urlencoded for form posts).";
        }
        else
        {
            detail =
                $"All {stats.Total} concurrent requests rejected by CSRF validation. " +
                "No CSRF token found via DOM query — navigate to the form that submits to this endpoint, then retry.";
        }

        return new ProbeObservation
        {
            Category = "csrf-blocked",
            Severity = "info",
            Url = url,
            Detail = detail
        };
    }

    public static ProbeObservation ThirdPartyCaptchaObservation(ThirdPartyCaptchaSignal signal) =>
        new()
        {
            Category = "captcha-present-untestable",
            Severity = "info",
            Url = "",
            Detail = $"{signal.Provider}: {signal.Detail}. Third-party CAPTCHA cannot be replay-tested programmatically from Trowser."
        };

    private static bool IsSuccessStatus(int status) => status is >= 200 and < 300;

    internal static string ReplaceBodyField(string body, string fieldName, string newValue)
    {
        if (body.Contains('=') && !body.TrimStart().StartsWith('{'))
        {
            var pairs = body.Split('&').Select(p =>
            {
                var eq = p.IndexOf('=');
                if (eq < 0) return p;
                var key = p[..eq];
                return key.Equals(fieldName, StringComparison.OrdinalIgnoreCase)
                    ? $"{key}={Uri.EscapeDataString(newValue)}" : p;
            });
            return string.Join("&", pairs);
        }

        if (body.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                var dict = new Dictionary<string, object?>();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    dict[prop.Name] = prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase)
                        ? newValue
                        : prop.Value;
                }
                return JsonSerializer.Serialize(dict);
            }
            catch
            {
                return body;
            }
        }

        return body;
    }
}
