using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Collects security token samples (CSRF nonces, OAuth state/nonce, custom params) from
/// network traffic and DOM, then runs entropy / predictability analysis via <see cref="SessionIdAnalyzer"/>.
/// </summary>
public static class TokenEntropySampleCollector
{
    public enum TokenCollectSource
    {
        Auto,
        Query,
        Header,
        Cookie,
        Json,
        Form,
        Dom
    }

    public sealed class TokenTargetSpec
    {
        public string Name { get; set; } = "";
        public string ParamName { get; set; } = "";
        public TokenCollectSource Source { get; set; } = TokenCollectSource.Auto;
    }

    public sealed class CollectOptions
    {
        /// <summary>Single-target shorthand (alias for one entry in <see cref="Targets"/>).</summary>
        public string? Name { get; set; }
        public string? ParamName { get; set; }
        public TokenCollectSource Source { get; set; } = TokenCollectSource.Auto;
        /// <summary>Explicit targets. When set, overrides Name/ParamName/Source.</summary>
        public IReadOnlyList<TokenTargetSpec>? Targets { get; set; }
        /// <summary>Built-in discovery profiles: csrf, oauth-state, oauth-nonce, anti-forgery.</summary>
        public IReadOnlyList<string>? Presets { get; set; }
        /// <summary>When true and no explicit target, scan for known CSRF/OAuth token names in traffic + DOM.</summary>
        public bool AutoDiscover { get; set; } = true;
        public int MinSamples { get; set; } = 2;
        public bool PageNetworkOnly { get; set; }
        public IReadOnlyList<string>? ExtraSamples { get; set; }
        public bool IncludeDom { get; set; } = true;
    }

    public sealed class TargetCollectResult
    {
        public string Name { get; init; } = "";
        public string ParamName { get; init; } = "";
        public string Source { get; init; } = "";
        public SessionIdAnalysisResult Analysis { get; init; } = new();
        public int MinSamplesRequired { get; init; }
        public bool MinSamplesMet { get; init; }
        public int TotalSampleCount { get; init; }
        public List<string> SampleSources { get; init; } = [];
        public List<string> Recommendations { get; init; } = [];
    }

    public sealed class CollectResult
    {
        public string Url { get; init; } = "";
        public List<TargetCollectResult> Targets { get; init; } = [];
        public List<string> Recommendations { get; init; } = [];
        public bool IsClean => Targets.Count > 0 && Targets.All(t => t.Analysis.IsClean);
    }

    private static readonly Regex OAuthAuthorizePattern = new(
        @"(?i)(/authorize|/oauth2?/auth|openid-connect/auth|/login/oauth)",
        RegexOptions.Compiled);

    private static readonly (string preset, string name, string param, TokenCollectSource source)[] PresetCatalog =
    [
        ("oauth-state", "oauth-state", "state", TokenCollectSource.Query),
        ("oauth-nonce", "oauth-nonce", "nonce", TokenCollectSource.Query),
        ("anti-forgery", "anti-forgery-token", "__RequestVerificationToken", TokenCollectSource.Form),
        ("csrf", "csrf-field-_token", "_token", TokenCollectSource.Form),
        ("csrf", "csrf-field-csrf_token", "csrf_token", TokenCollectSource.Form),
        ("csrf", "csrf-field-csrfmiddlewaretoken", "csrfmiddlewaretoken", TokenCollectSource.Form),
        ("csrf", "csrf-field-authenticity_token", "authenticity_token", TokenCollectSource.Form),
    ];

    private static readonly (string name, string param, TokenCollectSource source)[] AutoDiscoveryCatalog =
    [
        ("oauth-state", "state", TokenCollectSource.Query),
        ("oauth-nonce", "nonce", TokenCollectSource.Query),
        ("anti-forgery-token", "__RequestVerificationToken", TokenCollectSource.Form),
        ("csrf-token", "_token", TokenCollectSource.Form),
        ("csrf-token", "csrf_token", TokenCollectSource.Form),
        ("csrf-token", "csrfmiddlewaretoken", TokenCollectSource.Form),
        ("csrf-token", "authenticity_token", TokenCollectSource.Form),
        ("request-token", "request_token", TokenCollectSource.Form),
        ("verification-token", "verification_token", TokenCollectSource.Form),
        ("nonce-field", "nonce", TokenCollectSource.Form),
        ("nonce-field", "_nonce", TokenCollectSource.Form),
    ];

    public static async Task<CollectResult> CollectAndAnalyzeAsync(
        AutomationContext ctx,
        CollectOptions options,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var url = await ctx.GetCurrentUrl();
        var specs = ResolveTargetSpecs(options);
        var networkEntries = (options.PageNetworkOnly ? ctx.Network.PageEntries : ctx.Network.Entries).ToList();
        var domValues = options.IncludeDom
            ? await CollectDomHiddenInputsAsync(ctx, specs, ct)
            : new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        var targetResults = new List<TargetCollectResult>();
        var globalRecs = new List<string>();

        var autoDiscoverOnly = options.AutoDiscover
                               && string.IsNullOrWhiteSpace(options.ParamName)
                               && (options.Targets == null || options.Targets.Count == 0)
                               && (options.Presets == null || options.Presets.Count == 0);

        foreach (var spec in specs)
        {
            ct.ThrowIfCancellationRequested();
            var samples = new List<string>();
            var sources = new List<string>();
            CollectFromNetwork(spec, networkEntries, samples, sources);
            if (domValues.TryGetValue(spec.ParamName, out var domSamples))
            {
                samples.AddRange(domSamples);
                sources.Add($"DOM hidden input ({spec.ParamName}): {domSamples.Count} value(s)");
            }

            if (options.ExtraSamples is { Count: > 0 })
            {
                samples.AddRange(options.ExtraSamples.Where(s => !string.IsNullOrWhiteSpace(s)));
                sources.Add($"extraSamples: {options.ExtraSamples.Count}");
            }

            samples = samples.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.Ordinal).ToList();
            var minRequired = Math.Max(1, options.MinSamples);
            var minMet = samples.Count >= minRequired;

            var label = string.IsNullOrWhiteSpace(spec.Name) ? spec.ParamName : spec.Name;
            var syntheticCookie = new Dictionary<string, object>
            {
                ["name"] = label,
                ["value"] = samples.FirstOrDefault() ?? ""
            };

            var analysis = new SessionIdAnalyzer().Analyze(
                url,
                [syntheticCookie],
                samples,
                minSamplesForPattern: minRequired,
                targetCookieName: label);

            var recs = new List<string>();
            if (samples.Count == 0)
            {
                recs.Add(
                    $"No samples for '{label}' ({spec.ParamName}, source={FormatSource(spec.Source)}). " +
                    "Browse flows that emit this token, pass samples[], or enable autoDiscover/presets.");
            }
            else if (!minMet)
            {
                recs.Add(
                    $"Only {samples.Count} sample(s) for '{label}' — need {minRequired} for reliable predictability analysis.");
            }

            targetResults.Add(new TargetCollectResult
            {
                Name = label,
                ParamName = spec.ParamName,
                Source = FormatSource(spec.Source),
                Analysis = analysis,
                MinSamplesRequired = minRequired,
                MinSamplesMet = minMet,
                TotalSampleCount = samples.Count,
                SampleSources = sources.Distinct(StringComparer.Ordinal).ToList(),
                Recommendations = recs
            });
        }

        if (autoDiscoverOnly && targetResults.Any(t => t.TotalSampleCount > 0))
            targetResults = targetResults.Where(t => t.TotalSampleCount > 0).ToList();

        if (targetResults.Count == 0)
        {
            globalRecs.Add(
                "No token targets configured. Pass paramName, targets[], presets[] (csrf, oauth-state, oauth-nonce), or autoDiscover: true.");
        }
        else if (targetResults.All(t => t.TotalSampleCount == 0))
        {
            globalRecs.Add(
                "No token samples collected. Trigger OAuth login, form loads, or CSRF-protected POSTs to populate the network log.");
        }

        return new CollectResult
        {
            Url = url,
            Targets = targetResults,
            Recommendations = globalRecs
        };
    }

    private static List<TokenTargetSpec> ResolveTargetSpecs(CollectOptions options)
    {
        if (options.Targets is { Count: > 0 })
            return options.Targets.Select(NormalizeSpec).ToList();

        if (!string.IsNullOrWhiteSpace(options.ParamName))
        {
            return
            [
                new TokenTargetSpec
                {
                    Name = options.Name ?? options.ParamName!,
                    ParamName = options.ParamName!,
                    Source = options.Source
                }
            ];
        }

        var specs = new List<TokenTargetSpec>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.Presets is { Count: > 0 })
        {
            foreach (var preset in options.Presets.Where(p => !string.IsNullOrWhiteSpace(p)))
            {
                var key = preset.Trim().ToLowerInvariant();
                if (key is "csrf" or "anti-forgery")
                {
                    foreach (var header in CsrfTokenHeuristics.KnownHeaderNames)
                        AddUnique(specs, seen, $"csrf-header-{header}", header, TokenCollectSource.Header);
                    foreach (var field in CsrfTokenHeuristics.KnownFieldNames)
                        AddUnique(specs, seen, $"csrf-field-{field}", field, TokenCollectSource.Form);
                    foreach (var field in CsrfTokenHeuristics.KnownDomFieldNames)
                        AddUnique(specs, seen, $"csrf-dom-{field}", field, TokenCollectSource.Dom);
                }

                foreach (var row in PresetCatalog.Where(r => r.preset == key))
                    AddUnique(specs, seen, row.name, row.param, row.source);
            }
        }

        if (options.AutoDiscover && specs.Count == 0)
        {
            foreach (var row in AutoDiscoveryCatalog)
                AddUnique(specs, seen, row.name, row.param, row.source);
            foreach (var header in CsrfTokenHeuristics.KnownHeaderNames)
                AddUnique(specs, seen, $"csrf-header-{header}", header, TokenCollectSource.Header);
        }

        return specs;
    }

    private static void AddUnique(
        List<TokenTargetSpec> specs,
        HashSet<string> seen,
        string name,
        string param,
        TokenCollectSource source)
    {
        var key = $"{FormatSource(source)}|{param}";
        if (!seen.Add(key)) return;
        specs.Add(new TokenTargetSpec { Name = name, ParamName = param, Source = source });
    }

    private static TokenTargetSpec NormalizeSpec(TokenTargetSpec spec) =>
        new()
        {
            Name = string.IsNullOrWhiteSpace(spec.Name) ? spec.ParamName : spec.Name,
            ParamName = spec.ParamName,
            Source = spec.Source
        };

    private static void CollectFromNetwork(
        TokenTargetSpec spec,
        IReadOnlyList<NetworkEntry> entries,
        List<string> samples,
        List<string> sources)
    {
        var sourcesToScan = ExpandSources(spec.Source);
        foreach (var entry in entries)
        {
            foreach (var src in sourcesToScan)
            {
                switch (src)
                {
                    case TokenCollectSource.Query:
                        CollectQuery(entry, spec, samples, sources);
                        break;
                    case TokenCollectSource.Header:
                        CollectHeaders(entry, spec, samples, sources);
                        break;
                    case TokenCollectSource.Cookie:
                        CollectCookies(entry, spec, samples, sources);
                        break;
                    case TokenCollectSource.Json:
                        CollectJson(entry.ResponseBody, spec, samples, sources, entry.Path, response: true);
                        CollectJson(entry.RequestBody, spec, samples, sources, entry.Path, response: false);
                        break;
                    case TokenCollectSource.Form:
                        CollectForm(entry.RequestBody, entry.RequestHeaders, spec, samples, sources, entry.Path);
                        CollectForm(entry.ResponseBody, entry.ResponseHeaders, spec, samples, sources, entry.Path);
                        break;
                }
            }
        }
    }

    private static IEnumerable<TokenCollectSource> ExpandSources(TokenCollectSource source) =>
        source switch
        {
            TokenCollectSource.Auto =>
            [
                TokenCollectSource.Query,
                TokenCollectSource.Header,
                TokenCollectSource.Cookie,
                TokenCollectSource.Json,
                TokenCollectSource.Form
            ],
            TokenCollectSource.Dom => [],
            _ => [source]
        };

    private static void CollectQuery(
        NetworkEntry entry,
        TokenTargetSpec spec,
        List<string> samples,
        List<string> sources)
    {
        if (string.IsNullOrEmpty(entry.Url)) return;
        if (IsOAuthTarget(spec) && !OAuthAuthorizePattern.IsMatch(entry.Url))
            return;

        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
            return;

        var query = uri.Query.TrimStart('?');
        if (string.IsNullOrEmpty(query)) return;

        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var name = Uri.UnescapeDataString(part[..eq]);
            if (!name.Equals(spec.ParamName, StringComparison.OrdinalIgnoreCase)) continue;
            var value = Uri.UnescapeDataString(part[(eq + 1)..]);
            if (IsPlausibleToken(value))
            {
                samples.Add(value);
                sources.Add($"query param on {entry.Path ?? uri.AbsolutePath}");
            }
        }
    }

    private static void CollectHeaders(
        NetworkEntry entry,
        TokenTargetSpec spec,
        List<string> samples,
        List<string> sources)
    {
        foreach (var headers in new[] { entry.RequestHeaders, entry.ResponseHeaders })
        {
            if (headers == null) continue;
            foreach (var (key, value) in headers)
            {
                if (!key.Equals(spec.ParamName, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (IsPlausibleToken(value))
                {
                    samples.Add(value);
                    sources.Add($"header {key} on {entry.Path}");
                }
            }
        }
    }

    private static void CollectCookies(
        NetworkEntry entry,
        TokenTargetSpec spec,
        List<string> samples,
        List<string> sources)
    {
        if (entry.ResponseHeaders == null) return;
        foreach (var h in entry.ResponseHeaders.Where(h =>
                     h.Key.Equals("set-cookie", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var parsed in SetCookieHeaderParser.ParseHeaderValue(h.Value))
            {
                var name = parsed["name"]?.ToString() ?? "";
                if (!name.Equals(spec.ParamName, StringComparison.OrdinalIgnoreCase)) continue;
                var value = parsed["value"]?.ToString();
                if (IsPlausibleToken(value))
                {
                    samples.Add(value!);
                    sources.Add($"Set-Cookie {name} on {entry.Path}");
                }
            }
        }
    }

    private static void CollectJson(
        string? body,
        TokenTargetSpec spec,
        List<string> samples,
        List<string> sources,
        string? path,
        bool response)
    {
        if (string.IsNullOrWhiteSpace(body) || !body.TrimStart().StartsWith('{')) return;
        try
        {
            using var doc = JsonDocument.Parse(body.Length > 131_072 ? body[..131_072] : body);
            ExtractJsonField(doc.RootElement, spec.ParamName, samples, sources, path, response);
        }
        catch { /* ignore */ }
    }

    private static void ExtractJsonField(
        JsonElement el,
        string fieldName,
        List<string> samples,
        List<string> sources,
        string? path,
        bool response,
        string prefix = "")
    {
        if (el.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in el.EnumerateObject())
            {
                var full = string.IsNullOrEmpty(prefix) ? prop.Name : $"{prefix}.{prop.Name}";
                if (prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase)
                    && prop.Value.ValueKind == JsonValueKind.String)
                {
                    var v = prop.Value.GetString();
                    if (IsPlausibleToken(v))
                    {
                        samples.Add(v!);
                        sources.Add($"{(response ? "response" : "request")} JSON {full} on {path}");
                    }
                }
                else if (prop.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                    ExtractJsonField(prop.Value, fieldName, samples, sources, path, response, full);
            }
        }
        else if (el.ValueKind == JsonValueKind.Array)
        {
            var i = 0;
            foreach (var item in el.EnumerateArray())
            {
                ExtractJsonField(item, fieldName, samples, sources, path, response, $"{prefix}[{i}]");
                i++;
            }
        }
    }

    private static void CollectForm(
        string? body,
        IReadOnlyDictionary<string, string>? headers,
        TokenTargetSpec spec,
        List<string> samples,
        List<string> sources,
        string? path)
    {
        if (string.IsNullOrWhiteSpace(body)) return;
        var contentType = headers?.FirstOrDefault(h =>
            h.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)).Value ?? "";
        if (!contentType.Contains("form", StringComparison.OrdinalIgnoreCase)
            && !body.Contains('='))
            return;

        foreach (var part in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var name = Uri.UnescapeDataString(part[..eq].Replace('+', ' '));
            if (!name.Equals(spec.ParamName, StringComparison.OrdinalIgnoreCase)) continue;
            var value = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
            if (IsPlausibleToken(value))
            {
                samples.Add(value);
                sources.Add($"form field on {path}");
            }
        }
    }

    private static async Task<Dictionary<string, List<string>>> CollectDomHiddenInputsAsync(
        AutomationContext ctx,
        IReadOnlyList<TokenTargetSpec> specs,
        CancellationToken ct)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (specs.Count == 0) return result;

        var names = specs
            .Where(s => s.Source is TokenCollectSource.Dom or TokenCollectSource.Auto or TokenCollectSource.Form)
            .Select(s => s.ParamName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (names.Count == 0) return result;

        ct.ThrowIfCancellationRequested();
        try
        {
            var namesJson = JsonSerializer.Serialize(names);
            var raw = await ctx.ExecuteJs(
                $$"""
                (function(names){
                  var lower = {};
                  names.forEach(function(n){ lower[n.toLowerCase()] = n; });
                  var out = {};
                  names.forEach(function(n){ out[n] = []; });
                  document.querySelectorAll('input[type="hidden"]').forEach(function(el){
                    if (!el.name || !el.value) return;
                    var canonical = lower[el.name.toLowerCase()];
                    if (canonical) out[canonical].push(el.value);
                  });
                  return JSON.stringify(out);
                })({{namesJson}})
                """);

            if (string.IsNullOrWhiteSpace(raw) || raw == "null") return result;
            using var doc = JsonDocument.Parse(raw);
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.Array) continue;
                var values = prop.Value.EnumerateArray()
                    .Select(e => e.GetString())
                    .Where(v => IsPlausibleToken(v))
                    .Select(v => v!)
                    .ToList();
                if (values.Count > 0)
                    result[prop.Name] = values;
            }
        }
        catch { /* DOM unavailable */ }

        return result;
    }

    private static bool IsOAuthTarget(TokenTargetSpec spec) =>
        spec.Name.Contains("oauth", StringComparison.OrdinalIgnoreCase)
        || spec.ParamName.Equals("state", StringComparison.OrdinalIgnoreCase)
        || spec.ParamName.Equals("nonce", StringComparison.OrdinalIgnoreCase);

    private static bool IsPlausibleToken(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length >= 4 && value.Length <= 512;

    private static string FormatSource(TokenCollectSource source) =>
        source switch
        {
            TokenCollectSource.Query => "query",
            TokenCollectSource.Header => "header",
            TokenCollectSource.Cookie => "cookie",
            TokenCollectSource.Json => "json",
            TokenCollectSource.Form => "form",
            TokenCollectSource.Dom => "dom",
            _ => "auto"
        };
}
