using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Tests protected endpoints for missing authentication, JWT alg:none acceptance,
/// and optional alg-header variants (case/whitespace/missing alg).
/// Cookie-isolated requests avoid attributing session cookies to JWT/header auth tests.
/// </summary>
public static class JwtAcceptanceSweep
{
    public sealed class SweepOptions
    {
        public string? Host { get; set; }
        public int MaxEndpoints { get; set; } = 15;
        public int TimeoutMs { get; set; } = 15000;
        /// <summary>JWT to forge alg:none from, or a ready-made alg:none / Bearer token.</summary>
        public string? BaseToken { get; set; }
        /// <summary>Alias for <see cref="BaseToken"/>.</summary>
        public string? Token { get; set; }
        public bool IncludeUnauthenticatedOnly { get; set; }
        /// <summary>When true, test alg variants on endpoints that reject canonical alg:none.</summary>
        public bool IncludeAlgVariants { get; set; } = true;
        public bool Verbose { get; set; }
        /// <summary>When true (default), skip CDN/widget hosts outside scope.</summary>
        public bool ExcludeThirdParty { get; set; } = true;
        /// <summary>
        /// Explicit URLs to probe. When non-empty, these are tested first (and exclusively
        /// unless <see cref="IncludeNetworkLog"/> is true).
        /// </summary>
        public List<string>? Endpoints { get; set; }
        /// <summary>
        /// Include attack-surface candidates from the network log.
        /// Default: <c>false</c> when <see cref="Endpoints"/> is non-empty, otherwise <c>true</c>.
        /// </summary>
        public bool? IncludeNetworkLog { get; set; }
        /// <summary>
        /// Cookie name for cookie-transport probes (e.g. <c>_dct</c>).
        /// When set (or inferred from a cookie JWT source), alg:none is tested via both
        /// <c>Authorization: Bearer</c> and <c>Cookie: name=</c>.
        /// </summary>
        public string? CookieName { get; set; }
    }

    public sealed class SweepRow
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public int AnonStatus { get; init; }
        public int JwtNoneStatus { get; init; }
        public string AnonHash { get; init; } = "";
        public string JwtNoneHash { get; init; } = "";
        public string Finding { get; init; } = "";
        public string Severity { get; init; } = "info";
        public string? Detail { get; init; }
        public string? JwtPayloadUsed { get; init; }
        public string? VariantName { get; init; }
        public string? AlgValue { get; init; }
        /// <summary><c>bearer</c>, <c>cookie</c>, or <c>anon</c>.</summary>
        public string? Transport { get; init; }
        public string? CookieName { get; init; }
    }

    public sealed class SweepResult
    {
        public List<SweepRow> Rows { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public int EndpointsTested { get; init; }
        public int VariantFindings { get; init; }
        public string? JwtSource { get; init; }
        public string? AuthContext { get; init; }
        public string? CookieName { get; init; }
        public bool IncludedNetworkLog { get; init; }
        public List<string>? ExplicitEndpoints { get; init; }
    }

    public static async Task<SweepResult> RunAsync(
        AutomationContext ctx,
        SweepOptions options,
        CancellationToken ct = default)
    {
        var explicitEndpoints = NormalizeExplicitEndpoints(options.Endpoints);
        var includeNetworkLog = options.IncludeNetworkLog
            ?? (explicitEndpoints.Count == 0);

        string? pageUrl = null;
        try { pageUrl = await ctx.GetCurrentUrl(); }
        catch { /* page URL is optional; well-known CDNs are still excluded */ }
        var scopeHost = SecurityHostScope.ResolveScopeHost(options.Host, pageUrl);

        var candidates = new List<AttackSurfaceEndpoint>();
        foreach (var url in explicitEndpoints)
        {
            candidates.Add(new AttackSurfaceEndpoint
            {
                Url = url,
                UrlTemplate = url,
                Methods = { "GET" },
                Auth = new AttackSurfaceAuth { Required = true, Type = "bearer" },
                TestPriority = "critical",
                DiscoveredVia = { "explicit" }
            });
        }

        if (includeNetworkLog)
        {
            var remaining = Math.Max(0, options.MaxEndpoints - candidates.Count);
            if (remaining > 0 || explicitEndpoints.Count == 0)
            {
                var fromLog = JwtProbeHelpers.SelectCandidateEndpoints(
                    ctx, options.Host, explicitEndpoints.Count == 0 ? options.MaxEndpoints : remaining,
                    options.ExcludeThirdParty, scopeHost);
                var seen = new HashSet<string>(candidates.Select(c => c.Url), StringComparer.OrdinalIgnoreCase);
                foreach (var ep in fromLog)
                {
                    if (!seen.Add(ep.Url)) continue;
                    candidates.Add(ep);
                }
            }
        }

        if (candidates.Count > options.MaxEndpoints)
            candidates = candidates.Take(options.MaxEndpoints).ToList();

        var explicitToken = JwtProbeHelpers.NormalizeBearerToken(options.Token ?? options.BaseToken);
        string? jwtSource = explicitToken != null ? "explicit" : null;
        string? authContext = null;
        string? cookieName = string.IsNullOrWhiteSpace(options.CookieName)
            ? null
            : options.CookieName.Trim();

        if (string.IsNullOrWhiteSpace(explicitToken))
        {
            var analyzed = await HttpSecurityProbes.RunJwtAnalyzeAsync(ctx, null, ct);
            var pick = analyzed.Tokens
                .OrderByDescending(t => ScoreJwtSource(t.Source))
                .FirstOrDefault(t => !string.IsNullOrWhiteSpace(JwtProbeHelpers.TokenForProbe(t)));
            explicitToken = JwtProbeHelpers.TokenForProbe(pick);
            if (!string.IsNullOrWhiteSpace(explicitToken))
            {
                jwtSource = pick?.Source;
                if (cookieName == null && TryExtractCookieName(pick?.Source, out var inferredCookie))
                    cookieName = inferredCookie;
            }
        }

        if (string.IsNullOrWhiteSpace(explicitToken))
        {
            try
            {
                var cookies = await ctx.GetCookies();
                var jwtCookie = cookies
                    .Select(c =>
                    {
                        var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                        var value = c.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
                        return (name, value);
                    })
                    .Where(c => !string.IsNullOrEmpty(c.name) && SessionIdentityIntrospection.LooksLikeJwt(c.value))
                    .OrderByDescending(c => c.name.Equals("_dct", StringComparison.OrdinalIgnoreCase) ? 2
                        : c.name.Contains("access", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
                    .FirstOrDefault();

                if (!string.IsNullOrEmpty(jwtCookie.name))
                {
                    explicitToken = JwtProbeHelpers.NormalizeBearerToken(jwtCookie.value);
                    jwtSource = $"httpOnlyCookie:{jwtCookie.name}";
                    cookieName ??= jwtCookie.name;
                }
                else
                {
                    var sessionish = cookies.FirstOrDefault(c =>
                    {
                        var name = c.TryGetValue("name", out var n) ? n?.ToString()?.ToLowerInvariant() : "";
                        var value = c.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
                        if (SessionIdentityIntrospection.LooksLikeJwt(value)) return false;
                        return name is "session" or "connect.sid" or "jsessionid"
                            || (name?.Contains("session", StringComparison.Ordinal) == true)
                            || (name?.Contains("auth", StringComparison.Ordinal) == true);
                    });
                    if (sessionish != null)
                    {
                        authContext =
                            "Session cookie(s) present but no JWT — site likely uses cookie-based auth; " +
                            "JWT alg:none tests skipped unless you pass token/baseToken explicitly.";
                    }
                }
            }
            catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
        }
        else if (cookieName == null && TryExtractCookieName(jwtSource, out var fromSource))
        {
            cookieName = fromSource;
        }

        var (algNoneToken, algNoneNote) = JwtProbeHelpers.BuildAlgNoneBearerToken(explicitToken);
        if (algNoneToken != null && jwtSource == null)
            jwtSource = "explicit";

        var rawAlgNone = algNoneToken != null
            ? (algNoneToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? algNoneToken["Bearer ".Length..].Trim()
                : algNoneToken)
            : null;

        var rows = new List<SweepRow>();
        var summary = new List<string>();
        var endpointsTested = 0;

        // Bearer always; Cookie transport when a cookie name is known (cookie-JWT apps).
        var transports = new List<(string Name, Dictionary<string, string> Headers)>();
        if (!string.IsNullOrWhiteSpace(rawAlgNone))
        {
            transports.Add(("bearer", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = $"Bearer {rawAlgNone}"
            }));
            if (!string.IsNullOrWhiteSpace(cookieName))
            {
                transports.Add(("cookie", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Cookie"] = $"{cookieName}={rawAlgNone}"
                }));
            }
        }

        foreach (var ep in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var url = ep.Url;
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
                continue;

            endpointsTested++;
            var anon = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, options.TimeoutMs, includeBrowserCookies: false, ct);
            var anonOk = anon.Status is >= 200 and < 300;
            var anonHash = JwtProbeHelpers.ShortHash(anon.Body);
            var anonContentType = HeaderValue(anon.ResponseHeaders, "Content-Type");

            if (JwtProbeHelpers.IsStaticAsset(url, anonContentType))
            {
                rows.Add(MakeRow(url, anon.Status, 0, anonHash, "", "NO_ISSUE", "info",
                    "Static asset or map/CDN response — not scored as missing authentication.",
                    options.Verbose ? anonContentType : null,
                    transport: "anon"));
                continue;
            }

            if (options.IncludeUnauthenticatedOnly || string.IsNullOrWhiteSpace(rawAlgNone))
            {
                if (anonOk && JwtProbeHelpers.LooksSensitive(anon.Body, ep.UrlTemplate))
                {
                    rows.Add(MakeRow(url, anon.Status, 0, anonHash, "", "MISSING_AUTH", "high",
                        "Endpoint returned success without Authorization header or session cookies.",
                        options.Verbose ? "anon GET (no cookies, no Authorization)" : null,
                        transport: "anon"));
                }
                else
                {
                    rows.Add(MakeRow(url, anon.Status, 0, anonHash, "", "NO_ISSUE",
                        "info", DescribeCleanAnon(anon.Status),
                        options.Verbose ? "anon GET only (no JWT token available)" : null,
                        transport: "anon"));
                }
                continue;
            }

            // Probe alg:none on anonymous 2xx and 4xx. A session cookie does not make this a cookie-only site.
            if (anon.Status is not (>= 200 and < 300 or >= 400 and < 500))
            {
                rows.Add(MakeRow(url, anon.Status, 0, anonHash, "", "NO_ISSUE", "info",
                    $"Anonymous GET returned {anon.Status} — not a 2xx/4xx JWT test target.",
                    algNoneNote, transport: "anon"));
                continue;
            }

            var findingBefore = rows.Count;
            int lastJwtStatus = 0;
            string lastJwtHash = "";
            string? lastTransport = null;

            foreach (var (transportName, headers) in transports)
            {
                ct.ThrowIfCancellationRequested();
                var jwtResp = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", headers, null, options.TimeoutMs,
                    includeBrowserCookies: false, ct);
                var jwtHash = JwtProbeHelpers.ShortHash(jwtResp.Body);
                lastJwtStatus = jwtResp.Status;
                lastJwtHash = jwtHash;
                lastTransport = transportName;

                var verbosePayload = options.Verbose
                    ? $"anon GET → {anon.Status}; jwt GET transport={transportName} → {jwtResp.Status}"
                    : algNoneNote;

                if (IsAlgNoneAcceptance(anon.Status, anon.Body, jwtResp.Status, jwtResp.Body, ep.UrlTemplate))
                {
                    var sensitive = JwtProbeHelpers.LooksSensitive(jwtResp.Body, ep.UrlTemplate);
                    var gated = anon.Status is 401 or 403;
                    rows.Add(MakeRow(url, anon.Status, jwtResp.Status, anonHash, jwtHash, "JWT_ALG_NONE_ACCEPTED",
                        gated ? (sensitive ? "critical" : "high") : (sensitive ? "high" : "medium"),
                        gated
                            ? (sensitive
                                ? $"Anonymous request denied but alg:none JWT was accepted via {transportName} with a sensitive-looking body."
                                : $"Anonymous request denied (401/403) but alg:none JWT received HTTP success via {transportName} — JWT signature not verified.")
                            : $"Anonymous GET returned {anon.Status}; alg:none JWT via {transportName} returned {jwtResp.Status} with a different body — signature not verified.",
                        verbosePayload, transport: transportName,
                        cookieName: transportName == "cookie" ? cookieName : null));
                    continue;
                }

                if (options.IncludeAlgVariants && transportName == "bearer" && anon.Status is 401 or 403)
                {
                    foreach (var variant in JwtProbeHelpers.AlgVariants)
                    {
                        ct.ThrowIfCancellationRequested();
                        var variantToken = JwtProbeHelpers.CraftAlgVariantToken(variant.AlgValue);
                        var vHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["Authorization"] = $"Bearer {variantToken}"
                        };
                        var vResp = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", vHeaders, null, options.TimeoutMs,
                            includeBrowserCookies: false, ct);
                        if (vResp.Status is not (>= 200 and < 300)) continue;

                        var algDisplay = variant.AlgValue switch
                        {
                            null => "(missing)",
                            string s => s,
                            _ => JsonSerializer.Serialize(variant.AlgValue)
                        };
                        var vSensitive = JwtProbeHelpers.LooksSensitive(vResp.Body, ep.UrlTemplate);
                        rows.Add(MakeRow(url, anon.Status, vResp.Status, anonHash, JwtProbeHelpers.ShortHash(vResp.Body),
                            "JWT_ALG_VARIANT_ACCEPTED", vSensitive ? "critical" : "high",
                            $"Canonical alg:none rejected but variant '{variant.Name}' was accepted.",
                            $"variant alg={algDisplay}",
                            variant.Name, algDisplay, transport: "bearer"));
                        break;
                    }
                }
            }

            if (rows.Count == findingBefore)
            {
                if (anonOk && JwtProbeHelpers.LooksSensitive(anon.Body, ep.UrlTemplate))
                {
                    rows.Add(MakeRow(url, anon.Status, lastJwtStatus, anonHash, lastJwtHash, "MISSING_AUTH", "high",
                        "Endpoint returned success without Authorization header or session cookies.",
                        options.Verbose ? "anon GET (no cookies, no Authorization)" : null,
                        transport: "anon"));
                }
                else
                {
                    rows.Add(MakeRow(url, anon.Status, lastJwtStatus, anonHash, lastJwtHash, "NO_ISSUE", "info",
                        $"Anon {anon.Status}, JWT {lastJwtStatus} — no acceptance signal" +
                        (transports.Count > 1 ? $" (tested {string.Join("+", transports.Select(t => t.Name))})" : "") + ".",
                        options.Verbose
                            ? $"anon GET → {anon.Status}; last transport={lastTransport}"
                            : algNoneNote,
                        transport: lastTransport,
                        cookieName: lastTransport == "cookie" ? cookieName : null));
                }
            }
        }

        var variantCount = rows.Count(r => r.Finding == "JWT_ALG_VARIANT_ACCEPTED");
        if (rows.Any(r => r.Finding == "JWT_ALG_NONE_ACCEPTED"))
            summary.Add($"{rows.Count(r => r.Finding == "JWT_ALG_NONE_ACCEPTED")} endpoint(s) accept alg:none JWT.");
        if (variantCount > 0)
            summary.Add($"{variantCount} endpoint(s) accept non-canonical JWT alg variants.");
        if (rows.Any(r => r.Finding == "MISSING_AUTH"))
            summary.Add($"{rows.Count(r => r.Finding == "MISSING_AUTH")} endpoint(s) reachable without authentication.");
        if (string.IsNullOrWhiteSpace(rawAlgNone))
            summary.Add("No JWT token available — only anonymous GET checks were run (pass token or baseToken for alg:none tests).");
        else if (!rows.Any(r => r.Finding is "JWT_ALG_NONE_ACCEPTED" or "JWT_ALG_VARIANT_ACCEPTED" or "MISSING_AUTH"))
            summary.Add($"Tested {endpointsTested} endpoint(s); no missing-auth or JWT acceptance issues detected.");

        if (includeNetworkLog && options.ExcludeThirdParty && !string.IsNullOrEmpty(scopeHost))
            summary.Add($"Network-log candidates scoped to {scopeHost} (third-party hosts and static assets excluded).");
        if (!string.IsNullOrEmpty(cookieName))
            summary.Add($"Cookie transport also probed via Cookie: {cookieName}=…");
        if (explicitEndpoints.Count > 0)
            summary.Add($"Explicit endpoints: {explicitEndpoints.Count}; network-log candidates: {(includeNetworkLog ? "included" : "skipped")}.");

        if (!string.IsNullOrEmpty(authContext))
            summary.Add(authContext);

        return new SweepResult
        {
            Rows = rows,
            Summary = summary,
            EndpointsTested = endpointsTested,
            VariantFindings = variantCount,
            JwtSource = jwtSource,
            AuthContext = authContext,
            CookieName = cookieName,
            IncludedNetworkLog = includeNetworkLog,
            ExplicitEndpoints = explicitEndpoints.Count > 0 ? explicitEndpoints : null
        };
    }

    private static List<string> NormalizeExplicitEndpoints(IEnumerable<string>? endpoints)
    {
        if (endpoints == null) return [];
        return endpoints
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Select(u => u.Trim())
            .Where(u => Uri.TryCreate(u, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static int ScoreJwtSource(string? source)
    {
        if (string.IsNullOrEmpty(source)) return 0;
        if (source.StartsWith("httpOnlyCookie:", StringComparison.OrdinalIgnoreCase)) return 100;
        if (source.StartsWith("cookie:", StringComparison.OrdinalIgnoreCase)) return 90;
        if (source.Equals("cookie", StringComparison.OrdinalIgnoreCase)) return 80;
        if (source.StartsWith("localStorage", StringComparison.OrdinalIgnoreCase)) return 40;
        if (source.StartsWith("sessionStorage", StringComparison.OrdinalIgnoreCase)) return 35;
        if (source.StartsWith("responseHeader", StringComparison.OrdinalIgnoreCase)) return 20;
        if (source.StartsWith("responseBody", StringComparison.OrdinalIgnoreCase)) return 10;
        return 5;
    }

    private static bool TryExtractCookieName(string? source, out string? cookieName)
    {
        cookieName = null;
        if (string.IsNullOrEmpty(source)) return false;
        const string httpOnly = "httpOnlyCookie:";
        const string cookie = "cookie:";
        if (source.StartsWith(httpOnly, StringComparison.OrdinalIgnoreCase))
        {
            cookieName = source[httpOnly.Length..].Trim();
            return !string.IsNullOrEmpty(cookieName);
        }
        if (source.StartsWith(cookie, StringComparison.OrdinalIgnoreCase)
            && !source.Equals("cookie", StringComparison.OrdinalIgnoreCase))
        {
            cookieName = source[cookie.Length..].Trim();
            return !string.IsNullOrEmpty(cookieName);
        }
        return false;
    }

    private static SweepRow MakeRow(string url, int anonStatus, int jwtStatus, string anonHash, string jwtHash,
        string finding, string severity, string detail, string? jwtPayloadUsed,
        string? variantName = null, string? algValue = null, string? transport = null, string? cookieName = null) =>
        new()
        {
            Url = url,
            Method = "GET",
            AnonStatus = anonStatus,
            JwtNoneStatus = jwtStatus,
            AnonHash = anonHash,
            JwtNoneHash = jwtHash,
            Finding = finding,
            Severity = severity,
            Detail = detail,
            JwtPayloadUsed = jwtPayloadUsed,
            VariantName = variantName,
            AlgValue = algValue,
            Transport = transport,
            CookieName = cookieName
        };

    /// <summary>
    /// alg:none acceptance: 401/403→2xx, other 4xx→2xx API body, or 2xx→2xx where only the forged call looks sensitive.
    /// </summary>
    internal static bool IsAlgNoneAcceptance(int anonStatus, string anonBody, int jwtStatus, string jwtBody, string urlTemplate)
    {
        if (jwtStatus is not (>= 200 and < 300)) return false;
        // Gated 401/403 → 200 is the classic signal, including HTML. Other statuses ignore SPA shells.
        if (anonStatus is not (401 or 403) && LooksLikeHtmlShell(jwtBody)) return false;

        if (anonStatus is 401 or 403)
            return true;

        var anonHash = JwtProbeHelpers.ShortHash(anonBody);
        var jwtHash = JwtProbeHelpers.ShortHash(jwtBody);
        if (anonHash == jwtHash) return false;

        if (anonStatus is >= 400 and < 500)
            return IsJsonApiBody(jwtBody) && !LooksLikeAuthError(jwtBody);

        if (anonStatus is >= 200 and < 300)
        {
            return JwtProbeHelpers.LooksSensitive(jwtBody, urlTemplate)
                   && !JwtProbeHelpers.LooksSensitive(anonBody ?? "", urlTemplate);
        }

        return false;
    }

    private static bool IsJsonApiBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        return t.StartsWith('{') || t.StartsWith('[');
    }

    private static bool LooksLikeHtmlShell(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        return t.StartsWith("<!doctype", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("<html", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeAuthError(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var lower = body.ToLowerInvariant();
        return lower.Contains("unauthorized") || lower.Contains("forbidden") || lower.Contains("invalid token");
    }

    private static string? HeaderValue(IReadOnlyDictionary<string, string> headers, string name) =>
        headers.TryGetValue(name, out var value) ? value : null;

    private static string DescribeCleanAnon(int status) =>
        status is >= 200 and < 300
            ? "Anonymous GET succeeded but response did not look sensitive."
            : $"Anonymous GET returned {status}.";
}
