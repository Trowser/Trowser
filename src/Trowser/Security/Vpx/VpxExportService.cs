using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.Vpx;

/// <summary>
/// Builds VPX 1.1 documents from Trowser session state (findings + proof records).
/// VPX 1.0 documents are still accepted on import.
/// </summary>
public static class VpxExportService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    private static readonly string TrowserVersion =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0";

    internal const string SessionRunId = "run-trowser-session";

    public sealed class ExportInput
    {
        public required IReadOnlyList<ChainableFinding> Findings { get; init; }
        public required IReadOnlyList<VpxProofRecord> Proofs { get; init; }
        public IReadOnlyList<VpxVerdictRecord>? Verdicts { get; init; }
        public IReadOnlyDictionary<string, Dictionary<string, object?>>? ImportedSurfaces { get; init; }
        public IReadOnlyList<Dictionary<string, object?>>? ImportedRuns { get; init; }
        public IReadOnlyList<Dictionary<string, object?>>? ImportedAssessments { get; init; }
        public IReadOnlyList<Dictionary<string, object?>>? ImportedArtifacts { get; init; }
        public Dictionary<string, object?>? ImportTarget { get; init; }
        public string? BaseUrl { get; init; }
        public string Profile { get; init; } = "compact";
        public string? DocumentId { get; init; }
    }

    public static string ExportJson(ExportInput input) =>
        JsonSerializer.Serialize(BuildDocument(input), JsonOptions);

    public static object BuildDocument(ExportInput input)
    {
        var compact = !input.Profile.Equals("full", StringComparison.OrdinalIgnoreCase);
        var now = DateTime.UtcNow;

        var (surfaces, surfaceIdsByKey) = BuildSurfaces(input.Findings, input.ImportedSurfaces);
        var surfaceById = surfaces
            .OfType<Dictionary<string, object?>>()
            .GroupBy(s => (string)s["id"]!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var collapsed = CollapseExportFindings(input.Findings);
        var findings = collapsed
            .Select(f => MapFinding(f, compact, input.ImportTarget, surfaceById, surfaceIdsByKey))
            .ToList();
        var findingIds = findings
            .Select(f => (string)((Dictionary<string, object?>)f)["id"]!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var proofs = input.Proofs
            .Where(p => findingIds.Contains(p.FindingId))
            .Select(p => MapProof(p, SessionRunId))
            .Cast<object>()
            .ToList();

        var verdicts = BuildVerdicts(input, findingIds, compact, now);
        var (runs, sessionRunId) = BuildRuns(input, now);
        var assessments = input.ImportedAssessments?.Cast<object>().ToList() ?? [];
        var artifacts = BuildArtifacts(input, sessionRunId);

        Dictionary<string, object?>? target = input.ImportTarget != null
            ? new Dictionary<string, object?>(input.ImportTarget, StringComparer.OrdinalIgnoreCase)
            : null;
        if (target == null && !string.IsNullOrWhiteSpace(input.BaseUrl) && Uri.TryCreate(input.BaseUrl, UriKind.Absolute, out var uri))
        {
            target = new Dictionary<string, object?>
            {
                ["baseUrl"] = $"{uri.Scheme}://{uri.Authority}",
                ["environment"] = "browser-session"
            };
        }
        else if (target != null && !target.ContainsKey("baseUrl") && !string.IsNullOrWhiteSpace(input.BaseUrl) &&
                 Uri.TryCreate(input.BaseUrl, UriKind.Absolute, out var uri2))
        {
            target["baseUrl"] = $"{uri2.Scheme}://{uri2.Authority}";
        }

        return new Dictionary<string, object?>
        {
            ["vpxVersion"] = "1.1",
            ["documentId"] = input.DocumentId ?? Guid.NewGuid().ToString(),
            ["createdAt"] = now.ToString("o"),
            ["updatedAt"] = now.ToString("o"),
            ["profile"] = input.Profile,
            ["target"] = target,
            ["runs"] = runs,
            ["surfaces"] = surfaces,
            ["findings"] = findings,
            ["assessments"] = assessments,
            ["proofs"] = proofs,
            ["artifacts"] = artifacts,
            ["verdicts"] = verdicts
        };
    }

    private static List<object> BuildVerdicts(
        ExportInput input,
        HashSet<string> findingIds,
        bool compact,
        DateTime now)
    {
        var byFinding = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);

        if (input.Verdicts != null)
        {
            foreach (var v in input.Verdicts.Where(v => findingIds.Contains(v.FindingId)))
                byFinding[v.FindingId] = MapImportedVerdict(v);
        }

        foreach (var group in input.Proofs.Where(p => findingIds.Contains(p.FindingId))
                     .GroupBy(p => p.FindingId, StringComparer.OrdinalIgnoreCase))
        {
            var fid = group.Key;
            if (byFinding.ContainsKey(fid)) continue;
            byFinding[fid] = MapVerdict(group.OrderByDescending(x => x.ExecutedAtUtc).First(), compact);
        }

        if (!compact)
        {
            foreach (var fid in findingIds)
            {
                if (byFinding.ContainsKey(fid)) continue;
            byFinding[fid] = new Dictionary<string, object?>
            {
                ["id"] = $"verdict-{fid}",
                ["findingId"] = fid,
                ["runId"] = SessionRunId,
                ["exploitability"] = "hypothesis",
                ["updatedAt"] = now.ToString("o")
            };
            }
        }

        return byFinding.Values.Cast<object>().ToList();
    }

    private static Dictionary<string, object?> MapImportedVerdict(VpxVerdictRecord v)
    {
        var dict = new Dictionary<string, object?>
        {
            ["id"] = string.IsNullOrWhiteSpace(v.Id) ? $"verdict-{v.FindingId}" : v.Id,
            ["findingId"] = v.FindingId,
            ["exploitability"] = v.Exploitability
        };
        if (v.RunId != null) dict["runId"] = v.RunId;
        var basedOnProofs = v.BasedOnProofIds?.ToList() ?? [];
        if (basedOnProofs.Count == 0 && v.ProofId != null) basedOnProofs.Add(v.ProofId);
        if (basedOnProofs.Count > 0) dict["basedOnProofIds"] = basedOnProofs;
        if (v.ProofId != null) dict["proofId"] = v.ProofId;
        if (v.BasedOnAssessmentIds is { Count: > 0 }) dict["basedOnAssessmentIds"] = v.BasedOnAssessmentIds;
        if (v.SupersedesVerdictId != null) dict["supersedesVerdictId"] = v.SupersedesVerdictId;
        if (v.UpdatedAtUtc != null) dict["updatedAt"] = v.UpdatedAtUtc.Value.ToString("o");
        if (v.Disposition != null) dict["disposition"] = v.Disposition;
        if (v.Justification != null) dict["justification"] = v.Justification;
        if (v.EffectiveSeverity != null) dict["effectiveSeverity"] = v.EffectiveSeverity;
        if (v.Confidence != null) dict["confidence"] = v.Confidence;
        if (v.RerunToken != null) dict["rerunToken"] = v.RerunToken;
        if (v.Remediation != null) dict["remediation"] = v.Remediation;
        return dict;
    }

    private static (List<object> Surfaces, Dictionary<string, string> IdsByEndpointKey) BuildSurfaces(
        IReadOnlyList<ChainableFinding> findings,
        IReadOnlyDictionary<string, Dictionary<string, object?>>? importedSurfaces)
    {
        var byKey = new Dictionary<string, (string route, string method, HashSet<string> paramNames)>(StringComparer.OrdinalIgnoreCase);

        foreach (var f in findings)
        {
            if (string.IsNullOrWhiteSpace(f.Endpoint))
                continue;

            var route = NormalizeRoute(f.Endpoint);
            var method = string.IsNullOrWhiteSpace(f.Method) ? "GET" : f.Method.ToUpperInvariant();
            var key = SurfaceEndpointKey(method, route);

            if (!byKey.TryGetValue(key, out var entry))
            {
                entry = (route, method, []);
                byKey[key] = entry;
            }

            if (!string.IsNullOrWhiteSpace(f.Parameter))
                entry.paramNames.Add(f.Parameter);
        }

        var usedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var idsByEndpointKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<object>(byKey.Count);

        foreach (var (key, e) in byKey)
        {
            var id = AllocateUniqueSurfaceId(e.method, e.route, usedIds);
            idsByEndpointKey[key] = id;

            var surface = new Dictionary<string, object?>
            {
                ["id"] = id,
                ["route"] = e.route,
                ["method"] = e.method
            };
            if (e.paramNames.Count > 0)
            {
                surface["params"] = e.paramNames.OrderBy(p => p)
                    .Select(p => new Dictionary<string, object?> { ["name"] = p, ["in"] = "query", ["type"] = "string" })
                    .ToList();
            }

            if (importedSurfaces != null)
            {
                if (importedSurfaces.TryGetValue(id, out var imported))
                    MergeSurfaceMetadata(surface, imported);
                else
                {
                    foreach (var imp in importedSurfaces.Values)
                    {
                        if (imp.TryGetValue("route", out var r) && imp.TryGetValue("method", out var m) &&
                            string.Equals(r?.ToString(), e.route, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(m?.ToString(), e.method, StringComparison.OrdinalIgnoreCase))
                        {
                            MergeSurfaceMetadata(surface, imp);
                            break;
                        }
                    }
                }
            }

            list.Add(surface);
        }

        if (importedSurfaces == null)
            return (list, idsByEndpointKey);

        foreach (var (id, imported) in importedSurfaces)
        {
            if (!usedIds.Add(id)) continue;
            var copy = new Dictionary<string, object?>(imported, StringComparer.OrdinalIgnoreCase);
            if (!copy.ContainsKey("id")) copy["id"] = id;
            list.Add(copy);
        }

        return (list, idsByEndpointKey);
    }

    private static void MergeSurfaceMetadata(Dictionary<string, object?> target, Dictionary<string, object?> imported)
    {
        foreach (var key in new[] { "discoveredFrom", "routeConfidence", "auth", "params" })
        {
            if (imported.TryGetValue(key, out var val) && val != null)
                target[key] = val;
        }
    }

    /// <summary>
    /// One VPX row per (kind, endpoint, param) — payload variants merge into detail/evidence for LLM triage.
    /// </summary>
    private static List<ChainableFinding> CollapseExportFindings(IReadOnlyList<ChainableFinding> findings)
    {
        if (findings.Count <= 1) return findings.ToList();

        var groups = new Dictionary<string, ChainableFinding>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();

        foreach (var f in findings)
        {
            var kind = MapKind(f.Category);
            var endpoint = SecurityHostScope.LogicalEndpointKey(f.Method ?? "GET", f.Endpoint ?? "");
            var param = ChainFindingDedup.ExtractParameter(f.Title, f.Detail, f.Evidence) ?? "";
            var key = $"{kind}|{endpoint}|{param}".ToLowerInvariant();

            if (!groups.TryGetValue(key, out var existing))
            {
                groups[key] = f;
                order.Add(key);
                continue;
            }

            var mergedDetail = MergeText(existing.Detail, f.Detail);
            var mergedEvidence = MergeText(existing.Evidence, f.Evidence);
            if (SeverityRank(f.Severity) > SeverityRank(existing.Severity))
            {
                groups[key] = CloneFinding(f, mergedDetail, mergedEvidence);
            }
            else
            {
                groups[key] = CloneFinding(existing, mergedDetail, mergedEvidence);
            }
        }

        return order.Select(k => groups[k]).ToList();
    }

    private static ChainableFinding CloneFinding(ChainableFinding f, string? detail, string? evidence) => new()
    {
        Id = f.Id,
        Source = f.Source,
        Category = f.Category,
        Severity = f.Severity,
        Title = f.Title,
        Endpoint = f.Endpoint,
        Method = f.Method,
        Parameter = f.Parameter ?? ChainFindingDedup.ExtractParameter(f.Title, f.Detail, f.Evidence),
        Detail = detail,
        Evidence = evidence,
        Remediation = f.Remediation,
        Reference = f.Reference,
        Tags = f.Tags.Count > 0 ? [.. f.Tags] : []
    };

    private static string? MergeText(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(b)) return a;
        if (string.IsNullOrWhiteSpace(a)) return b;
        if (a.Contains(b, StringComparison.Ordinal)) return a;
        var merged = $"{a}; {b}";
        return merged.Length > 1200 ? merged[..1200] + "…" : merged;
    }

    private static int SeverityRank(string severity) => (severity ?? "").Trim().ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private static Dictionary<string, object?> MapFinding(
        ChainableFinding f,
        bool compact,
        Dictionary<string, object?>? target,
        Dictionary<string, Dictionary<string, object?>> surfaceById,
        Dictionary<string, string> surfaceIdsByKey)
    {
        string? surfaceId = null;
        if (!string.IsNullOrWhiteSpace(f.Endpoint))
        {
            var method = string.IsNullOrWhiteSpace(f.Method) ? "GET" : f.Method.ToUpperInvariant();
            var route = NormalizeRoute(f.Endpoint);
            var key = SurfaceEndpointKey(method, route);
            surfaceId = surfaceIdsByKey.TryGetValue(key, out var assigned)
                ? assigned
                : SlugSurfaceId(method, route);
        }

        var kind = MapKind(f.Category);
        var (owasp, cwes) = MapOwaspCwe(f.Category, kind);
        var normalizedSeverity = NormalizeSeverity(f.Severity);

        var finding = new Dictionary<string, object?>
        {
            ["id"] = NormalizeFindingId(f.Id),
            ["kind"] = kind,
            ["owasp"] = owasp,
            ["cwe"] = cwes,
            ["severity"] = CapReportingSeverity(kind, f.Category, normalizedSeverity, out var claimedSeverity),
            ["title"] = TextEncodingFix.FixMojibake(f.Title),
            ["description"] = TextEncodingFix.FixMojibake(f.Detail),
            ["remediation"] = f.Remediation,
            ["status"] = "hypothesis",
            ["surfaceId"] = surfaceId,
            ["url"] = string.IsNullOrWhiteSpace(f.Endpoint) ? null : f.Endpoint,
            ["method"] = string.IsNullOrWhiteSpace(f.Method) ? null : f.Method.ToUpperInvariant(),
            ["param"] = f.Parameter,
            ["origin"] = new Dictionary<string, object?>
            {
                ["tool"] = $"trowser-{f.Source}",
                ["rule"] = f.Category
            },
            ["proofHints"] = compact
                ? new Dictionary<string, object?> { ["category"] = f.Category, ["oracle"] = DefaultOracle(f.Category) }
                : new Dictionary<string, object?>
                {
                    ["category"] = f.Category,
                    ["oracle"] = DefaultOracle(f.Category),
                    ["identity"] = "browser-session"
                },
            ["proofPriority"] = PriorityFromSeverity(f.Severity),
            ["reportedByRunIds"] = new List<string> { SessionRunId }
        };

        if (!string.IsNullOrWhiteSpace(surfaceId) &&
            surfaceById.TryGetValue(surfaceId, out var surface))
        {
            var route = surface.TryGetValue("route", out var r) ? r?.ToString() : null;
            var method = surface.TryGetValue("method", out var m) ? m?.ToString() : f.Method;
            finding["fingerprint"] = VpxFingerprint.Compute(new VpxFingerprint.Input
            {
                Repository = TargetString(target, "repository"),
                Kind = kind,
                Route = route ?? f.Endpoint,
                Method = method,
                Param = f.Parameter
            });
        }
        else if (!string.IsNullOrWhiteSpace(f.Endpoint) || !string.IsNullOrWhiteSpace(kind))
        {
            finding["fingerprint"] = VpxFingerprint.Compute(new VpxFingerprint.Input
            {
                Repository = TargetString(target, "repository"),
                Kind = kind,
                Route = f.Endpoint,
                Method = f.Method,
                Param = f.Parameter
            });
        }

        if (claimedSeverity != null)
            finding["claimedSeverity"] = claimedSeverity;

        if (!string.IsNullOrWhiteSpace(f.Reference))
            finding["reference"] = f.Reference;

        if (!compact)
        {
            var trace = new List<string>();
            if (!string.IsNullOrWhiteSpace(f.Detail)) trace.Add(f.Detail);
            if (!string.IsNullOrWhiteSpace(f.Evidence)) trace.Add(f.Evidence);
            if (trace.Count > 0) finding["trace"] = trace;
        }

        return finding;
    }

    /// <summary>
    /// Cap severities that are indications/hypotheses in VPX export (XSS without proof, cache-map, etc.).
    /// </summary>
    private static string CapReportingSeverity(string kind, string category, string severity, out string? claimedSeverity)
    {
        claimedSeverity = null;

        if (IsCacheIndicationKind(kind, category))
        {
            if (severity is "high" or "critical" or "medium")
            {
                claimedSeverity = severity;
                return severity switch
                {
                    "critical" or "high" => "info",
                    _ => "low"
                };
            }

            return severity;
        }

        return CapUnverifiedInjectionSeverity(kind, severity, out claimedSeverity);
    }

    private static bool IsCacheIndicationKind(string kind, string category) =>
        kind.Equals("cache-map", StringComparison.OrdinalIgnoreCase)
        || kind.Equals("cache-poison", StringComparison.OrdinalIgnoreCase)
        || category.Equals("cache-map", StringComparison.OrdinalIgnoreCase)
        || category.Equals("cache-poison", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Unverified XSS findings must not present as critical/high in VPX without sink+effect /
    /// HTML document proof — emit medium and keep claimedSeverity for triage.
    /// Other injection classes keep their scanner severity (error-based SQLi / RCE output are oracles).
    /// </summary>
    private static string CapUnverifiedInjectionSeverity(string kind, string severity, out string? claimedSeverity)
    {
        claimedSeverity = null;
        var isXss = kind.Contains("xss", StringComparison.OrdinalIgnoreCase)
                    || kind.Equals("dom", StringComparison.OrdinalIgnoreCase);

        if (!isXss) return severity;

        if (severity is "critical" or "high")
        {
            claimedSeverity = severity;
            return "medium";
        }

        return severity;
    }

    /// <summary>
    /// Maps finding categories to TrowserTwelve OWASP IDs and CWE entries.
    /// Uses Trowser's own taxonomy (A01-A14), not OWASP 2021 numbering.
    /// Key differences from OWASP 2021: A02=Misconfiguration, A03=Supply Chain,
    /// A04=Crypto, A05=Injection, A06=Insecure Design, A11=SSRF, A12=Availability, A13=AI/LLM.
    /// </summary>
    private static (string owasp, List<string> cwes) MapOwaspCwe(string category, string kind)
    {
        return category switch
        {
            // A01 Access Control
            "idor" or "bfla" or "bola" => ("A01", ["CWE-639"]),
            "csrf" => ("A01", ["CWE-352"]),
            "mass-assignment" => ("A01", ["CWE-915"]),

            // A02 Misconfiguration
            "missing-csp" or "missing-hsts" or "missing-xframe"
                or "missing-referrer-policy" or "missing-permissions-policy"
                or "missing-content-type-options" or "weak-headers"
                => ("A02", ["CWE-693"]),
            "missing-httponly" or "missing-secure-flag" or "missing-samesite"
                or "weak-cookies"
                => ("A02", ["CWE-614"]),
            "cors-misconfig" => ("A02", ["CWE-942"]),
            "subdomain-takeover" => ("A02", ["CWE-200", "CWE-404"]),
            "source-maps" => ("A02", ["CWE-200"]),
            "hidden-url-in-comment" => ("A02", ["CWE-200"]),
            "dangerous-methods" => ("A02", ["CWE-749"]),
            "smuggling-indicator" or "ambiguous-framing" => ("A02", ["CWE-444"]),
            "info-leak" => ("A02", ["CWE-200"]),
            "forced-error" => ("A02", ["CWE-209"]),
            "jwt-insecure-config" or "jwt-weak-secret" or "jwt-sensitive-data" or "jwt-expired"
                => ("A02", ["CWE-327"]),
            "weak-jwt-algorithm" => ("A02", ["CWE-327"]),

            // A03 Supply Chain
            "missing-sri" => ("A03", ["CWE-353"]),
            "vulnerable-library" or "cve-library" => ("A03", ["CWE-1035"]),
            "ci-cd-exposure" => ("A03", ["CWE-200"]),

            // A04 Crypto & Secrets
            "weak-crypto" or "weak-tls" => ("A04", ["CWE-326"]),
            "jwt-none" or "jwt-weak" => ("A04", ["CWE-327"]),
            "jwt-header-abuse" => ("A04", ["CWE-347"]),
            "weak-token-entropy" => ("A04", ["CWE-330"]),
            "credential-exposure" or "token-in-storage" or "sensitive-storage"
                => ("A04", ["CWE-798", "CWE-312"]),
            "jwt-token" or "jwt-sensitive-claim" or "md5-password-hash-in-jwt"
                or "api-key" or "bearer-token" or "password" or "aws-access-key"
                or "private-key" or "connection-string" or "secret-assignment"
                or "email-password-combo" or "hardcoded-credential" or "api-key-in-request"
                or "plaintext-password-in-transit" or "credit-card"
                or "comment-secret-signal" or "base64-decoded-url-or-secret"
                => ("A04", ["CWE-798", "CWE-312"]),

            // A05 Injection
            "sqli" or "sqli-indicator" or "sqli-login-bypass" => ("A05", ["CWE-89"]),
            "xss" or "csti" => ("A05", ["CWE-79"]),
            "ssti" or "ssti-confirmed" or "ssti-polyglot" or "ssti-stored" => ("A05", ["CWE-1336"]),
            "command-injection" or "rce-indicator" or "cmd-injection" => ("A05", ["CWE-78"]),
            "nosql" or "nosql-injection" => ("A05", ["CWE-943"]),
            "ldap" or "ldap-injection" => ("A05", ["CWE-90"]),
            "path-traversal" => ("A05", ["CWE-22"]),
            "open-redirect" => ("A05", ["CWE-601"]),
            "websocket-injection" => ("A05", ["CWE-79"]),
            "xxe" or "xxe-upload" => ("A05", ["CWE-611"]),
            "prototype-pollution" => ("A05", ["CWE-1321"]),
            "insecure-deserialization" or "deserialization-suspected"
                or "rce-deserialization" or "deserialization-dos" or "nextjs-rsc-rce"
                => ("A05", ["CWE-502"]),
            "parser-differential" or "content-type-confusion" => ("A05", ["CWE-436"]),
            "file-upload-bypass" or "file-upload-oversize" or "file-upload-wrong-type"
                or "file-upload-polyglot" or "file-upload-spa-shell"
                => ("A05", ["CWE-434"]),

            // A06 Insecure Design
            "race-condition" => ("A06", ["CWE-362"]),
            "captcha-bypass" or "broken-anti-automation" => ("A06", ["CWE-804"]),
            "workflow-skip" => ("A06", ["CWE-841"]),
            "fail-open" or "fail-open-unauthenticated" or "fail-open-invalid-token"
                => ("A06", ["CWE-636"]),
            "missing-parameter-crash" => ("A06", ["CWE-234"]),

            // A07 Authentication
            "weak-auth" or "sqli-login" or "default-credentials"
                => ("A07", ["CWE-287"]),
            "session-fixation" => ("A07", ["CWE-384"]),
            "weak-password-reset" or "password-reset-weak" => ("A07", ["CWE-640"]),
            "account-enumeration" => ("A07", ["CWE-204"]),
            "logout-invalidation" => ("A07", ["CWE-613"]),
            "cookie-prefix-bypass" => ("A07", ["CWE-565"]),
            "auth-bypass-header-spoof" => ("A07", ["CWE-290"]),
            "oidc-dangerous-grant" or "oidc-weak-pkce" or "oidc-weak-signing"
                or "oidc-open-registration" or "oidc-exposed-scopes" or "oidc-misconfiguration"
                => ("A07", ["CWE-287"]),

            // A09 Operational Security
            "stack-trace-leak" or "verbose-error" or "debug-console-leak" => ("A09", ["CWE-209"]),
            "console-stack-trace" or "server-error-response" => ("A09", ["CWE-209"]),
            "source-maps-debug" or "info-leak-headers" => ("A09", ["CWE-200"]),

            // A11 SSRF
            "ssrf" => ("A11", ["CWE-918"]),

            // A12 Availability
            "missing-rate-limit" or "weak-rate-limit" or "rate-limit-present"
                => ("A12", ["CWE-770"]),
            "body-size-unbounded" => ("A12", ["CWE-770"]),
            "redos-suspected" => ("A12", ["CWE-1333"]),
            "graphql-batching" or "graphql-depth-unlimited"
                or "graphql-amplification" or "graphql-introspection"
                or "graphql-no-limit" or "graphql-field-suggestion"
                or "graphql-misconfiguration"
                => ("A12", ["CWE-400"]),

            // A13 AI & LLM
            "prompt-injection" or "indirect-prompt-injection"
                => ("A13", ["CWE-77"]),
            "jailbreak" => ("A13", ["CWE-693"]),
            "data-exfiltration" or "sensitive-disclosure"
                => ("A13", ["CWE-200"]),
            "excessive-agency" or "web-mcp-abuse"
                => ("A13", ["CWE-284"]),
            "hallucination" => ("A13", ["CWE-697"]),
            "llm-dos" => ("A13", ["CWE-400"]),
            "model-theft" => ("A13", ["CWE-285"]),
            "insecure-llm-output" => ("A13", ["CWE-79"]),

            // A14 Other
            "http-smuggling" => ("A14", ["CWE-444"]),
            "host-header-injection" => ("A14", ["CWE-644"]),
            "cache-deception" or "web-cache-deception" => ("A14", ["CWE-525"]),
            "cache-poison" or "cache-map" => ("A14", ["CWE-525", "CWE-349"]),

            _ => kind switch
            {
                "misconfiguration" => ("A02", ["CWE-16"]),
                "sqli" => ("A05", ["CWE-89"]),
                "xss" => ("A05", ["CWE-79"]),
                "command-injection" => ("A05", ["CWE-78"]),
                "deserialization" => ("A05", ["CWE-502"]),
                "info-leak" => ("A02", ["CWE-200"]),
                _ => ("A02", ["CWE-16"])
            }
        };
    }

    private static string? TargetString(Dictionary<string, object?>? target, string key)
    {
        if (target == null) return null;
        return target.TryGetValue(key, out var v) ? v?.ToString() : null;
    }

    private static (List<object> Runs, string SessionRunId) BuildRuns(ExportInput input, DateTime now)
    {
        var runs = new List<object>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (input.ImportedRuns != null)
        {
            foreach (var run in input.ImportedRuns)
            {
                runs.Add(run);
                if (run.TryGetValue("id", out var idObj) && idObj is string id)
                    seen.Add(id);
            }
        }

        if (!seen.Contains(SessionRunId))
        {
            runs.Add(new Dictionary<string, object?>
            {
                ["id"] = SessionRunId,
                ["stage"] = "proof",
                ["actor"] = new Dictionary<string, object?>
                {
                    ["type"] = "tool",
                    ["name"] = "trowser",
                    ["version"] = TrowserVersion
                },
                ["startedAt"] = now.ToString("o"),
                ["completedAt"] = now.ToString("o")
            });
        }

        return (runs, SessionRunId);
    }

    private static List<object> BuildArtifacts(ExportInput input, string sessionRunId)
    {
        var list = new List<object>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (input.ImportedArtifacts != null)
        {
            foreach (var art in input.ImportedArtifacts)
            {
                list.Add(art);
                if (art.TryGetValue("id", out var idObj) && idObj is string id)
                    seen.Add(id);
            }
        }

        foreach (var p in input.Proofs)
        {
            if (string.IsNullOrWhiteSpace(p.EvidenceBundlePath)) continue;
            var artifactId = $"artifact-{p.Id}";
            if (!seen.Add(artifactId)) continue;
            list.Add(new Dictionary<string, object?>
            {
                ["id"] = artifactId,
                ["kind"] = "workflow",
                ["uri"] = p.EvidenceBundlePath,
                ["producedByRunId"] = p.RunId ?? sessionRunId
            });
        }

        return list;
    }

    private static Dictionary<string, object?> MapProof(VpxProofRecord p, string sessionRunId)
    {
        var proof = new Dictionary<string, object?>
        {
            ["id"] = p.Id,
            ["findingId"] = p.FindingId,
            ["runId"] = string.IsNullOrWhiteSpace(p.RunId) ? sessionRunId : p.RunId,
            ["executedAt"] = p.ExecutedAtUtc.ToString("o"),
            ["outcome"] = ResolveOutcome(p),
            ["tool"] = new Dictionary<string, object?> { ["name"] = "trowser", ["version"] = TrowserVersion },
            ["workflow"] = new Dictionary<string, object?>
            {
                ["type"] = p.WorkflowType,
                ["templateId"] = p.TemplateId,
                ["path"] = p.EvidenceBundlePath != null ? $"{p.EvidenceBundlePath}/workflow.json" : null
            },
            ["oracle"] = MapOracle(p),
            ["elapsedMs"] = p.ElapsedMs
        };

        if (p.SurfaceId != null || p.Param != null || p.Payload != null)
        {
            proof["injection"] = new Dictionary<string, object?>
            {
                ["surfaceId"] = p.SurfaceId,
                ["param"] = p.Param,
                ["payload"] = p.Payload
            };
        }

        if (p.EvidenceBundlePath != null)
            proof["evidenceBundle"] = p.EvidenceBundlePath;

        if (p.Limitations is { Count: > 0 })
            proof["limitations"] = p.Limitations;

        var artifactIds = p.ArtifactIds?.ToList() ?? [];
        if (p.EvidenceBundlePath != null)
        {
            var artifactId = $"artifact-{p.Id}";
            if (!artifactIds.Contains(artifactId, StringComparer.OrdinalIgnoreCase))
                artifactIds.Add(artifactId);
        }
        if (artifactIds.Count > 0)
            proof["artifactIds"] = artifactIds;

        return proof;
    }

    private static string ResolveOutcome(VpxProofRecord p)
    {
        if (!string.IsNullOrWhiteSpace(p.Outcome))
            return p.Outcome;
        return p.OraclePassed ? "exploited" : "not-reproduced";
    }

    private static Dictionary<string, object?> MapOracle(VpxProofRecord p)
    {
        var observed = p.OracleObserved ?? p.OraclePassed;
        var actual = p.OracleEvidence switch
        {
            string s => s,
            null => null,
            _ => JsonSerializer.Serialize(p.OracleEvidence)
        };
        var oracle = new Dictionary<string, object?>
        {
            ["type"] = string.IsNullOrWhiteSpace(p.OracleType) ? "none" : p.OracleType,
            ["observed"] = observed
        };
        if (actual != null)
            oracle["actualSignal"] = actual;
        return oracle;
    }

    private static Dictionary<string, object?> MapVerdict(VpxProofRecord p, bool compact)
    {
        var exploited = ResolveOutcome(p) == "exploited";
        var verdict = new Dictionary<string, object?>
        {
            ["id"] = $"verdict-{p.FindingId}",
            ["findingId"] = p.FindingId,
            ["runId"] = SessionRunId,
            ["basedOnProofIds"] = new List<string> { p.Id },
            ["proofId"] = p.Id,
            ["updatedAt"] = p.ExecutedAtUtc.ToString("o"),
            ["exploitability"] = exploited ? "confirmed" : "not_reproduced",
            ["disposition"] = exploited ? "fix-now" : "monitor",
            ["justification"] = exploited
                ? $"Oracle '{p.OracleType}' observed the expected harmful-effect signal during browser proof."
                : $"Proof attempt with oracle '{p.OracleType}' did not demonstrate the effect. Failure to reproduce is not proof that exploitation is impossible."
        };

        if (p.EvidenceBundlePath != null)
            verdict["rerunToken"] = $"{p.EvidenceBundlePath}/manifest.json";

        if (!compact && exploited)
        {
            verdict["effectiveSeverity"] = "high";
            verdict["confidence"] = 0.85;
        }

        return verdict;
    }

    public static string NormalizeFindingId(string id)
    {
        if (id.StartsWith("vpx-", StringComparison.OrdinalIgnoreCase))
            return id;
        return $"vpx-{id.Replace('/', '-').Replace(' ', '-')}";
    }

    public static string SlugSurfaceId(string method, string route)
    {
        var slug = route.Trim('/').Replace('/', '-').Replace('{', '-').Replace('}', '-');
        while (slug.Contains("--", StringComparison.Ordinal))
            slug = slug.Replace("--", "-", StringComparison.Ordinal);
        slug = slug.Trim('-');
        if (string.IsNullOrEmpty(slug)) slug = "root";
        return $"surf-{method.ToLowerInvariant()}-{slug}";
    }

    internal static string NormalizeRoute(string endpoint)
    {
        var route = VpxFingerprint.NormalizeRoute(endpoint);
        if (string.IsNullOrEmpty(route))
            return "/";
        return route[0] == '/' ? route : "/" + route;
    }

    private static string SurfaceEndpointKey(string method, string route) => $"{method}|{route}";

    private static string AllocateUniqueSurfaceId(string method, string route, HashSet<string> usedIds)
    {
        var id = SlugSurfaceId(method, route);
        if (usedIds.Add(id))
            return id;

        for (var n = 2; ; n++)
        {
            var candidate = $"{id}-{n}";
            if (usedIds.Add(candidate))
                return candidate;
        }
    }

    private static string MapKind(string category) => category switch
    {
        "sqli" or "sqli-indicator" => "sqli",
        "missing-csp" or "missing-hsts" or "missing-xframe" or "missing-referrer-policy"
            or "missing-permissions-policy" or "weak-headers" or "missing-httponly"
            or "missing-secure-flag" or "missing-samesite" or "weak-cookies" => "misconfiguration",
        "token-in-storage" or "sensitive-storage" => "info-leak",
        "ssti-confirmed" => "ssti",
        "rce-indicator" or "command-injection" => "command-injection",
        "deserialization-suspected" or "parser-differential" or "content-type-confusion" => "deserialization",
        "cache-map" or "cache-poison" => "cache-map",
        "xs-leaks" or "xs-leaks+cors" => "xs-leak",
        _ => category
    };

    private static string NormalizeSeverity(string severity) =>
        severity.ToLowerInvariant() switch
        {
            "critical" or "high" or "medium" or "low" or "info" => severity.ToLowerInvariant(),
            _ => "medium"
        };

    private static int PriorityFromSeverity(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 95,
        "high" => 80,
        "medium" => 60,
        "low" => 40,
        _ => 20
    };

    private static string DefaultOracle(string category) => category switch
    {
        "sqli" or "sqli-indicator" => "error-or-timing",
        "xss" => "reflection",
        "csrf" => "status-code",
        "idor" => "status-code",
        "ssrf" => "network-match",
        "open-redirect" => "status-code",
        "path-traversal" => "status-code",
        _ => "network-match"
    };

    public static string ResolveFindingId(
        System.Text.Json.JsonElement workflowBody,
        IReadOnlyList<ChainableFinding> findings,
        string fallbackPrefix)
    {
        if (workflowBody.TryGetProperty("vpxFindingId", out var fidEl))
        {
            var fid = fidEl.GetString();
            if (!string.IsNullOrWhiteSpace(fid))
                return NormalizeFindingId(fid);
        }

        if (workflowBody.TryGetProperty("markers", out var markers) && markers.ValueKind == JsonValueKind.Object)
        {
            foreach (var name in new[] { "endpoint", "url", "targetUrl" })
            {
                if (!markers.TryGetProperty(name, out var epEl)) continue;
                var ep = epEl.GetString();
                if (string.IsNullOrWhiteSpace(ep)) continue;
                var match = findings.FirstOrDefault(f =>
                    !string.IsNullOrWhiteSpace(f.Endpoint) &&
                    f.Endpoint.Contains(ep, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                    return NormalizeFindingId(match.Id);
            }
        }

        var best = findings.FirstOrDefault();
        if (best != null)
            return NormalizeFindingId(best.Id);

        return NormalizeFindingId($"{fallbackPrefix}-{Guid.NewGuid():N}"[..16]);
    }

    public static void RecordSessionProof(
        AutomationContext context,
        JsonElement workflowBody,
        Workflow.WorkflowVerifyResult result,
        string workflowType = "verify-workflow",
        string? templateId = null)
    {
        var findings = ChainAnalysisService.CollectFindings(context);
        context.AddVpxProof(RecordFromWorkflow(workflowBody, result, findings, workflowType, templateId));
    }

    public static void RecordSessionProofFromChain(
        AutomationContext context,
        JsonElement workflowHint,
        ChainProofResult chainResult,
        string patternId)
    {
        var workflowResult = new Workflow.WorkflowVerifyResult
        {
            WorkflowId = chainResult.WorkflowId,
            Verified = chainResult.Proven,
            OraclePassed = chainResult.Proven,
            Oracle = new Workflow.OracleCheckResult
            {
                Type = chainResult.OracleType ?? "chain",
                Passed = chainResult.Proven,
                Evidence = chainResult.OracleEvidence,
                Error = chainResult.FailureReason
            },
            EvidenceBundlePath = chainResult.EvidenceBundlePath,
            ElapsedMs = chainResult.ElapsedMs
        };
        RecordSessionProof(context, workflowHint, workflowResult, "chain-prove", patternId);
    }

    public static VpxProofRecord RecordFromWorkflow(
        System.Text.Json.JsonElement workflowBody,
        Workflow.WorkflowVerifyResult result,
        IReadOnlyList<ChainableFinding> findings,
        string workflowType = "verify-workflow",
        string? templateId = null)
    {
        var findingId = ResolveFindingId(workflowBody, findings, "proof");
        string? surfaceId = null;
        string? param = null;

        var match = findings.FirstOrDefault(f => NormalizeFindingId(f.Id) == findingId);
        if (match != null && !string.IsNullOrWhiteSpace(match.Endpoint))
        {
            surfaceId = SlugSurfaceId(
                string.IsNullOrWhiteSpace(match.Method) ? "GET" : match.Method.ToUpperInvariant(),
                NormalizeRoute(match.Endpoint));
            param = match.Parameter;
        }

        return new VpxProofRecord
        {
            Id = $"proof-{result.WorkflowId ?? Guid.NewGuid().ToString("N")[..8]}",
            FindingId = findingId,
            ExecutedAtUtc = DateTime.UtcNow,
            WorkflowType = workflowType,
            TemplateId = templateId,
            WorkflowId = result.WorkflowId,
            RunId = SessionRunId,
            OraclePassed = result.OraclePassed,
            Outcome = result.OraclePassed ? "exploited" : "not-reproduced",
            OracleObserved = result.OraclePassed,
            OracleType = result.Oracle?.Type ?? "none",
            OracleEvidence = result.Oracle?.Evidence,
            EvidenceBundlePath = result.EvidenceBundlePath,
            SurfaceId = surfaceId,
            Param = param,
            ElapsedMs = result.ElapsedMs
        };
    }
}
