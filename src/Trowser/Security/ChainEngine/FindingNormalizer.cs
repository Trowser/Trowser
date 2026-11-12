using Trowser.Automation;
using Trowser.SessionLog;

namespace Trowser.Security.ChainEngine;

/// <summary>
/// Normalizes findings from all sources (shadow, auto-scan, journal, manual)
/// into <see cref="ChainableFinding"/> instances for chain analysis.
/// </summary>
public static class FindingNormalizer
{
    /// <summary>
    /// All normalized finding categories accepted by chain analysis and manual chain-findings.
    /// Includes parser/cmd probe categories used by scanners and manual chain findings.
    /// </summary>
    public static readonly IReadOnlySet<string> KnownCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // XSS / injection
        "xss", "sqli", "sqli-indicator", "nosql-injection", "ldap-injection", "csrf", "idor", "ssrf", "open-redirect",
        "path-traversal", "path-filter-bypass", "mass-assignment", "header-injection",
        // Parser / RCE probes (pre-registered for manual findings and future scanners)
        "content-type-confusion", "deserialization-suspected", "parser-differential",
        "rce-deserialization", "deserialization-dos",
        "file-upload-oversize", "file-upload-wrong-type", "file-upload-polyglot", "file-upload-spa-shell",
        "xxe-upload",
        "command-injection", "ssti-confirmed", "ssti-suspected", "ssti-polyglot", "ssti-stored", "csti-confirmed", "rce-indicator",
        "prototype-pollution",
        // Auth / session
        "weak-auth", "auth-bypass-pivot", "auth-bypass-header-spoof", "jwt-acceptance", "jwt-alg-variant", "jwt-header-abuse",
        "cookie-prefix-bypass", "weak-saml-signature", "weak-tls", "expiring-cert", "rest-scaffold-unauth",
        "session-fixation", "missing-httponly", "missing-secure-flag",
        "password-reset-weak", "account-enumeration", "logout-invalidation", "oauth-flow-weakness",
        "missing-samesite", "credential-exposure", "token-in-storage",
        "plaintext-password-in-transit", "weak-reset-token",
        // Headers / policy
        "missing-csp", "missing-hsts", "missing-xframe", "missing-referrer-policy", "http-downgrade-proven",
        "duplicate-fetch",
        "missing-permissions-policy", "weak-headers", "weak-cookies", "cors-misconfig",
        // Info / recon
        "info-leak", "verbose-error", "default-credentials", "source-maps", "server-disclosure", "mixed-content",
        "nuclei-match",
        "sensitive-storage", "captcha-leak", "timing-oracle", "missing-rate-limit",
        "weak-rate-limit", "rate-limit-present", "redos-suspected",
        "body-size-unbounded", "body-size-limit-present", "body-size-no-413",
        "costly-large-response", "costly-missing-pagination", "costly-unbounded-page", "costly-page-size-honored",
        "costly-heavy-route", "costly-slow-sync", "costly-bulk-input", "costly-expansion",
        "costly-image-dimensions", "costly-upload-surface", "costly-n-plus-one",
        "costly-long-lived-stream", "costly-compose-graphql", "costly-compose-llm",
        "costly-compose-ssrf-fetch", "costly-compose-redos", "costly-spec-unbounded",
        "costly-nested-payload", "costly-recipient-fanout", "costly-date-range", "costly-filter-depth",
        "costly-spec-graphql",
        "swaggering-server-error", "swaggering-verbose-error", "swaggering-slow",
        "swaggering-auth-anomaly", "swaggering-shadow-exposed", "swaggering-injection-hint",
        "swaggering-sensitive-data",
        "race-condition", "broken-anti-automation", "workflow-step-skip",
        "fail-open-unauthenticated", "fail-open-invalid-token",
        "missing-parameter-crash", "missing-parameter-error", "missing-parameter-npe-hint",
        // Supply chain (A03)
        "manifest-leak", "vulnerable-dependency-declared", "missing-sri", "vulnerable-component",
        "shadow-api", "zombie-api", "auth-gated-api", "clickjack-vulnerable",
        "tabnabbing", "xss-hygiene",
        "other"
    };

    /// <summary>Returns true when <paramref name="category"/> is a known chain category.</summary>
    public static bool IsKnownCategory(string category) =>
        KnownCategories.Contains(category);

    /// <summary>
    /// Collect all chainable findings from shadow, auto-scan, journal, and manual sources.
    /// </summary>
    public static List<ChainableFinding> CollectAll(
        SecurityShadowManager? shadow,
        List<AutoScanPipeline.AutoScanFinding>? autoScanFindings,
        List<ChainableFinding>? manualFindings,
        IReadOnlyList<SessionLogger.JournalEntry>? journalEntries = null)
    {
        var all = new List<ChainableFinding>();

        if (shadow?.Enabled == true)
            all.AddRange(NormalizeShadow(shadow.GetFindings()));

        if (autoScanFindings != null)
            all.AddRange(NormalizeAutoScan(autoScanFindings));

        if (manualFindings != null)
            all.AddRange(manualFindings);

        if (journalEntries != null)
            all.AddRange(NormalizeJournal(journalEntries));

        return Deduplicate(all);
    }

    /// <summary>
    /// Collapse duplicate findings from repeated scans, orchestration double-feeds, or identical endpoint hits.
    /// Source-agnostic — prefers the first occurrence (shadow/autoscan before orchestrate copies).
    /// </summary>
    private static List<ChainableFinding> Deduplicate(List<ChainableFinding> findings)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deduped = new List<ChainableFinding>();
        foreach (var finding in findings)
        {
            if (seen.Add(ChainFindingDedup.Key(finding)))
                deduped.Add(finding);
        }
        return deduped;
    }

    /// <summary>
    /// Normalize <see cref="ShadowFinding"/> instances into chainable findings.
    /// </summary>
    public static List<ChainableFinding> NormalizeShadow(List<ShadowFinding> findings)
    {
        var result = new List<ChainableFinding>();
        foreach (var f in findings)
        {
            var category = MapShadowCategory(f.Audit, f.Title);
            if (category == null) continue;

            result.Add(new ChainableFinding
            {
                Id = $"shadow-{f.Id}",
                Source = "shadow",
                Category = category,
                Severity = f.Severity.ToString().ToLowerInvariant(),
                Title = f.Title,
                Endpoint = f.Url,
                Detail = f.Description,
                Tags = [f.Audit.ToLowerInvariant()]
            });
        }
        return result;
    }

    /// <summary>
    /// Normalize <see cref="AutoScanPipeline.AutoScanFinding"/> instances into chainable findings.
    /// </summary>
    public static List<ChainableFinding> NormalizeAutoScan(List<AutoScanPipeline.AutoScanFinding> findings)
    {
        var result = new List<ChainableFinding>();
        for (var i = 0; i < findings.Count; i++)
        {
            var f = findings[i];
            result.Add(new ChainableFinding
            {
                Id = $"autoscan-{f.Scanner}-{i}",
                Source = "autoscan",
                Category = MapAutoScanCategory(f.Scanner, f.Title),
                Severity = f.Severity.ToLowerInvariant(),
                Title = f.Title,
                Endpoint = f.Endpoint,
                Method = f.Method,
                Parameter = ChainFindingDedup.ExtractParameter(f.Title, f.Detail, f.Evidence),
                Detail = f.Detail,
                Evidence = f.Evidence,
                Tags = [f.Scanner.ToLowerInvariant()]
            });
        }
        return result;
    }

    /// <summary>
    /// Normalize bug/enhancement journal entries with security tags or category hints into chainable findings.
    /// </summary>
    public static List<ChainableFinding> NormalizeJournal(IReadOnlyList<SessionLogger.JournalEntry> entries)
    {
        var result = new List<ChainableFinding>();
        for (var i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            var kind = (e.Kind ?? e.Type).ToLowerInvariant();
            if (kind is not (NoteKinds.Bug or NoteKinds.Enhancement or NoteKinds.Observation))
                continue;

            if (e.Tags?.Any(t => t.Equals("chain-prove", StringComparison.OrdinalIgnoreCase)) == true)
                continue;

            var category = MapJournalCategory(e);
            if (category == null || category == "other") continue;

            result.Add(new ChainableFinding
            {
                Id = $"journal-{e.Index}",
                Source = "journal",
                Category = category,
                Severity = NormalizeJournalSeverity(e.Severity, category),
                Title = e.Summary,
                Endpoint = e.Url,
                Detail = e.Details,
                Tags = e.Tags ?? [],
                Evidence = FormatJournalEvidence(e)
            });
        }
        return result;
    }

    private static string? MapJournalCategory(SessionLogger.JournalEntry entry)
    {
        if (entry.Fields != null)
        {
            if (entry.Fields.TryGetValue("category", out var explicitCat) && IsKnownCategory(explicitCat))
                return explicitCat.ToLowerInvariant();
            foreach (var kv in entry.Fields)
            {
                if (kv.Key.Equals("securityCategory", StringComparison.OrdinalIgnoreCase) && IsKnownCategory(kv.Value))
                    return kv.Value.ToLowerInvariant();
            }
        }

        if (entry.Tags != null)
        {
            foreach (var tag in entry.Tags)
            {
                if (string.IsNullOrWhiteSpace(tag)) continue;
                if (tag.StartsWith("category:", StringComparison.OrdinalIgnoreCase))
                {
                    var cat = tag["category:".Length..].Trim();
                    if (IsKnownCategory(cat)) return cat.ToLowerInvariant();
                }
                if (IsKnownCategory(tag)) return tag.ToLowerInvariant();
            }
        }

        var text = $"{entry.Summary} {entry.Details}".ToLowerInvariant();
        return MapTextToCategory(text);
    }

    private static string? MapTextToCategory(string text)
    {
        if (text.Contains("alg:none") || text.Contains("jwt alg") || text.Contains("algorithm confusion")
            || text.Contains("jwt-algorithm") || text.Contains("jwt acceptance"))
            return "jwt-acceptance";
        if (text.Contains("alg variant") || text.Contains("jwt_alg_variant")) return "jwt-alg-variant";
        if (text.Contains("jku") || text.Contains("x5u") || text.Contains("jwt header abuse")) return "jwt-header-abuse";
        if (text.Contains("xss")) return "xss";
        if (text.Contains("csrf")) return "csrf";
        if (text.Contains("idor")) return "idor";
        if (text.Contains("sqli") || text.Contains("sql injection")) return text.Contains("indicator") ? "sqli-indicator" : "sqli";
        if (text.Contains("ssrf")) return "ssrf";
        if (text.Contains("open redirect")) return "open-redirect";
        if (text.Contains("path traversal")) return "path-traversal";
        if (text.Contains("mass assignment")) return "mass-assignment";
        if (text.Contains("content-type") && text.Contains("confus")) return "content-type-confusion";
        if (text.Contains("deserial")) return "deserialization-suspected";
        if (text.Contains("parser differential") || text.Contains("parser disagreement")) return "parser-differential";
        if (text.Contains("command injection") || text.Contains("shell injection")) return "command-injection";
        var ssti = MapSstiCategoryFromText(text);
        if (ssti != null) return ssti;
        if (text.Contains("csti") || text.Contains("client-side template")) return "csti-confirmed";
        if (text.Contains("rce") || text.Contains("remote code execution")) return "rce-indicator";
        if (text.Contains("plaintext password") || (text.Contains("password field") && text.Contains("request body")))
            return "plaintext-password-in-transit";
        if (text.Contains("reset token") || text.Contains("password reset token") || text.Contains("verification token"))
            return "weak-reset-token";
        if (text.Contains("missing httponly") || text.Contains("httponly")) return "missing-httponly";
        if (text.Contains("missing csp") || text.Contains("content-security-policy")) return "missing-csp";
        if (text.Contains("cors")) return "cors-misconfig";
        if (text.Contains("fail open") || text.Contains("fail-open")) return "fail-open-unauthenticated";
        if (text.Contains("missing parameter") || text.Contains("omitted field")) return "missing-parameter-crash";
        if (text.Contains("trusted-header") || text.Contains("x-forwarded-user")) return "auth-bypass-header-spoof";
        if (text.Contains("default credential") || text.Contains("default password")) return "default-credentials";
        if (text.Contains("stack trace") || text.Contains("info leak")) return "info-leak";
        if (text.Contains("weak auth") || text.Contains("unauthenticated")) return "weak-auth";
        if (text.Contains("auth bypass pivot") || text.Contains("authenticated pivot")) return "auth-bypass-pivot";
        if (text.Contains("cookie prefix") || text.Contains("__host-") || text.Contains("__secure-")) return "cookie-prefix-bypass";
        if (text.Contains("weak saml") || text.Contains("missing-signature") || text.Contains("sha-1")) return "weak-saml-signature";
        if (text.Contains("tls 1.0") || text.Contains("tls 1.1") || text.Contains("deprecated tls")) return "weak-tls";
        if (text.Contains("certificate expir") || text.Contains("expiring cert")) return "expiring-cert";
        if (text.Contains("rest scaffold") || text.Contains("scaffold path")) return "rest-scaffold-unauth";
        if (text.Contains("path-filter bypass") || text.Contains("path filter bypass")) return "path-filter-bypass";
        if (text.Contains("credential") && text.Contains("leak")) return "credential-exposure";
        if (text.Contains("shadow api") || text.Contains("undocumented api")) return "shadow-api";
        if (text.Contains("zombie api") || text.Contains("zombie-candidate") ||
            text.Contains("parallel api version")) return "zombie-api";
        if (text.Contains("session-only") && text.Contains("endpoint")) return "auth-gated-api";
        if (text.Contains("clickjack") || text.Contains("ui redress")) return "clickjack-vulnerable";
        return null;
    }

    private static string NormalizeJournalSeverity(string? severity, string category) =>
        severity?.ToLowerInvariant() switch
        {
            "critical" or "high" or "medium" or "low" => severity.ToLowerInvariant(),
            _ => category is "xss" or "sqli" or "idor" or "rce-indicator" or "command-injection" ? "high" : "medium"
        };

    private static string? FormatJournalEvidence(SessionLogger.JournalEntry entry)
    {
        if (entry.Fields == null || entry.Fields.Count == 0) return null;
        var parts = entry.Fields
            .Where(kv => kv.Key is "steps" or "actual" or "expected" or "oracle" or "priority")
            .Select(kv => $"{kv.Key}: {kv.Value}");
        return string.Join(" | ", parts);
    }

    /// <summary>
    /// Map shadow audit + title into a normalized category for chain matching.
    /// </summary>
    private static string? MapShadowCategory(string audit, string title)
    {
        var t = title.ToLowerInvariant();
        var a = audit.ToLowerInvariant();

        // Security Headers
        if (a.Contains("header"))
        {
            if (t.Contains("content-security-policy") || t.Contains("csp")) return "missing-csp";
            if (t.Contains("strict-transport") || t.Contains("hsts")) return "missing-hsts";
            if (t.Contains("x-frame-options") || t.Contains("frame-ancestors")) return "missing-xframe";
            if (t.Contains("referrer-policy")) return "missing-referrer-policy";
            if (t.Contains("permissions-policy")) return "missing-permissions-policy";
            if (t.Contains("server") && t.Contains("disclos")) return "server-disclosure";
            return "weak-headers";
        }

        // Cookies
        if (a.Contains("cookie"))
        {
            if (t.Contains("httponly")) return "missing-httponly";
            if (t.Contains("secure")) return "missing-secure-flag";
            // Only SameSite=None / missing SameSite — not recommendations that mention "SameSite".
            if (t.Contains("samesitenone") || t.Contains("samesite=none")
                || t.Contains("samesite none")
                || (t.Contains("samesite") && (t.Contains("missing") || t.Contains("none"))))
                return "missing-samesite";
            return "weak-cookies";
        }

        if (a.Contains("tabnabbing") || t.Contains("tabnabbing") || t.Contains("reverse tabnabbing"))
            return "tabnabbing";

        // XSS — do not treat passive DOM hygiene (inline handlers / javascript: URLs) as
        // chainable exploit XSS; those inflate worm/CSRF chains without stored/reflected proof.
        if (a.Contains("inline-handler") || t.Contains("inline-handler")
            || a.Contains("javascript-url") || t.Contains("javascript-url")
            || t.Contains("javascript: url") || t.Contains("inline event handler"))
            return "xss-hygiene";

        if (a.Contains("xss") || t.Contains("xss") || t.Contains("innerhtml") ||
            t.Contains("eval(") || t.Contains("document.write"))
            return "xss";

        // CORS
        if (a.Contains("cors") || t.Contains("cors"))
            return "cors-misconfig";

        // Mixed content
        if (a.Contains("mixed") || t.Contains("mixed content"))
            return "mixed-content";

        // Source maps
        if (a.Contains("source.map") || t.Contains("source map"))
            return "source-maps";

        // Storage
        if (a.Contains("storage"))
        {
            if (t.Contains("token") || t.Contains("auth") || t.Contains("jwt"))
                return "token-in-storage";
            return "sensitive-storage";
        }

        if (a.Contains("network") && t.Contains("duplicate"))
            return null;

        // Network-based passive detections
        if (t.Contains("500") || t.Contains("server error") || t.Contains("stack trace"))
            return "info-leak";
        if (t.Contains("sql") && (t.Contains("error") || t.Contains("syntax")))
            return "sqli-indicator";
        if (t.Contains("credential") || t.Contains("password") || t.Contains("secret"))
            return "credential-exposure";
        if (t.Contains("captcha"))
            return "captcha-leak";

        // CSRF
        if (a.Contains("csrf") || t.Contains("csrf"))
            return "csrf";

        // Parser / content-type confusion (shadow passive + future parser-probe)
        if (t.Contains("content-type") && (t.Contains("confus") || t.Contains("415")))
            return "content-type-confusion";
        if (t.Contains("deserial") || t.Contains("java-serialized") || t.Contains("xml entity"))
            return "deserialization-suspected";
        if (t.Contains("parser") && (t.Contains("differential") || t.Contains("disagree")))
            return "parser-differential";

        // Command injection / RCE indicators (shadow passive + future cmd-canary)
        if (t.Contains("command injection") || t.Contains("shell injection") ||
            (t.Contains("uid=") && t.Contains("injection")))
            return "command-injection";
        var ssti = MapSstiCategoryFromText(t);
        if (ssti != null) return ssti;
        if (t.Contains("rce") || t.Contains("remote code execution") ||
            t.Contains("code execution"))
            return "rce-indicator";

        // Session fixation
        if (t.Contains("session fixation") || (t.Contains("session id") && t.Contains("pre-auth"))
            || (t.Contains("session cookie") && t.Contains("unchanged")))
            return "session-fixation";
        if (t.Contains("password reset") && (t.Contains("security question") || t.Contains("canonical answer")))
            return "password-reset-weak";
        if (t.Contains("account enum") || t.Contains("user enum") || t.Contains("enumeration"))
            return "account-enumeration";
        if (t.Contains("logout") && (t.Contains("still valid") || t.Contains("after logout")))
            return "logout-invalidation";
        if (t.Contains("oauth") && (t.Contains("pkce") || t.Contains("plain")))
            return "oauth-flow-weakness";

        // Header injection
        if (t.Contains("header injection") || t.Contains("crlf") || t.Contains("response splitting"))
            return "header-injection";

        // Weak auth
        if (t.Contains("missing auth") || t.Contains("unauthenticated") && t.Contains("endpoint"))
            return "weak-auth";

        return "other";
    }

    /// <summary>
    /// Map auto-scan scanner name + title into a normalized category.
    /// </summary>
    private static string MapAutoScanCategory(string scanner, string title)
    {
        var s = scanner.ToLowerInvariant();
        return s switch
        {
            "sqli" => title.Contains("login bypass", StringComparison.OrdinalIgnoreCase) ? "sqli-indicator" : "sqli",
            "nosql" => "nosql-injection",
            "ldap" => "ldap-injection",
            "idor" => "idor",
            "csrf" => "csrf",
            "path-traversal" or "path_traversal" => "path-traversal",
            "mass-assignment" or "mass_assignment" => "mass-assignment",
            "open-redirect" or "open_redirect" => "open-redirect",
            "ssrf" => "ssrf",
            "xss" => "xss",
            "content-type-confusion" or "content_type_confusion" => "content-type-confusion",
            "deserialization-suspected" or "deserialization_suspected" => "deserialization-suspected",
            "rce-deserialization" or "rce_deserialization" => "rce-deserialization",
            "deserialization-dos" or "deserialization_dos" => "deserialization-dos",
            "file-upload-oversize" or "file_upload_oversize" => "file-upload-oversize",
            "file-upload-wrong-type" or "file_upload_wrong_type" => "file-upload-wrong-type",
            "file-upload-polyglot" or "file_upload_polyglot" => "file-upload-polyglot",
            "xxe-upload" or "xxe_upload" => "xxe-upload",
            "parser-differential" or "parser_differential" => "parser-differential",
            "command-injection" or "command_injection" => "command-injection",
            "ssti-confirmed" or "ssti_confirmed" => "ssti-confirmed",
            "ssti-suspected" or "ssti_suspected" or "ssti" => "ssti-suspected",
            "ssti-polyglot" or "ssti_polyglot" => "ssti-polyglot",
            "ssti-stored" or "ssti_stored" => "ssti-stored",
            "prototype-pollution" or "prototype_pollution" => "prototype-pollution",
            "rce-indicator" or "rce_indicator" => "rce-indicator",
            "weak-auth" or "weak_auth" => "weak-auth",
            "auth-bypass-pivot" or "auth_bypass_pivot" => "auth-bypass-pivot",
            "jwt-acceptance-sweep" or "jwt_acceptance_sweep" or "jwt-acceptance" => "jwt-acceptance",
            "jwt-alg-variant" or "jwt_alg_variant" => "jwt-alg-variant",
            "jwt-header-abuse" or "jwt_header_abuse" => "jwt-header-abuse",
            "cookie-prefix-bypass" or "cookie_prefix_bypass" => "cookie-prefix-bypass",
            "tls-introspection" or "weak-tls" => "weak-tls",
            "expiring-cert" => "expiring-cert",
            "weak-saml-signature" or "missing-signature" => "weak-saml-signature",
            "rest-scaffold" or "rest_scaffold" => "rest-scaffold-unauth",
            "path-filter-bypass" or "path_filter_bypass" => "path-filter-bypass",
            "session-fixation" or "session_fixation" => "session-fixation",
            "header-injection" or "header_injection" => "header-injection",
            "credential-exposure" or "credential_exposure" => "credential-exposure",
            "race-condition" or "race_condition" => "race-condition",
            "broken-anti-automation" or "broken_anti_automation" or "captcha-replay" => "broken-anti-automation",
            "workflow-step-skip" or "workflow_step_skip" => "workflow-step-skip",
            "session-fixation-scan" or "session_fixation_scan" => "session-fixation",
            "password-reset-weak" or "password_reset_weak" => "password-reset-weak",
            "account-enumeration" or "account_enumeration" => "account-enumeration",
            "logout-invalidation" or "logout_invalidation" => "logout-invalidation",
            "default-credential-canary" or "default_credentials" => "default-credentials",
            "sqli-login-sweep" or "sqli_login_sweep" => "sqli-login-bypass",
            "oauth-flow-test" or "oauth_flow_test" => "oauth-flow-weakness",
            "passive-network-recall" or "passive_network_recall" =>
                title.Contains("SQL", StringComparison.OrdinalIgnoreCase) ? "sqli"
                : title.Contains("Stored XSS", StringComparison.OrdinalIgnoreCase) ? "xss"
                : "info-leak",
            _ => IsKnownCategory(s) ? s : s
        };
    }

    /// <summary>
    /// Map free-text SSTI mentions to chain categories — only arithmetic/dual/canary signals are "confirmed".
    /// </summary>
    private static string? MapSstiCategoryFromText(string text)
    {
        if (!text.Contains("ssti", StringComparison.Ordinal)
            && !text.Contains("server-side template", StringComparison.Ordinal)
            && !text.Contains("template injection", StringComparison.Ordinal))
            return null;

        if (text.Contains("error signature", StringComparison.Ordinal)
            || text.Contains("suspected", StringComparison.Ordinal)
            || text.Contains("tentative", StringComparison.Ordinal)
            || text.Contains("template error", StringComparison.Ordinal))
            return "ssti-suspected";

        if (text.Contains("arithmetic", StringComparison.Ordinal)
            || text.Contains("dual", StringComparison.Ordinal)
            || text.Contains("engine canary", StringComparison.Ordinal)
            || text.Contains("49/56", StringComparison.Ordinal)
            || text.Contains("template arithmetic evaluated", StringComparison.Ordinal)
            || (text.Contains("confirmed", StringComparison.Ordinal)
                && !text.Contains("not confirmed", StringComparison.Ordinal)))
            return "ssti-confirmed";

        return "ssti-suspected";
    }
}
