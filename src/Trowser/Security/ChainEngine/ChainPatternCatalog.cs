namespace Trowser.Security.ChainEngine;

/// <summary>
/// Built-in catalog of known attack chain patterns. Each pattern describes how
/// two or more individual findings combine into a higher-impact exploit.
/// Custom patterns can be added at runtime via the API.
/// </summary>
public class ChainPatternCatalog
{
    private readonly object _lock = new();
    private readonly List<ChainPattern> _patterns = [];

    public ChainPatternCatalog()
    {
        _patterns.AddRange(BuiltInPatterns);
    }

    /// <summary>All patterns (built-in + custom).</summary>
    public List<ChainPattern> GetAll()
    {
        lock (_lock) return [.. _patterns];
    }

    /// <summary>Add a custom pattern. Returns false if ID already exists.</summary>
    public bool Add(ChainPattern pattern)
    {
        lock (_lock)
        {
            if (_patterns.Any(p => p.Id == pattern.Id)) return false;
            _patterns.Add(pattern);
            return true;
        }
    }

    /// <summary>Remove a custom pattern by ID. Built-in patterns cannot be removed.</summary>
    public bool Remove(string patternId)
    {
        lock (_lock)
        {
            var idx = _patterns.FindIndex(p => p.Id == patternId);
            if (idx < 0) return false;
            if (idx < BuiltInPatterns.Length) return false; // can't remove built-in
            _patterns.RemoveAt(idx);
            return true;
        }
    }

    // ───────────────────────────────────────────────────────────────────
    //  Built-in patterns
    // ───────────────────────────────────────────────────────────────────

    private static readonly ChainPattern[] BuiltInPatterns =
    [
        // ── Critical chains ──

        new()
        {
            Id = "csrf-stored-xss-worm",
            Name = "CSRF + Stored XSS → Self-Propagating Worm",
            ChainedSeverity = "critical",
            Impact = "worm",
            Links =
            [
                new() { RequiredCategory = "csrf", Role = "enabler", Constraint = "state-changing" },
                // Constraint "stored-or-reflected-xss" excludes inline-handler / hygiene XSS.
                new() { RequiredCategory = "xss", Role = "trigger", Constraint = "stored-or-reflected-xss" }
            ],
            Description = "The {0} endpoint has no CSRF protection. The {1} page is vulnerable to XSS. An attacker page can auto-submit an XSS payload via CSRF. When any user views the affected page, the XSS fires and replicates — creating a self-propagating worm.",
            ProofTemplateId = "csrf-stored-xss-worm"
        },

        new()
        {
            Id = "xss-missing-httponly-session-hijack",
            Name = "XSS + Missing HttpOnly → Session Hijack",
            ChainedSeverity = "critical",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "xss", Role = "trigger", Constraint = "stored-or-reflected-xss" },
                new() { RequiredCategory = "missing-httponly", Role = "enabler" }
            ],
            Description = "Exploit-grade XSS ({0}) with a session cookie readable from JavaScript ({1}) enables session hijack via document.cookie.",
            ProofTemplateId = "xss-missing-httponly-session-hijack"
        },

        new()
        {
            Id = "idor-weak-auth-unauth-access",
            Name = "IDOR + Missing Auth Ordering → Unauthenticated Data Access",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "idor", Role = "trigger" },
                new() { RequiredCategory = "weak-auth", Role = "enabler" }
            ],
            Description = "The IDOR on {0} allows accessing other users' resources. Combined with weak authentication checks ({1}), an unauthenticated attacker may access arbitrary user data by iterating IDs.",
            ProofTemplateId = "idor-weak-auth-unauth-access"
        },

        new()
        {
            Id = "open-redirect-oauth-token-theft",
            Name = "Open Redirect + OAuth → Authorization Code Theft",
            ChainedSeverity = "critical",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "open-redirect", Role = "trigger" },
                new() { RequiredCategory = "cors-misconfig", Role = "amplifier", Optional = true }
            ],
            Description = "An open redirect on {0} can be abused in an OAuth flow to redirect the authorization code to an attacker-controlled server, enabling account takeover.",
            ProofTemplateId = "open-redirect-oauth-token-theft"
        },

        new()
        {
            Id = "open-redirect-csrf-lax-bypass",
            Name = "Open Redirect + CSRF → Same-Site Forged POST",
            ChainedSeverity = "high",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "open-redirect", Role = "enabler" },
                new() { RequiredCategory = "csrf", Role = "trigger", Constraint = "state-changing" }
            ],
            Description =
                "Open redirect on {0} can chain with unprotected or Referer-only CSRF on {1}: " +
                "top-level navigation (SameSite Lax) or redirect-wrapped action URLs turn a cross-site attack into a same-site request. " +
                "Run POST /api/security/csrf with includeCrossSiteProof:true and review dom-flows nav-hijack chains."
        },

        new()
        {
            Id = "sqli-idor-mass-breach",
            Name = "SQL Injection + IDOR → Mass Data Breach",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "sqli", Role = "trigger" },
                new() { RequiredCategory = "idor", Role = "amplifier" }
            ],
            Description = "SQL injection on {0} combined with IDOR on {1} enables extracting data from all user records, not just the attacker's own.",
            ProofTemplateId = "sqli-auth-bypass-proof"
        },

        new()
        {
            Id = "cors-sensitive-data-theft",
            Name = "CORS Misconfiguration + Sensitive Endpoint → Cross-Origin Data Theft",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "cors-misconfig", Role = "enabler" },
                new() { RequiredCategory = "credential-exposure", Role = "trigger" }
            ],
            Description = "CORS misconfiguration ({0}) allows any origin to read API responses. A sensitive endpoint ({1}) leaks credentials or PII, enabling cross-origin data theft from an attacker's page.",
            ProofTemplateId = "cors-sensitive-data-theft"
        },

        new()
        {
            Id = "ssrf-cloud-metadata",
            Name = "SSRF + Cloud Metadata → IAM Credential Theft",
            ChainedSeverity = "critical",
            Impact = "rce",
            Links =
            [
                new() { RequiredCategory = "ssrf", Role = "trigger" },
                new() { RequiredCategory = "info-leak", Role = "amplifier", Optional = true }
            ],
            Description = "Server-Side Request Forgery on {0} allows reaching internal services. On cloud infrastructure, the metadata endpoint (169.254.169.254) returns IAM credentials, potentially granting full cloud account access.",
            ProofTemplateId = "ssrf-cloud-metadata-proof"
        },

        new()
        {
            Id = "path-traversal-upload-rce",
            Name = "Path Traversal + File Upload → Remote Code Execution",
            ChainedSeverity = "critical",
            Impact = "rce",
            Links =
            [
                new() { RequiredCategory = "path-traversal", Role = "trigger" },
                // Require a real upload amplifier — do not bind unrelated command-injection as "file upload".
                new() { RequiredCategory = "file-upload-polyglot", Role = "amplifier", Constraint = "same-origin" },
                new() { RequiredCategory = "mass-assignment", Role = "amplifier", Optional = true, Constraint = "same-origin" },
                new() { RequiredCategory = "rce-indicator", Role = "amplifier", Optional = true, Constraint = "same-origin" }
            ],
            Description = "Path traversal ({0}) can be combined with file upload to place a web shell in a server-accessible directory, enabling remote code execution.",
            ProofTemplateId = "file-upload-polyglot-rce"
        },

        new()
        {
            Id = "deserialization-rce-confirmed",
            Name = "Deserialization RCE → Server Compromise",
            ChainedSeverity = "critical",
            Impact = "rce",
            Links =
            [
                new() { RequiredCategory = "rce-deserialization", Role = "trigger" },
                new() { RequiredCategory = "deserialization-suspected", Role = "enabler", Optional = true }
            ],
            Description = "Untrusted deserialization ({0}) yields server-side code execution indicators.",
            ProofTemplateId = "node-serialize-rce-proof"
        },

        // ── High chains ──

        new()
        {
            Id = "csrf-password-change-takeover",
            Name = "CSRF on Password/Email Change → Account Takeover",
            ChainedSeverity = "high",
            Impact = "account-takeover",
            Links =
            [
                new()
                {
                    RequiredCategory = "csrf",
                    Role = "trigger",
                    Constraint = "state-changing",
                    EndpointPattern = @"(?i)(password|passwd|email|account|settings|profile|credentials|security|change[-_]?password|update[-_]?email)"
                }
            ],
            Description = "The password or email change endpoint ({0}) lacks CSRF protection. An attacker can force a victim to change their credentials, taking over the account."
        },

        new()
        {
            Id = "timing-oracle-no-ratelimit-bruteforce",
            Name = "Timing Oracle + No Rate Limit → Credential Brute Force",
            ChainedSeverity = "high",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "timing-oracle", Role = "enabler" },
                new()
                {
                    RequiredCategory = "missing-rate-limit",
                    Role = "amplifier",
                    Optional = true,
                    EndpointPattern = @"(?i)(login|signin|sign-in|auth|token|session|oauth|password|otp|mfa|credential)"
                }
            ],
            Description = "A timing difference on {0} reveals valid usernames. Without rate limiting, an attacker can enumerate users then brute-force passwords."
        },

        new()
        {
            Id = "missing-csp-reflected-xss",
            Name = "Missing CSP + Reflected XSS → Reliable XSS Execution",
            ChainedSeverity = "high",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "missing-csp", Role = "enabler" },
                new() { RequiredCategory = "xss", Role = "trigger", Constraint = "stored-or-reflected-xss" }
            ],
            Description = "Missing or weak CSP ({0}) combined with exploit-grade XSS ({1}) allows reliable script execution in the page context.",
            ProofTemplateId = "missing-csp-reflected-xss"
        },

        new()
        {
            Id = "header-injection-cache-poisoning",
            Name = "Header Injection + Cacheable Response → Cache Poisoning",
            ChainedSeverity = "high",
            Impact = "defacement",
            Links =
            [
                new() { RequiredCategory = "header-injection", Role = "trigger" },
                new() { RequiredCategory = "weak-headers", Role = "enabler", Optional = true }
            ],
            Description = "Header injection on {0} can modify response content. If the response is cached, all subsequent users receive the poisoned response, enabling widespread XSS or defacement."
        },

        new()
        {
            Id = "session-fixation-xss-hijack",
            Name = "Session Fixation + XSS → Pre-Auth Session Hijack",
            ChainedSeverity = "high",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "session-fixation", Role = "enabler" },
                new() { RequiredCategory = "xss", Role = "trigger" }
            ],
            Description = "An attacker fixes the victim's session ID, then uses XSS ({1}) to confirm the session was authenticated. The attacker already knows the session ID and can hijack it."
        },

        new()
        {
            Id = "mass-assignment-privilege-escalation",
            Name = "Mass Assignment + Privilege Field → Privilege Escalation",
            ChainedSeverity = "high",
            Impact = "privilege-escalation",
            Links =
            [
                new() { RequiredCategory = "mass-assignment", Role = "trigger" }
            ],
            Description = "Mass assignment vulnerability ({0}) allows injecting privileged fields (role, isAdmin, permissions) into update requests, escalating a regular user to administrator.",
            ProofTemplateId = "role-self-promote"
        },

        new()
        {
            Id = "weak-auth-auth-bypass-pivot",
            Name = "Weak Auth / SQLi → Authenticated Pivot → Protected Endpoint Access",
            ChainedSeverity = "critical",
            Impact = "privilege-escalation",
            Links =
            [
                new() { RequiredCategory = "weak-auth", Role = "enabler", Optional = true },
                new() { RequiredCategory = "sqli-indicator", Role = "enabler", Optional = true },
                new() { RequiredCategory = "auth-bypass-pivot", Role = "trigger" }
            ],
            Description = "Authentication weakness ({0}) yields a usable token. Authenticated pivot ({1}) unlocks endpoints that reject anonymous callers.",
            ProofTemplateId = "sqli-auth-bypass-proof"
        },

        new()
        {
            Id = "auth-bypass-header-spoof",
            Name = "Trusted Header Spoof → Protected Resource Access",
            ChainedSeverity = "critical",
            Impact = "privilege-escalation",
            Links =
            [
                new() { RequiredCategory = "auth-bypass-header-spoof", Role = "trigger" }
            ],
            Description = "The application trusts client-supplied proxy headers ({0}), allowing anonymous callers to access protected admin or internal resources."
        },

        new()
        {
            Id = "content-type-confusion-mass-assignment-priv-esc",
            Name = "Content-Type Confusion + Mass Assignment → Privilege Escalation",
            ChainedSeverity = "critical",
            Impact = "privilege-escalation",
            Links =
            [
                new() { RequiredCategory = "content-type-confusion", Role = "enabler" },
                // Mass-assignment must be present — optional pairing upgraded parser noise to critical.
                new() { RequiredCategory = "mass-assignment", Role = "trigger" },
                new() { RequiredCategory = "deserialization-suspected", Role = "amplifier", Optional = true }
            ],
            Description = "Alternate Content-Type parsing ({0}) accepts fields the JSON parser ignores. Combined with mass assignment ({1}), an attacker may inject privileged fields via XML or form-encoded bodies.",
            ProofTemplateId = "content-type-confusion-mass-assignment-priv-esc"
        },

        new()
        {
            Id = "ssti-confirmed-missing-csp",
            Name = "SSTI Confirmed + Missing CSP → Reliable Server-Side Execution Indicator",
            ChainedSeverity = "high",
            Impact = "rce",
            Links =
            [
                new() { RequiredCategory = "ssti-confirmed", Role = "trigger" },
                new() { RequiredCategory = "missing-csp", Role = "amplifier", Optional = true }
            ],
            Description = "Server-side template injection ({0}) reflects arithmetic evaluation, confirming template execution. Without CSP restrictions ({1}), any chained client-side impact executes reliably.",
            ProofTemplateId = "ssti-confirmed-arithmetic-proof"
        },

        new()
        {
            Id = "command-injection-ssrf-internal-rce",
            Name = "Command Injection + SSRF → Internal RCE Indicator",
            ChainedSeverity = "critical",
            Impact = "rce",
            Links =
            [
                new() { RequiredCategory = "command-injection", Role = "trigger", Optional = true },
                new() { RequiredCategory = "rce-indicator", Role = "trigger", Optional = true },
                new() { RequiredCategory = "ssrf", Role = "enabler" }
            ],
            Description = "SSRF ({2}) reaches internal services. Command injection or RCE indicators ({0}) on the same host suggest shell execution on internal infrastructure.",
            ProofTemplateId = "rce-indicator-cmd-canary-proof"
        },

        new()
        {
            Id = "missing-samesite-csrf-bypass",
            Name = "Missing SameSite + CSRF Token Not Validated → Full CSRF",
            ChainedSeverity = "high",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "missing-samesite", Role = "enabler" },
                new() { RequiredCategory = "csrf", Role = "trigger", Constraint = "state-changing" }
            ],
            Description = "Session cookies lack SameSite attribute ({0}), allowing cross-site request attachment. Combined with missing CSRF validation ({1}), any state-changing request can be forged from an attacker's page."
        },

        // ── Medium → High upgrade chains ──

        new()
        {
            Id = "info-leak-targeted-injection",
            Name = "Info Leak (Stack Trace) + Error Reflection → Targeted Injection",
            ChainedSeverity = "high",
            Impact = "data-breach",
            Links =
            [
                // Exclude swagger/OpenAPI keyword noise (e.g. "PostgreSQL" in schema descriptions).
                new()
                {
                    RequiredCategory = "info-leak",
                    Role = "enabler",
                    EndpointPattern = @"(?i)^(?!.*(swagger|openapi|/api-docs|\.ya?ml\b)).*"
                },
                new() { RequiredCategory = "sqli-indicator", Role = "trigger", Constraint = "same-origin" }
            ],
            Description = "Stack traces ({0}) reveal backend technology and query patterns. SQL error messages ({1}) confirm injection points. Together, these enable precisely targeted SQL injection with known database engine syntax."
        },

        new()
        {
            Id = "parser-differential-info-leak-injection",
            Name = "Parser Differential + Info Leak → Targeted Injection",
            ChainedSeverity = "high",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "parser-differential", Role = "enabler", Constraint = "same-origin" },
                new()
                {
                    RequiredCategory = "info-leak",
                    Role = "enabler",
                    Constraint = "same-origin",
                    EndpointPattern = @"(?i)^(?!.*(swagger|openapi|/api-docs|\.ya?ml\b)).*"
                },
                new() { RequiredCategory = "sqli-indicator", Role = "trigger", Optional = true, Constraint = "same-origin" },
                new() { RequiredCategory = "command-injection", Role = "trigger", Optional = true, Constraint = "same-origin" }
            ],
            Description = "Parser disagreement ({0}) combined with stack traces or error leaks ({1}) reveals backend parsers and injection surfaces — enabling targeted SQLi or command injection with engine-specific syntax."
        },

        new()
        {
            Id = "source-maps-targeted-attack",
            Name = "Source Maps Exposed + XSS → Precisely Targeted XSS",
            ChainedSeverity = "high",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "source-maps", Role = "enabler" },
                new() { RequiredCategory = "xss", Role = "trigger" }
            ],
            Description = "Exposed source maps ({0}) reveal the full client-side source code, including sanitization logic and DOM manipulation patterns. This allows crafting XSS payloads ({1}) that precisely bypass the application's defenses."
        },

        // ── Supply chain (A03) ──

        new()
        {
            Id = "manifest-leak-vulnerable-dep",
            Name = "Manifest Leak + Vulnerable Dependency → Targeted Exploit",
            ChainedSeverity = "critical",
            Impact = "rce",
            ProofTemplateId = "manifest-leak-vulnerable-dep",
            Links =
            [
                new() { RequiredCategory = "manifest-leak", Role = "enabler" },
                new() { RequiredCategory = "vulnerable-dependency-declared", Role = "trigger" }
            ],
            Description = "Exposed dependency manifest ({0}) reveals exact package versions. OSV advisories ({1}) give attackers the precise CVE and version needed to build an exploit without guessing."
        },

        new()
        {
            Id = "missing-sri-cdn-compromise",
            Name = "Missing SRI + CDN Script → Supply Chain Code Execution",
            ChainedSeverity = "high",
            Impact = "session-hijack",
            ProofTemplateId = "missing-sri-cdn-compromise",
            Links =
            [
                new() { RequiredCategory = "missing-sri", Role = "enabler" },
                new() { RequiredCategory = "missing-csp", Role = "amplifier", Optional = true }
            ],
            Description = "Third-party script ({0}) loads without Subresource Integrity. A compromised CDN or MITM can substitute arbitrary JavaScript that executes in the victim origin context."
        },

        new()
        {
            Id = "source-map-exposed-creds",
            Name = "Source Maps + Credential Exposure → Full Secret Recovery",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "source-maps", Role = "enabler" },
                new() { RequiredCategory = "credential-exposure", Role = "trigger" }
            ],
            Description = "Exposed source maps ({0}) reveal original source including hardcoded secrets. Combined with credential exposure findings ({1}), attackers recover API keys and internal endpoints from production bundles."
        },

        // ── Cryptographic failures (A04) ──

        new()
        {
            Id = "missing-hsts-downgrade-risk",
            Name = "Missing HSTS → SSL Stripping / Downgrade Risk",
            ChainedSeverity = "high",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "missing-hsts", Role = "enabler" }
            ],
            ConfirmationAnyCategories =
            [
                "mixed-content", "missing-secure-flag", "http-downgrade-proven"
            ],
            HypothesisSeverityCap = "medium",
            HypothesisTags = ["needs-http-probe"],
            Description = "HTTPS page ({0}) lacks Strict-Transport-Security. Attackers on the network path can strip TLS and intercept credentials or session cookies."
        },

        new()
        {
            Id = "jwt-alg-none-acceptance",
            Name = "JWT alg:none Acceptance → Authentication Bypass",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            ProofTemplateId = "jwt-algorithm-confusion",
            Links =
            [
                new() { RequiredCategory = "jwt-acceptance", Role = "trigger" }
            ],
            Description = "Protected endpoint ({0}) accepts unsigned or alg:none JWTs. Forge tokens to impersonate any user without a valid signature."
        },

        new()
        {
            Id = "jwt-alg-variant-acceptance",
            Name = "JWT Alg Variant Acceptance → Auth Bypass",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            ProofTemplateId = "jwt-algorithm-confusion",
            Links =
            [
                new() { RequiredCategory = "jwt-alg-variant", Role = "trigger" }
            ],
            Description = "JWT validator rejects canonical alg:none but accepts case/whitespace variants on {0} — equivalent authentication bypass."
        },

        new()
        {
            Id = "storage-token-xss-theft",
            Name = "Token in Storage + XSS → Bearer Token Theft",
            ChainedSeverity = "critical",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "token-in-storage", Role = "enabler" },
                new() { RequiredCategory = "xss", Role = "trigger" }
            ],
            Description = "Auth token stored in localStorage/sessionStorage ({0}). XSS on {1} lets attacker read storage and replay the bearer token."
        },

        new()
        {
            Id = "weak-saml-signature-spoof",
            Name = "Weak/Missing SAML Signature → Identity Spoofing",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "weak-saml-signature", Role = "trigger" }
            ],
            Description = "SAML assertion lacks signature or uses weak SHA-1 ({0}). Replay or forge assertions to impersonate users — use saml-replay with removeSignature for proof."
        },

        new()
        {
            Id = "mixed-content-downgrade",
            Name = "Mixed Content + Missing HSTS → Active Network Attack",
            ChainedSeverity = "high",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "mixed-content", Role = "enabler" },
                new() { RequiredCategory = "missing-hsts", Role = "amplifier", Optional = true }
            ],
            Description = "HTTPS page loads HTTP subresources ({0}). Without HSTS, network attackers can modify cleartext assets to steal sessions or inject script."
        },

        new()
        {
            Id = "shadow-api-unauthenticated-mutation",
            Name = "Shadow API + Missing Auth → Unmonitored Mutation Surface",
            ChainedSeverity = "high",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "shadow-api", Role = "enabler" },
                new() { RequiredCategory = "weak-auth", Role = "amplifier" }
            ],
            Description = "Undocumented API path ({0}) is reachable without the controls applied to official endpoints. Combined with weak or missing authentication, attackers can mutate state on an unmonitored route."
        },

        new()
        {
            Id = "shadow-api-csrf",
            Name = "Shadow API + CSRF Gap → Cross-Site State Change",
            ChainedSeverity = "high",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "shadow-api", Role = "enabler" },
                new() { RequiredCategory = "csrf", Role = "trigger", Constraint = "state-changing" }
            ],
            Description = "Shadow API ({0}) lacks inventory controls and accepts cross-site requests ({1}). Attackers can drive state changes on a route the team may not monitor."
        },

        new()
        {
            Id = "zombie-api-parallel-versions",
            Name = "Zombie / Parallel API Versions → Deprecated Attack Surface",
            ChainedSeverity = "high",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "zombie-api", Role = "enabler" }
            ],
            Description = "Deprecated or parallel API version ({0}) remains active alongside newer routes. Zombie endpoints often lack current auth, rate limits, and monitoring."
        },

        new()
        {
            Id = "clickjack-sensitive-flow",
            Name = "Missing Frame Protection + Sensitive Flow → UI Redress",
            // Active clickjack proof required — bare missing XFO (info) must not escalate to high.
            ChainedSeverity = "medium",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "clickjack-vulnerable", Role = "trigger" },
                new() { RequiredCategory = "missing-xframe", Role = "enabler", Optional = true }
            ],
            Description = "Sensitive page ({0}) can be framed cross-origin (missing X-Frame-Options / CSP frame-ancestors). Attackers can overlay invisible UI to trick users into unintended actions."
        },

        new()
        {
            Id = "default-credentials-login",
            Name = "Default Credentials → Account Takeover",
            ChainedSeverity = "critical",
            Impact = "account-takeover",
            ProofTemplateId = "default-credential-login-proof",
            Links =
            [
                new() { RequiredCategory = "default-credentials", Role = "trigger" }
            ],
            Description = "Default or leaked credentials work on {0}. Attacker gains authenticated session without brute force."
        },

        new()
        {
            Id = "oauth-pkce-downgrade",
            Name = "OAuth PKCE Downgrade → Authorization Code Interception",
            ChainedSeverity = "critical",
            Impact = "account-takeover",
            ProofTemplateId = "oauth-pkce-downgrade-proof",
            Links =
            [
                new() { RequiredCategory = "oauth-flow-weakness", Role = "trigger", Optional = true },
                new() { RequiredCategory = "weak-auth", Role = "enabler", Optional = true }
            ],
            Description = "OAuth authorize endpoint ({0}) accepts PKCE downgrade or weak state — code/token theft via redirect manipulation."
        },

        new()
        {
            Id = "session-fixation-hijack",
            Name = "Session Fixation → Pre-Auth Session Hijack",
            ChainedSeverity = "high",
            Impact = "session-hijack",
            ProofTemplateId = "session-fixation-proof",
            Links =
            [
                new() { RequiredCategory = "session-fixation", Role = "trigger" }
            ],
            Description = "Session ID unchanged after login on {0}. Attacker who fixed the pre-auth session can hijack the authenticated session."
        },

        new()
        {
            Id = "password-reset-weak-chain",
            Name = "Weak Security Question → Password Reset Takeover",
            ChainedSeverity = "critical",
            Impact = "account-takeover",
            ProofTemplateId = "password-reset-weak-proof",
            Links =
            [
                new() { RequiredCategory = "password-reset-weak", Role = "trigger" }
            ],
            Description = "Password reset accepts canonical security-question answers on {0} — account takeover without email access."
        },

        new()
        {
            Id = "account-enum-bruteforce",
            Name = "Account Enumeration + No Rate Limit → Targeted Attack",
            ChainedSeverity = "high",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "account-enumeration", Role = "enabler" },
                new()
                {
                    RequiredCategory = "missing-rate-limit",
                    Role = "amplifier",
                    Optional = true,
                    EndpointPattern = @"(?i)(login|signin|sign-in|auth|token|session|oauth|password|otp|mfa|credential)"
                }
            ],
            Description = "Valid usernames can be enumerated via {0}. Combined with missing rate limits, attackers can focus credential stuffing."
        },

        new()
        {
            Id = "llm05-improper-output-handling",
            Name = "LLM05 Improper Output Handling → XSS via Model Response",
            ChainedSeverity = "high",
            Impact = "xss",
            ProofTemplateId = "llm05-improper-output-handling-proof",
            Links =
            [
                new() { RequiredCategory = "llm05-improper-output-handling", Role = "trigger" },
                new() { RequiredCategory = "llm-redteam", Role = "trigger", Optional = true }
            ],
            Description = "LLM returned unsanitized HTML/script in chat response on {0}. Downstream render without encoding enables stored/reflected XSS in copilot UI."
        },

        // ── Cross-category chains (§7.10) ──

        new()
        {
            Id = "csrf-samesite-bypass-chain",
            Name = "CSRF + SameSite=None Cookie → SameSite Bypass CSRF",
            ChainedSeverity = "high",
            Impact = "account-takeover",
            ProofTemplateId = "csrf-samesite-bypass",
            Links =
            [
                new() { RequiredCategory = "csrf", Role = "trigger", Constraint = "state-changing" },
                new() { RequiredCategory = "missing-samesite", Role = "enabler" },
                new() { RequiredCategory = "weak-cookies", Role = "enabler", Optional = true }
            ],
            Description = "CSRF on {0} is exploitable because session cookies are set with SameSite=None ({1}), allowing cross-site request attachment. Weak cookie attributes ({2}) further reduce browser protections."
        },

        new()
        {
            Id = "cors-credentials-data-exfil",
            Name = "CORS Misconfiguration + Credential Cookies → Cross-Origin Data Exfiltration",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            ProofTemplateId = "cors-credentials-leak",
            Links =
            [
                new() { RequiredCategory = "cors-misconfig", Role = "enabler" },
                new() { RequiredCategory = "credential-exposure", Role = "trigger" }
            ],
            Description = "Permissive CORS policy ({0}) with Access-Control-Allow-Credentials allows attacker origins to read authenticated responses. Credential endpoint ({1}) leaks PII or tokens cross-origin."
        },

        new()
        {
            Id = "subdomain-takeover-phishing",
            Name = "Dangling CNAME + Trusted Subdomain → Phishing / Cookie Theft",
            ChainedSeverity = "high",
            Impact = "phishing",
            ProofTemplateId = "subdomain-takeover-fingerprint",
            Links =
            [
                new() { RequiredCategory = "subdomain-takeover", Role = "trigger" },
                new() { RequiredCategory = "weak-cookies", Role = "amplifier", Optional = true },
                new() { RequiredCategory = "missing-httponly", Role = "amplifier", Optional = true }
            ],
            Description = "Dangling CNAME ({0}) allows attacker to claim the subdomain. Trusted subdomain status enables phishing campaigns or parent-domain cookie theft via weak cookie scope ({1})."
        },

        new()
        {
            Id = "cache-poison-xss",
            Name = "Cache Poisoning + Reflected XSS → Mass User Compromise",
            ChainedSeverity = "critical",
            Impact = "mass-compromise",
            ProofTemplateId = "cache-poison-unkeyed-header",
            Links =
            [
                new() { RequiredCategory = "cache-poison", Role = "trigger" },
                new() { RequiredCategory = "xss", Role = "amplifier", Optional = true }
            ],
            Description = "Unkeyed header injection poisons the cache ({0}). When combined with reflected XSS ({1}), every user who hits the cached response executes attacker-controlled script — one request compromises all visitors."
        },

        new()
        {
            Id = "bfla-admin-takeover",
            Name = "BFLA + Admin Endpoint → Admin Access Without Auth",
            ChainedSeverity = "critical",
            Impact = "privilege-escalation",
            ProofTemplateId = "bfla-admin-endpoint",
            Links =
            [
                new() { RequiredCategory = "bfla", Role = "trigger" },
                new() { RequiredCategory = "weak-auth", Role = "amplifier", Optional = true },
                new() { RequiredCategory = "missing-rate-limit", Role = "amplifier", Optional = true }
            ],
            Description = "Broken function-level authorization ({0}) exposes admin endpoints to low-privileged users. Weak authentication ({1}) or missing rate limits ({2}) amplify the impact."
        },

        new()
        {
            Id = "mass-assignment-role-elevation-chain",
            Name = "Mass Assignment + Role Field → Unauthorized Privilege Escalation",
            ChainedSeverity = "high",
            Impact = "privilege-escalation",
            ProofTemplateId = "mass-assignment-role-elevation",
            Links =
            [
                new() { RequiredCategory = "mass-assignment", Role = "trigger" },
                new() { RequiredCategory = "weak-auth", Role = "amplifier", Optional = true }
            ],
            Description = "Mass assignment ({0}) allows injecting role or permission fields into update requests. Weak authorization checks ({1}) fail to block the escalated privilege, granting attacker admin access."
        },

        new()
        {
            Id = "idor-csrf-account-takeover",
            Name = "IDOR + CSRF → Cross-Site Modification of Other Users' Data",
            ChainedSeverity = "critical",
            Impact = "account-takeover",
            Links =
            [
                new() { RequiredCategory = "idor", Role = "trigger", Constraint = "mutating-idor" },
                new() { RequiredCategory = "csrf", Role = "enabler", Constraint = "state-changing" }
            ],
            Description = "IDOR on {0} allows accessing other users' resources by ID. CSRF on {1} lets an attacker forge cross-site requests that modify victim data without their knowledge."
        },

        new()
        {
            Id = "ssrf-idor-internal-access",
            Name = "SSRF + IDOR → Internal API Access with User Context Pivoting",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "ssrf", Role = "trigger" },
                new() { RequiredCategory = "idor", Role = "amplifier" }
            ],
            Description = "SSRF on {0} reaches internal APIs. Combined with IDOR ({1}), the attacker can iterate user contexts on internal endpoints, accessing data across multiple accounts."
        },

        new()
        {
            Id = "xss-csrf-worm-samesite-bypass",
            Name = "XSS + CSRF + SameSite=None → Self-Propagating Cross-Site Worm",
            ChainedSeverity = "critical",
            Impact = "worm",
            Links =
            [
                new() { RequiredCategory = "xss", Role = "trigger", Constraint = "stored-or-reflected-xss" },
                new() { RequiredCategory = "csrf", Role = "enabler", Constraint = "state-changing" },
                // Required: do not narrate SameSite=None when cookies are Lax/Strict.
                new() { RequiredCategory = "missing-samesite", Role = "amplifier" }
            ],
            Description = "XSS on {0} executes attacker script. CSRF gap ({1}) allows forging state-changing requests. SameSite=None cookies ({2}) ensure cross-site cookie attachment — enabling a self-propagating worm that spreads to every user who views the payload."
        },

        new()
        {
            Id = "weak-tls-credential-interception",
            Name = "Weak TLS + Credential Endpoint → Credential Interception via MITM",
            ChainedSeverity = "high",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "weak-tls", Role = "enabler" },
                new() { RequiredCategory = "credential-exposure", Role = "trigger" }
            ],
            Description = "Weak TLS configuration ({0}) allows MITM decryption of traffic. Credential endpoint ({1}) transmits secrets over this weakened channel, enabling passive interception of passwords and tokens."
        },

        // ── LLM/AI chains ──

        new()
        {
            Id = "llm-output-xss",
            Name = "Prompt Injection + Unsanitized Output → XSS via LLM",
            ChainedSeverity = "critical",
            Impact = "session-hijack",
            Links =
            [
                new() { RequiredCategory = "prompt-injection", Role = "trigger" },
                new() { RequiredCategory = "llm-output-xss", Role = "enabler" },
                new() { RequiredCategory = "missing-csp", Role = "amplifier", Optional = true }
            ],
            Description = "Prompt injection on {0} causes the LLM to output attacker-controlled HTML/JS. The application renders LLM output into a dangerous DOM sink ({1}) without sanitization. This achieves XSS through the LLM as a proxy — bypassing traditional input filters. Missing CSP ({2}) removes the last defense layer."
        },

        new()
        {
            Id = "llm-injection-data-exfil",
            Name = "Prompt Injection + Data Exfiltration → Confidential Data Theft",
            ChainedSeverity = "critical",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "prompt-injection", Role = "trigger" },
                new() { RequiredCategory = "data-exfiltration", Role = "enabler" },
                new() { RequiredCategory = "missing-csp", Role = "amplifier", Optional = true }
            ],
            Description = "Prompt injection on {0} manipulates the LLM into revealing or exfiltrating sensitive data ({1}). If the LLM has access to user data, RAG documents, or tool results, the injected prompt can extract and encode this data in its response or trigger outbound requests."
        },

        new()
        {
            Id = "indirect-injection-stored-xss",
            Name = "Indirect Prompt Injection + Output Sink → Stored XSS via RAG",
            ChainedSeverity = "critical",
            Impact = "worm",
            Links =
            [
                new() { RequiredCategory = "indirect-prompt-injection", Role = "trigger" },
                new() { RequiredCategory = "llm-output-xss", Role = "enabler" },
                new() { RequiredCategory = "missing-httponly", Role = "amplifier", Optional = true }
            ],
            Description = "Indirect prompt injection ({0}) injects malicious instructions into data the LLM consumes (files, URLs, RAG documents). When any user queries the LLM, the injected payload executes via unsanitized output rendering ({1}). This creates a stored XSS-like vector that fires for every user who triggers the LLM with poisoned context."
        },

        new()
        {
            Id = "xs-leak-side-channel-cors-read",
            Name = "XS-Leak Side Channel + CORS → Cross-Origin Read",
            ChainedSeverity = "high",
            Impact = "data-breach",
            Links =
            [
                new() { RequiredCategory = "xs-leaks", Role = "trigger" },
                new() { RequiredCategory = "xs-leaks+cors", Role = "enabler" }
            ],
            ConfirmationAnyCategories = ["xs-leaks+cors"],
            Description =
                "A confirmed XS-Leak differential ({0}) on {1} combines with permissive CORS ({2}) so a cross-site page may read response bytes via fetch(), not only infer state from side channels."
        },
    ];
}
