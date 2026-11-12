using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A04 Crypto &amp; Secrets: security-headers (HSTS) → cookie audit (Secure/HttpOnly) →
/// secrets-harvest → session-id entropy → JWT analysis → storage/IndexedDB → source-maps.
/// </summary>
public sealed class A04CryptoPlaybook : IPlaybook
{
    public string Id => "a04-crypto";
    public string Title => "A04 Crypto & Secrets";
    public string Category => "cryptographic-failures";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "security-headers-hsts",
                Description = "Check HSTS, Strict-Transport-Security, and transport-layer headers",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "cookie-audit-crypto",
                Description = "Audit cookies for Secure flag, HttpOnly, and SameSite attributes",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "secrets-harvest",
                Description = "Scan JS bundles, cookies, storage, network, and page text for leaked secrets/credentials",
                HttpVerbs = "GET (JS fetch)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "JS fetch requires safe mode" : null
            },
            new DryRunStep
            {
                Name = "session-id-entropy",
                Description = "Analyze session token entropy, predictability, and randomness quality",
                HttpVerbs = "none (passive - uses captured cookies)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "jwt-analysis",
                Description = "Decode and analyze JWT tokens for weak algorithms, missing claims, and insecure configurations",
                HttpVerbs = "none (passive - uses captured tokens)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "storage-indexeddb",
                Description = "Audit localStorage, sessionStorage, and IndexedDB for tokens, JWTs, and PII",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "source-maps",
                Description = "Detect exposed source maps that may reveal hardcoded keys in original source",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            }
        ];
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);

        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: Security headers — focus on transport-layer headers (HSTS, Secure, etc.)
        await ctx.RunStepAsync("security-headers-hsts", async _ =>
        {
            var result = await ctx.Automation.CheckSecurityHeaders();
            int findingCount = 0;
            if (result.Findings != null)
            {
                foreach (var f in result.Findings.Where(f => IsCryptoRelevantHeader(f.Header)))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a04-header-{findingCount}",
                        Source = "orchestrate-a04",
                        Category = NormalizeHeaderCategory(f.Header),
                        Severity = f.Severity.ToString().ToLowerInvariant(),
                        Title = $"Missing/weak: {f.Header}",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = f.Description,
                        Remediation = f.Recommendation,
                        Reference = f.Reference
                    });
                    findingCount++;
                }
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 2: Cookie audit — Secure, HttpOnly
        await ctx.RunStepAsync("cookie-audit-crypto", async _ =>
        {
            var result = await ctx.Automation.CheckCookieSecurity();
            int findingCount = 0;
            if (result.Findings != null)
            {
                foreach (var f in result.Findings.Where(f => IsCryptoRelevantCookie(f.Category)))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a04-cookie-{findingCount}",
                        Source = "orchestrate-a04",
                        Category = NormalizeCookieCategory(f.Category),
                        Severity = f.Severity.ToString().ToLowerInvariant(),
                        Title = $"Cookie: {f.Category} ({f.CookieName})",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = f.Description,
                        Remediation = f.Recommendation,
                        Parameter = f.CookieName
                    });
                    findingCount++;
                }
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 3: Secrets harvest (requires probes for JS bundle fetch)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("secrets-harvest", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunSecretsHarvest(
                    includeJsBundles: true,
                    includeCookiesAndStorage: true,
                    includeNetworkResponses: true,
                    includePageText: true,
                    includeSourceMaps: true);
                int findingCount = 0;
                int filteredCount = 0;
                foreach (var f in result.Findings)
                {
                    if (IsSecretsHarvestNoise(f))
                    {
                        filteredCount++;
                        continue;
                    }
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a04-secret-{findingCount}",
                        Source = "orchestrate-a04",
                        Category = SecretsCategoryMapper.ToVpxCategory(f.Category, f.Location),
                        Severity = f.Severity,
                        Title = TextEncodingFix.FixMojibake(f.Description) ?? f.Description,
                        Endpoint = f.Location,
                        Detail = TextEncodingFix.FixMojibake(f.Snippet),
                        Remediation = "Remove hardcoded secrets from client-side code. Use server-side environment variables or a secrets manager.",
                        Reference = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["filteredNoise"] = filteredCount
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("secrets-harvest",
                $"JS bundle fetch requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 4: Session ID entropy analysis (passive)
        await ctx.RunStepAsync("session-id-entropy", async _ =>
        {
            var result = await ctx.Automation.AnalyzeSessionIds();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a04-entropy-{findingCount}",
                    Source = "orchestrate-a04",
                    Category = "weak-token-entropy",
                    Severity = f.Severity.ToString().ToLowerInvariant(),
                    Title = $"Session ID quality: {f.Description}",
                    Endpoint = await ctx.GetCurrentUrlAsync(),
                    Detail = $"Cookie: {f.CookieName}. {f.Description}",
                    Parameter = f.CookieName,
                    Remediation = f.Recommendation.Length > 0 ? f.Recommendation
                        : "Use cryptographically secure random number generators (CSPRNG) with at least 128 bits of entropy for session tokens.",
                    Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                });
                findingCount++;
            }
            return new Dictionary<string, object?>
            {
                ["findings"] = findingCount,
                ["samplesAnalyzed"] = result.Samples.Count
            };
        }, ct);

        // Step 5: JWT analysis (passive — uses tokens from network log/cookies)
        await ctx.RunStepAsync("jwt-analysis", async _ =>
        {
            var result = await ctx.Automation.RunJwtAnalysis();
            int findingCount = 0;
            foreach (var token in result.Tokens)
            {
                foreach (var issue in token.Issues)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a04-jwt-{findingCount}",
                        Source = "orchestrate-a04",
                        Category = ClassifyJwtCategory(issue),
                        Severity = ClassifyJwtSeverity(issue),
                        Title = $"JWT ({token.Source}): {issue}",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = $"Algorithm: {token.HeaderAlg ?? "unknown"}. {issue}",
                        Remediation = "Use strong signing algorithms (RS256/ES256). Validate all claims server-side. Set short expiration times.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                foreach (var claim in token.SensitiveClaims)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a04-jwt-sensitive-{findingCount}",
                        Source = "orchestrate-a04",
                        Category = "jwt-sensitive-data",
                        Severity = "medium",
                        Title = $"JWT ({token.Source}): sensitive claim '{claim}'",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = $"JWT payload contains potentially sensitive claim: {claim}",
                        Remediation = "Avoid storing PII or sensitive data in JWT payloads. Use opaque tokens or encrypted JWTs (JWE)."
                    });
                    findingCount++;
                }
            }
            return new Dictionary<string, object?>
            {
                ["findings"] = findingCount,
                ["tokensAnalyzed"] = result.Tokens.Count
            };
        }, ct);

        // IndexedDB + web storage (passive)
        await ctx.RunStepAsync("storage-indexeddb", async _ =>
        {
            var result = await ctx.Automation.CheckStorageSecurity();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a04-storage-{findingCount}",
                    Source = "orchestrate-a04",
                    Category = f.Category.ToLowerInvariant() switch
                    {
                        "jwtinstorage" => "jwt-in-storage",
                        "authtokeninstorage" => "token-in-storage",
                        _ => "sensitive-storage"
                    },
                    Severity = f.Severity.ToString().ToLowerInvariant(),
                    Title = $"{f.StorageType}: {f.Key} ({f.Category})",
                    Endpoint = result.Url,
                    Detail = f.Description,
                    Evidence = f.ValueSnippet,
                    Remediation = f.Recommendation,
                    Reference = "https://owasp.org/www-community/vulnerabilities/Using_local_storage_to_store_sensitive_data"
                });
                findingCount++;
            }
            return new Dictionary<string, object?>
            {
                ["findings"] = findingCount,
                ["localStorage"] = result.LocalStorageCount,
                ["sessionStorage"] = result.SessionStorageCount,
                ["indexedDbRecords"] = result.IndexedDbRecordCount
            };
        }, ct);

        // Step 6: Source maps (passive)
        await ctx.RunStepAsync("source-maps", async _ =>
        {
            var result = await ctx.Automation.CheckSourceMaps();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a04-sourcemap-{findingCount}",
                    Source = "orchestrate-a04",
                    Category = "source-maps",
                    Severity = f.Severity.ToString().ToLowerInvariant(),
                    Title = f.Description,
                    Endpoint = f.Url ?? await ctx.GetCurrentUrlAsync(),
                    Detail = f.Detail,
                    Remediation = "Remove source maps from production deployments. Configure build tools to exclude .map files."
                });
                findingCount++;
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        var nextActions = BuildNextActions(ctx);

        return new PlaybookResponse
        {
            PlaybookId = Id,
            RunId = ctx.RunId,
            Scope = request.Scope,
            SafetyMode = ctx.SafetyMode.ToLabel(),
            Depth = ctx.DepthProfile.ToLabel(),
            StartedAt = startedAt.ToString("o"),
            FinishedAt = DateTime.UtcNow.ToString("o"),
            StepsExecuted = ctx.Steps,
            BudgetUsed = ctx.Budget.ToSummary(),
            Warnings = ctx.Warnings,
            AssertionsAdded = ctx.AssertionsAdded,
            NextActions = nextActions
        };
    }

    private static List<NextAction> BuildNextActions(PlaybookContext ctx)
    {
        var actions = new List<NextAction>();

        bool hasWeakJwt = ctx.Findings.All.Any(f => f.Category is "weak-jwt-algorithm" or "jwt-insecure-config");
        bool hasCredentials = ctx.Findings.All.Any(f => SecretsCategoryMapper.IsSecretLikeCategory(f.Category));
        bool hasWeakEntropy = ctx.Findings.All.Any(f => f.Category == "weak-token-entropy");

        if (hasWeakJwt)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "Weak JWT configuration found - test authentication flows for exploitability."
            });
        }

        if (hasCredentials)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "Exposed credentials may allow unauthorized access to protected endpoints."
            });
        }

        if (hasWeakEntropy)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "Weak session token entropy may enable session prediction attacks."
            });
        }

        return actions;
    }

    private static bool IsCryptoRelevantHeader(string? header) =>
        (header ?? "").ToLowerInvariant() is
            "strict-transport-security" or "hsts" or
            "content-security-policy" or "csp" or
            "x-content-type-options";

    private static bool IsCryptoRelevantCookie(string? category)
    {
        var c = (category ?? "").ToLowerInvariant();
        return c.Contains("secure") || c.Contains("httponly");
    }

    private static string NormalizeHeaderCategory(string? header) => (header ?? "").ToLowerInvariant() switch
    {
        "strict-transport-security" or "hsts" => "missing-hsts",
        "content-security-policy" or "csp" => "missing-csp",
        "x-content-type-options" => "missing-content-type-options",
        _ => "weak-headers"
    };

    private static string NormalizeCookieCategory(string? category) => (category ?? "").ToLowerInvariant() switch
    {
        string s when s.Contains("secure") => "missing-secure-flag",
        string s when s.Contains("httponly") => "missing-httponly",
        _ => "weak-cookies"
    };

    private static string ClassifyJwtCategory(string? issue) => (issue ?? "").ToLowerInvariant() switch
    {
        string s when s.Contains("none") || s.Contains("algorithm") => "weak-jwt-algorithm",
        string s when s.Contains("expired") || s.Contains("expir") => "jwt-expired",
        string s when s.Contains("secret") || s.Contains("key") => "jwt-weak-secret",
        _ => "jwt-insecure-config"
    };

    private static string ClassifyJwtSeverity(string issue) => issue.ToLowerInvariant() switch
    {
        string s when s.Contains("none") => "critical",
        string s when s.Contains("hs256") || s.Contains("symmetric") => "high",
        string s when s.Contains("expired") => "low",
        _ => "medium"
    };

    /// <summary>
    /// Filters known false-positive patterns from secrets harvest to reduce noise in orchestrated reports.
    /// The pipeline emits these at info/low; orchestration omits them from VPX findings.
    /// </summary>
    internal static bool IsSecretsHarvestNoise(SecretsHarvestPipeline.SecretFinding f) =>
        SecretsHarvestHeuristics.IsOrchestrationNoise(f);
}
