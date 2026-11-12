using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A07 Authentication: JWT analysis → OIDC/OAuth analysis → session-id entropy →
/// session-fixation → password-reset-weak → account-enumeration → logout-invalidation.
/// </summary>
public sealed class A07AuthnPlaybook : IPlaybook
{
    public string Id => "a07-authn";
    public string Title => "A07 Authentication";
    public string Category => "authentication-failures";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "jwt-analysis",
                Description = "Decode and analyze JWT tokens for weak algorithms, missing claims, and insecure configurations",
                HttpVerbs = "none (passive - uses captured tokens)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "session-id-entropy",
                Description = "Analyze session token entropy and predictability patterns",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "cookie-audit-authn",
                Description = "Audit session cookies for Secure, HttpOnly, SameSite",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "oidc-analysis",
                Description = "Analyze OpenID Connect provider configuration for weak grants, PKCE, and signing",
                HttpVerbs = "GET (well-known fetch)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "OIDC endpoint fetch requires safe mode" : null
            },
            new DryRunStep
            {
                Name = "session-fixation",
                Description = "Test for session fixation vulnerability (token rotation after login)",
                HttpVerbs = "GET, POST",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "password-reset-weak",
                Description = "Test password reset flow for weak token generation and replay",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "account-enumeration",
                Description = "Test login/register endpoints for username/email enumeration via response differences",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "logout-invalidation",
                Description = "Verify that logout actually invalidates the session token server-side",
                HttpVerbs = "GET, POST",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            }
        ];
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var depth = ctx.DepthProfile;

        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: JWT analysis (passive)
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
                        Id = $"a07-jwt-{findingCount}",
                        Source = "orchestrate-a07",
                        Category = ClassifyJwtCategory(issue),
                        Severity = ClassifyJwtSeverity(issue),
                        Title = $"JWT ({token.Source}): {issue}",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = $"Algorithm: {token.HeaderAlg ?? "unknown"}. {issue}",
                        Remediation = "Use strong signing algorithms (RS256/ES256). Validate all claims server-side.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
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
        ctx.Budget.AddRequests(1);

        // Step 2: Session ID entropy (passive)
        await ctx.RunStepAsync("session-id-entropy", async _ =>
        {
            var result = await ctx.Automation.AnalyzeSessionIds();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a07-entropy-{findingCount}",
                    Source = "orchestrate-a07",
                    Category = "weak-token-entropy",
                    Severity = f.Severity.ToString().ToLowerInvariant(),
                    Title = $"Session ID quality: {f.Description}",
                    Endpoint = await ctx.GetCurrentUrlAsync(),
                    Detail = $"Cookie: {f.CookieName}. {f.Description}",
                    Parameter = f.CookieName,
                    Remediation = f.Recommendation.Length > 0 ? f.Recommendation
                        : "Use CSPRNG with at least 128 bits of entropy for session tokens.",
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
        ctx.Budget.AddRequests(1);

        // Step 3: Cookie audit — session-relevant attributes
        await ctx.RunStepAsync("cookie-audit-authn", async _ =>
        {
            var result = await ctx.Automation.CheckCookieSecurity();
            int findingCount = 0;
            if (result.Findings != null)
            {
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a07-cookie-{findingCount}",
                        Source = "orchestrate-a07",
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
        ctx.Budget.AddRequests(1);

        // Step 4: OIDC provider analysis (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("oidc-analysis", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunOidcAnalysis(
                    autoDetect: true,
                    probeEndpoints: true,
                    testDynamicRegistration: true,
                    testGrantTypes: ctx.SafetyMode.AllowsWriteVerbs());
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a07-oidc-{findingCount}",
                        Source = "orchestrate-a07",
                        Category = ClassifyOidcCategory(f.Category),
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = f.Title,
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = f.Description + (f.Detail != null ? $" {f.Detail}" : ""),
                        Remediation = f.Recommendation,
                        Reference = "https://openid.net/specs/openid-connect-core-1_0.html"
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["issuer"] = result.Issuer,
                    ["endpointsProbed"] = result.EndpointProbes.Count
                };
            }, ct);
            ctx.Budget.AddRequests(Math.Max(1, 3));
        }
        else
        {
            ctx.SkipStep("oidc-analysis",
                $"OIDC endpoint fetch requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 5: Session fixation (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("session-fixation", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunSessionFixationScan(
                    new SessionFixationScanProbe.ScanOptions
                    {
                        TimeoutMs = ProbeTimeoutMs(ctx, depth.Depth),
                        MaxLoginSurfaces = depth.Depth switch
                        {
                            PlaybookDepth.Quick => 1,
                            PlaybookDepth.Deep => 3,
                            _ => 2
                        },
                        PreferBrowserLogin = depth.Depth != PlaybookDepth.Quick,
                        TryDefaultCredentials = depth.Depth != PlaybookDepth.Quick
                    }, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a07-fixation-{findingCount}",
                        Source = "orchestrate-a07",
                        Category = "session-fixation",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Session fixation: {f.CookieName} not rotated after login",
                        Endpoint = f.LoginUrl,
                        Detail = f.Detail,
                        Parameter = f.CookieName,
                        Remediation = "Regenerate session ID after successful authentication. Invalidate the pre-login token.",
                        Reference = "https://owasp.org/www-community/attacks/Session_fixation"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(Math.Max(2, findingCount));
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("session-fixation",
                $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 6: Password reset weakness (active only)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("password-reset-weak", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunPasswordResetWeakScan(
                    new PasswordResetWeakScanProbe.ScanOptions
                    {
                        TimeoutMs = ProbeTimeoutMs(ctx, depth.Depth)
                    }, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a07-reset-{findingCount}",
                        Source = "orchestrate-a07",
                        Category = "weak-password-reset",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Password reset: security question guessable ({f.Question})",
                        Endpoint = f.QuestionUrl.Length > 0 ? f.QuestionUrl : f.ResetUrl,
                        Detail = f.Detail,
                        Remediation = "Use cryptographically random, time-limited, single-use reset tokens. Avoid security questions.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(Math.Max(2, findingCount));
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("password-reset-weak",
                $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 7: Account enumeration (active only)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("account-enumeration", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                string? loginUrl = null;
                if (!string.IsNullOrWhiteSpace(request.Scope.TargetUrl)
                    && Uri.TryCreate(request.Scope.TargetUrl, UriKind.Absolute, out var targetUri)
                    && SqliLoginSweep.LooksLikeLoginPath(targetUri.AbsolutePath))
                {
                    loginUrl = request.Scope.TargetUrl;
                }

                var result = await ctx.Automation.RunAccountEnumerationScan(
                    new AccountEnumerationScanProbe.ScanOptions
                    {
                        TimeoutMs = ProbeTimeoutMs(ctx, depth.Depth),
                        // TargetUrl scopes login differential when it is a login surface;
                        // REST user-list scaffolds still run (not disabled by TargetUrl).
                        LoginUrl = loginUrl,
                        IncludeRestLeak = true,
                        MaxRestPaths = 16
                    }, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a07-enum-{findingCount}",
                        Source = "orchestrate-a07",
                        Category = "account-enumeration",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Account enumeration: {f.Signal}",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.Evidence?.ToString(),
                        Remediation = "Return identical responses for valid and invalid accounts. Use generic error messages.",
                        Reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"
                    });
                    findingCount++;
                }
                // REST scaffolds + login differentials are real HTTP work even when findings=0.
                var estimatedRequests = Math.Max(result.Findings.Count, 8);
                ctx.Budget.AddRequests(estimatedRequests);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["requestsEstimated"] = estimatedRequests
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("account-enumeration",
                $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 8: Logout invalidation (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("logout-invalidation", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunLogoutInvalidationProbe(
                    new LogoutInvalidationProbe.ProbeOptions
                    {
                        TimeoutMs = ProbeTimeoutMs(ctx, depth.Depth)
                    }, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a07-logout-{findingCount}",
                        Source = "orchestrate-a07",
                        Category = "logout-invalidation",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Session not invalidated after logout ({f.Outcome})",
                        Endpoint = f.ProtectedUrl,
                        Detail = f.Detail,
                        Remediation = "Invalidate server-side session on logout. Clear session cookies and storage.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration"
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
            // Logout invalidation always issues at least a few authenticated requests.
            ctx.Budget.AddRequests(2);
        }
        else
        {
            ctx.SkipStep("logout-invalidation",
                $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        var nextActions = BuildNextActions(ctx);

        return new PlaybookResponse
        {
            PlaybookId = Id,
            RunId = ctx.RunId,
            Scope = request.Scope,
            SafetyMode = ctx.SafetyMode.ToLabel(),
            Depth = depth.ToLabel(),
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

        bool hasWeakJwt = ctx.Findings.All.Any(f =>
            f.Category is "weak-jwt-algorithm" or "jwt-insecure-config" or "jwt-weak-secret");
        bool hasSessionIssues = ctx.Findings.All.Any(f =>
            f.Category is "session-fixation" or "weak-token-entropy" or "logout-invalidation");

        if (hasWeakJwt || hasSessionIssues)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "Authentication weaknesses may enable unauthorized access - test access control."
            });
        }

        if (hasWeakJwt)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a04-crypto",
                Rationale = "Weak JWT may indicate broader cryptographic failures - check secrets and transport."
            });
        }

        if (ctx.Findings.Count > 0)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a11-ssrf",
                Rationale = "Authentication bypass combined with SSRF can escalate to internal network access."
            });
        }

        return actions;
    }

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

    private static string ClassifyOidcCategory(string? category) => (category ?? "").ToLowerInvariant() switch
    {
        string s when s.Contains("grant") => "oidc-dangerous-grant",
        string s when s.Contains("pkce") => "oidc-weak-pkce",
        string s when s.Contains("signing") || s.Contains("algorithm") => "oidc-weak-signing",
        string s when s.Contains("registration") => "oidc-open-registration",
        string s when s.Contains("scope") => "oidc-exposed-scopes",
        _ => "oidc-misconfiguration"
    };

    private static int ProbeTimeoutMs(PlaybookContext ctx, PlaybookDepth depth)
    {
        var cap = depth switch
        {
            PlaybookDepth.Quick => 5000,
            PlaybookDepth.Deep => 15000,
            _ => 8000
        };
        return Math.Min(ctx.Budget.RemainingSeconds * 1000, cap);
    }

    private static string NormalizeCookieCategory(string? category) => (category ?? "").ToLowerInvariant() switch
    {
        string s when s.Contains("httponly") => "missing-httponly",
        string s when s.Contains("secure") => "missing-secure-flag",
        "samesitenone" or "samesitenoneinsecure" => "missing-samesite",
        string s when s.Contains("samesite") && s.Contains("none") => "missing-samesite",
        _ => "weak-cookies"
    };
}
