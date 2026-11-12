using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class TrowserApiServer
{
// SAML decode/capture/replay remain per-surface: capture/replay are stateful and the MCP variants
// expose different modes (e.g. 'status') and XML-oriented text rendering. The remaining auth scans
// below use shared canonical Build*Async(JsonBody) methods consumed by both REST and MCP.

private async Task HandlePostSamlDecode(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var source = body.GetString("source") ?? "network";
        var findAll = body.GetBool("findAll") || body.GetBool("all");

        try
        {
            if (source.Equals("raw", StringComparison.OrdinalIgnoreCase))
            {
                var raw = body.GetString("raw");
                if (string.IsNullOrEmpty(raw))
                {
                    await WriteError(response, 400, "Missing required field: raw (the SAML message to decode)");
                    return;
                }
                var encoding = body.GetString("encoding") ?? "redirect";
                var result = SamlDecoder.DecodeRaw(raw, encoding);
                await WriteSuccess(response, FormatSamlDecodeResult(result));
            }
            else if (findAll)
            {
                var urlFilter = body.GetString("networkFilter") ?? body.GetString("url");
                var results = SamlDecoder.DecodeAllFromNetwork(_context.Network, urlFilter);

                if (results.Count == 0)
                {
                    var hint = urlFilter != null ? $" matching '{urlFilter}'" : "";
                    await WriteSuccess(response, new
                    {
                        count = 0,
                        messages = Array.Empty<object>(),
                        summary = $"No SAML messages found in network log{hint}."
                    });
                    return;
                }

                await WriteSuccess(response, new
                {
                    count = results.Count,
                    successCount = results.Count(r => r.Success),
                    errorCount = results.Count(r => !r.Success),
                    messages = results.Select(r => r.Success
                        ? (object)new
                        {
                            success = true,
                            networkEntryId = r.NetworkEntryId,
                            data = FormatSamlDecodeResult(r.Result!)
                        }
                        : new
                        {
                            success = false,
                            networkEntryId = r.NetworkEntryId,
                            data = (object)new
                            {
                                error = r.Error,
                                sourceUrl = r.SourceUrl,
                                parameterName = r.ParameterName,
                                timestamp = r.Timestamp
                            }
                        }
                    ).ToList()
                });
            }
            else
            {
                var urlFilter = body.GetString("networkFilter") ?? body.GetString("url");
                var result = SamlDecoder.DecodeFromNetwork(_context.Network, urlFilter);
                await WriteSuccess(response, FormatSamlDecodeResult(result));
            }
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

private async Task HandlePostSamlCapture(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var mode = body.GetString("mode") ?? "next-login";

        try
        {
            if (mode.Equals("next-login", StringComparison.OrdinalIgnoreCase))
            {
                var captureRequests = body.GetBool("captureRequests");
                _context.SamlCapture.Arm(captureRequests);
                var requestMsg = captureRequests
                    ? " Both outgoing SAMLRequest and incoming SAMLResponse will be captured."
                    : "";
                await WriteSuccess(response, new
                {
                    status = "armed",
                    captureRequests,
                    message = "SAML capture armed. Navigate through a SAML login flow. " +
                              "The next SAMLResponse POST will be captured automatically." +
                              requestMsg +
                              " Call GET /api/security/saml-capture to retrieve the captured assertion."
                });
            }
            else if (mode.Equals("network", StringComparison.OrdinalIgnoreCase))
            {
                var urlFilter = body.GetString("url");
                var captured = _context.SamlCapture.CaptureFromNetworkLog(_context.Network, urlFilter);
                if (captured == null)
                {
                    await WriteError(response, 404,
                        "No SAML Response found in network log. Navigate through a SAML login flow first.");
                    return;
                }

                await WriteCapturedAssertion(response, captured);
            }
            else if (mode.Equals("disarm", StringComparison.OrdinalIgnoreCase))
            {
                _context.SamlCapture.Disarm();
                await WriteSuccess(response, new
                {
                    status = "disarmed",
                    message = "SAML capture disarmed."
                });
            }
            else
            {
                await WriteError(response, 400,
                    $"Unknown mode: '{mode}'. Use 'next-login', 'network', or 'disarm'.");
            }
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

private async Task HandleGetSamlCapture(HttpListenerResponse response)
    {
        var captured = _context.SamlCapture.GetCaptured();
        if (captured == null)
        {
            var isArmed = _context.SamlCapture.IsArmed;
            var capturedRequest = _context.SamlCapture.GetCapturedRequest();

            var data = new Dictionary<string, object?>
            {
                ["status"] = isArmed ? "armed" : "idle",
                ["captured"] = null,
                ["message"] = isArmed
                    ? "Capture is armed and waiting for a SAML login. Navigate through the IdP flow."
                    : "No assertion captured. Call POST /api/security/saml-capture with mode 'next-login' to arm, " +
                      "or mode 'network' to search the existing network log."
            };

            // May have captured a SAMLRequest even if SAMLResponse hasn't arrived yet
            if (capturedRequest != null)
                data["samlRequest"] = FormatCapturedRequest(capturedRequest);

            await WriteSuccess(response, data);
            return;
        }

        await WriteCapturedAssertion(response, captured);
    }

private async Task HandlePostSamlReplay(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        try
        {
            var captured = _context.SamlCapture.GetCaptured();

            // Allow providing a raw assertion XML or base64 instead of using the captured one
            var rawAssertion = body.GetString("assertion");
            if (rawAssertion != null)
            {
                string xml;
                try
                {
                    xml = XDocument.Parse(rawAssertion).ToString();
                }
                catch
                {
                    var bytes = Convert.FromBase64String(rawAssertion);
                    xml = Encoding.UTF8.GetString(bytes);
                }

                captured = new SamlCapturedAssertion
                {
                    RawSamlResponse = rawAssertion,
                    Xml = xml,
                    TargetUrl = body.GetString("targetUrl") ?? "",
                    Binding = "POST",
                    Timestamp = DateTime.UtcNow,
                    Decoded = SamlDecoder.DecodeRaw(
                        Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)), "post")
                };
            }

            if (captured == null)
            {
                await WriteError(response, 400,
                    "No assertion available. Capture one first (POST /api/security/saml-capture) " +
                    "or provide an 'assertion' field with raw XML or Base64.");
                return;
            }

            var targetUrl = body.GetString("targetUrl") ?? captured.TargetUrl;
            if (string.IsNullOrEmpty(targetUrl))
            {
                await WriteError(response, 400, "Missing required field: targetUrl");
                return;
            }

            var payload = SamlCaptureManager.BuildReplay(captured,
                targetUrl: targetUrl,
                removeSignature: body.GetBool("removeSignature"),
                changeSubject: body.GetString("changeSubject"),
                expireAssertion: body.GetBool("expireAssertion"),
                removeAudienceRestriction: body.GetBool("removeAudienceRestriction"),
                changeIssuer: body.GetString("changeIssuer"),
                extendValidityMinutes: body.HasProperty("extendValidityMinutes")
                    ? (int?)body.GetInt("extendValidityMinutes") : null,
                customXml: body.GetString("customXml"));

            if (body.GetBool("dryRun"))
            {
                await WriteSuccess(response, new
                {
                    dryRun = true,
                    targetUrl = payload.TargetUrl,
                    modifications = payload.Modifications,
                    modifiedXml = payload.ModifiedXml,
                    modifiedBase64 = payload.ModifiedBase64,
                    formBody = payload.FormBody
                });
                return;
            }

            var result = await SamlCaptureManager.ExecuteReplayAsync(_context, payload);

            await WriteSuccess(response, new
            {
                targetUrl = result.TargetUrl,
                modifications = result.Modifications,
                responseStatus = result.ResponseStatus,
                responseStatusText = result.ResponseStatusText,
                responseUrl = result.ResponseUrl,
                redirected = result.Redirected,
                bodyLength = result.BodyLength,
                response = result.RawResponse,
                timestamp = result.Timestamp
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

private Task HandlePostCookieAudit(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildCookieAuditAsync);

internal async Task<object> BuildCookieAuditAsync(JsonBody body) => await BuildCookieAuditPayloadAsync();

private Task HandlePostSessionIdAnalysis(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSessionIdAnalysisAsync);

internal async Task<object> BuildSessionIdAnalysisAsync(JsonBody body)
    {
        var cookieName = body.GetString("cookieName");
        var pageNetworkOnly = body.GetBool("pageNetworkOnly", false);
        var extraSamples = body.GetStringArray("samples") ?? body.GetStringArray("extraSamples");
        var minSamples = body.GetInt("minSamples", 2);

        var collected = await Security.SessionIdSampleCollector.CollectAndAnalyzeAsync(_context,
            new Security.SessionIdSampleCollector.CollectOptions
            {
                CookieName = cookieName,
                MinSamples = minSamples,
                PageNetworkOnly = pageNetworkOnly,
                ExtraSamples = extraSamples
            });

        var result = collected.Analysis;
        return new
        {
            url = result.Url,
            isClean = result.IsClean,
            minSamplesRequired = collected.MinSamplesRequired,
            minSamplesMet = collected.MinSamplesMet,
            networkSampleCount = collected.NetworkSampleCount,
            totalSampleCount = collected.TotalSampleCount,
            sampleSources = collected.SampleSources,
            recommendations = collected.Recommendations,
            samples = result.Samples.Select(s => new
            {
                cookieName = s.CookieName,
                currentValue = s.CurrentValue,
                sampleCount = s.SampleCount,
                entropyBitsPerChar = Math.Round(s.EntropyBitsPerChar, 3),
                entropyAssessment = s.EntropyAssessment,
                patterns = s.Patterns
            }).ToList(),
            findings = result.Findings.Select(f => new
            {
                cookieName = f.CookieName,
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description,
                recommendation = f.Recommendation
            }).ToList()
        };
    }

private Task HandlePostResetTokenAnalysis(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildResetTokenAnalysisAsync);

internal async Task<object> BuildResetTokenAnalysisAsync(JsonBody body)
    {
        var pageNetworkOnly = body.GetBool("pageNetworkOnly", false);
        var extraSamples = body.GetStringArray("samples") ?? body.GetStringArray("extraSamples");
        var minSamples = body.GetInt("minSamples", 2);

        var collected = await Security.ResetTokenSampleCollector.CollectAndAnalyzeAsync(_context,
            new Security.ResetTokenSampleCollector.CollectOptions
            {
                MinSamples = minSamples,
                PageNetworkOnly = pageNetworkOnly,
                ExtraSamples = extraSamples
            });

        var result = collected.Analysis;
        return new
        {
            url = result.Url,
            isClean = result.IsClean,
            minSamplesRequired = collected.MinSamplesRequired,
            minSamplesMet = collected.MinSamplesMet,
            networkSampleCount = collected.NetworkSampleCount,
            totalSampleCount = collected.TotalSampleCount,
            sampleSources = collected.SampleSources,
            resetEndpointsSeen = collected.ResetEndpointsSeen,
            recommendations = collected.Recommendations,
            samples = result.Samples.Select(s => new
            {
                tokenName = s.CookieName,
                currentValue = s.CurrentValue,
                sampleCount = s.SampleCount,
                entropyBitsPerChar = Math.Round(s.EntropyBitsPerChar, 3),
                entropyAssessment = s.EntropyAssessment,
                patterns = s.Patterns
            }).ToList(),
            findings = result.Findings.Select(f => new
            {
                tokenName = f.CookieName,
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description,
                recommendation = f.Recommendation
            }).ToList()
        };
    }

private Task HandlePostTokenEntropyAnalysis(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildTokenEntropyAnalysisAsync);

internal async Task<object> BuildTokenEntropyAnalysisAsync(JsonBody body)
    {
        var collected = await Security.TokenEntropySampleCollector.CollectAndAnalyzeAsync(_context,
            ParseTokenEntropyOptions(body));
        return FormatTokenEntropyPayload(collected);
    }

private Task HandlePostSecurityCsrf(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCsrfAsync);

internal async Task<object> BuildSecurityCsrfAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "CSRF testing replays captured requests with modified tokens against the real server");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var maxEndpoints = body.GetInt("maxEndpoints", 5);
        var maxUnprotected = body.GetInt("maxUnprotected", 10);
        var includeGet = body.GetBool("includeGet", false);
        var includeRefererBypass = body.GetBool("includeRefererBypass", true);
        var maxRefererEndpoints = body.GetInt("maxRefererEndpoints", 5);
        var includeJsonApiProbing = body.GetBool("includeJsonApiProbing", true);
        var maxJsonApiProbes = body.GetInt("maxJsonApiProbes", 10);
        var includeCustomHeaderProbes = body.GetBool("includeCustomHeaderProbes", true);
        var maxCustomHeaderProbes = body.GetInt("maxCustomHeaderProbes", 5);
        var includeSameSiteAnalysis = body.GetBool("includeSameSiteAnalysis", true);
        var includeCrossSiteProof = body.GetBool("includeCrossSiteProof", false);
        var maxCrossSiteProbes = body.GetInt("maxCrossSiteProbes", 3);
        var attackerSite = body.GetString("attackerSite") ?? "cross-site";
        var hostFilter = body.GetString("host");
        if (hostFilter == null && !body.GetBool("allHosts", false))
        {
            var pageUrl = await _context.GetCurrentUrl();
            if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
                hostFilter = pageUri.Host;
        }
        var result = await _context.RunCsrfTest(maxEndpoints, maxUnprotected, includeGet, hostFilter,
            includeRefererBypass, maxRefererEndpoints, includeJsonApiProbing, maxJsonApiProbes,
            includeCustomHeaderProbes, maxCustomHeaderProbes, includeSameSiteAnalysis,
            includeCrossSiteProof, maxCrossSiteProbes, attackerSite);

        var correlations = body.GetBool("includeCorrelations", true)
            ? await SecurityFindingCorrelator.CorrelateForCsrfScanAsync(
                _context,
                result,
                includeSecretsHarvest: body.GetBool("correlateSecretsHarvest", true),
                includeXss: body.GetBool("correlateXss", true),
                timeoutMs: body.GetInt("correlationTimeoutMs", 10000))
            : [];

        return new
        {
            endpointsTested = result.EndpointsTested,
            unprotectedCount = result.UnprotectedCount,
            vulnerableCount = result.VulnerableCount,
            message = result.Message,
            hostFilter,
            includeGet,
            includeRefererBypass,
            getFormFindingsCount = result.GetFormFindingsCount,
            refererEndpointsTested = result.RefererEndpointsTested,
            refererBypassCount = result.RefererBypassCount,
            customHeaderProbesRun = result.CustomHeaderProbesRun,
            sameSiteContext = result.SameSiteContext == null ? null : new
            {
                crossSiteCookieRisk = result.SameSiteContext.CrossSiteCookieRisk,
                summary = result.SameSiteContext.Summary,
                sessionCookies = result.SameSiteContext.SessionCookies.Select(c => new
                {
                    c.Name, c.SameSite, c.Secure, c.HttpOnly
                })
            },
            stateChangingGetHints = result.StateChangingGetHints.Select(h => new { h.Url, h.Reason }).ToList(),
            scenarios = result.Scenarios.Select(s => new
            {
                url = s.Url,
                path = s.Path,
                endpoint = s.Url,
                method = s.Method,
                testType = s.TestType,
                severity = s.Severity,
                description = s.Description,
                originalStatus = s.OriginalStatus,
                testStatus = s.TestStatus,
                vulnerable = s.Vulnerable,
                error = s.Error,
                tokenLocation = s.TokenLocation,
                mutationIndicators = s.MutationIndicators,
                formFields = s.FormFields,
            }).ToList(),
            refererFindings = result.RefererFindings.Select(f => new
            {
                url = f.Url,
                path = f.Path,
                method = f.Method,
                hasCsrfToken = f.HasCsrfToken,
                refererValidationDetected = f.RefererValidationDetected,
                probes = f.Probes.Select(p => new
                {
                    probeName = p.ProbeName,
                    refererValue = p.RefererValue,
                    classification = p.Classification,
                    baselineStatus = p.BaselineStatus,
                    probeStatus = p.ProbeStatus,
                    vulnerable = p.Vulnerable,
                    severity = p.Severity,
                    description = p.Description,
                    error = p.Error,
                }).ToList(),
            }).ToList(),
            correlations = correlations.Select(c => new
            {
                id = c.Id,
                severity = c.Severity,
                title = c.Title,
                description = c.Description,
                relatedTools = c.RelatedTools,
                fieldName = c.FieldName,
                url = c.Url,
            }).ToList(),
            jsonApiProbesRun = result.JsonApiProbesRun,
            jsonApiHints = result.JsonApiHints.Select(h => new
            {
                source = h.Source,
                url = h.Url,
                method = h.Method,
                evidence = h.Evidence,
            }).ToList(),
            includeCrossSiteProof,
            maxCrossSiteProbes,
            attackerSite,
            crossSiteProof = result.CrossSiteProof == null ? null : new
            {
                runId = result.CrossSiteProof.RunId,
                attackerOrigin = result.CrossSiteProof.AttackerOrigin,
                probesRun = result.CrossSiteProof.ProbesRun,
                credentialDelivery = result.CrossSiteProof.CredentialDelivery,
                browserModel = result.CrossSiteProof.BrowserModel.ToApiObject(),
                proofs = result.CrossSiteProof.Proofs.Select(p => new
                {
                    technique = p.Technique,
                    url = p.Url,
                    path = p.Path,
                    method = p.Method,
                    triggered = p.Triggered,
                    observedStatus = p.ObservedStatus,
                    observedResourceType = p.ObservedResourceType,
                    cookieDelivery = p.CookieDelivery,
                    vulnerable = p.Vulnerable,
                    severity = p.Severity,
                    description = p.Description,
                }).ToList()
            },
        };
    }

private Task HandlePostSecuritySessionFixationScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySessionFixationScanAsync);

internal async Task<object> BuildSecuritySessionFixationScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Session-fixation scan performs login attempts");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            return await _context.RunSessionFixationScan(new Security.SessionFixationScanProbe.ScanOptions
            {
                LoginUrl = body.GetString("loginUrl"),
                Username = body.GetString("username"),
                Password = body.GetString("password"),
                CookieName = body.GetString("cookieName"),
                BodyTemplate = body.GetString("bodyTemplate") ?? body.GetString("body"),
                ContentType = body.GetString("contentType"),
                UsernameField = body.GetString("usernameField"),
                PasswordField = body.GetString("passwordField"),
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                TryDefaultCredentials = body.GetBool("tryDefaultCredentials", true),
                PreferBrowserLogin = body.GetBool("preferBrowserLogin", true),
                RegisterChainFindings = body.GetBool("registerChainFindings", true)
            });
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityPasswordResetWeakScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityPasswordResetWeakScanAsync);

internal async Task<object> BuildSecurityPasswordResetWeakScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Password-reset-weak scan may change account passwords");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            return await _context.RunPasswordResetWeakScan(new Security.PasswordResetWeakScanProbe.ScanOptions
            {
                Email = body.GetString("email"),
                ResetUrl = body.GetString("resetUrl"),
                QuestionUrl = body.GetString("questionUrl"),
                NewPassword = body.GetString("newPassword") ?? "TrowserReset1!",
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                MaxAttempts = body.GetInt("maxAttempts", 12),
                ConfirmDestructive = body.GetBool("confirmDestructive", false),
                RegisterChainFindings = body.GetBool("registerChainFindings", true)
            });
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityAccountEnumerationScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityAccountEnumerationScanAsync);

internal async Task<object> BuildSecurityAccountEnumerationScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Account-enumeration scan probes login/register endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            return await _context.RunAccountEnumerationScan(new Security.AccountEnumerationScanProbe.ScanOptions
            {
                LoginUrl = body.GetString("loginUrl"),
                ValidUsername = body.GetString("validUsername"),
                RegisterUrl = body.GetString("registerUrl"),
                BodyTemplate = body.GetString("bodyTemplate") ?? body.GetString("body"),
                ContentType = body.GetString("contentType"),
                UsernameField = body.GetString("usernameField"),
                PasswordField = body.GetString("passwordField"),
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                MaxRestPaths = body.GetInt("maxRestPaths", 12),
                IncludeRestLeak = body.GetBool("includeRestLeak", true),
                IncludeLoginDifferential = body.GetBool("includeLoginDifferential", true),
                IncludeRegisterProbe = body.GetBool("includeRegisterProbe", true),
                RegisterChainFindings = body.GetBool("registerChainFindings", true)
            });
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityLogoutInvalidationProbe(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLogoutInvalidationProbeAsync);

internal async Task<object> BuildSecurityLogoutInvalidationProbeAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Logout-invalidation probe calls logout then replays session cookies");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            return await _context.RunLogoutInvalidationProbe(new Security.LogoutInvalidationProbe.ProbeOptions
            {
                LogoutUrl = body.GetString("logoutUrl"),
                LogoutMethod = body.GetString("logoutMethod"),
                LogoutBody = body.GetString("logoutBody"),
                LogoutContentType = body.GetString("logoutContentType"),
                ProtectedUrl = body.GetString("protectedUrl"),
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                RegisterChainFindings = body.GetBool("registerChainFindings", true)
            });
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityJwtAnalyze(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityJwtAnalyzeAsync);

internal async Task<object> BuildSecurityJwtAnalyzeAsync(JsonBody body)
    {
        // Passive decode + cookie/storage harvest — no server probes. Active mode not required.
        List<string>? extra = null;
        var one = body.GetString("token");
        if (!string.IsNullOrWhiteSpace(one)) (extra = new List<string>()).Add(one!);
        var many = body.GetStringArray("tokens");
        if (many is { Count: > 0 })
        {
            extra ??= new List<string>();
            foreach (var t in many)
            {
                if (!string.IsNullOrWhiteSpace(t)) extra.Add(t!);
            }
        }

        var result = await Security.HttpSecurityProbes.RunJwtAnalyzeAsync(_context, extra);
        var list = result.Tokens.Select(t => new
        {
            t.Source,
            t.Raw,
            algorithm = t.HeaderAlg,
            header = t.HeaderJson,
            payload = t.PayloadJson,
            t.Issues,
            sensitiveClaims = t.SensitiveClaims,
            expiresUtc = t.ExpiresUtc
        }).ToList();
        return new
        {
            count = list.Count,
            tokens = list,
            findings = list
        };
    }

private Task HandlePostSecurityJwtForge(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityJwtForgeAsync);

internal Task<object> BuildSecurityJwtForgeAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "JWT forging is for authorized security testing");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var baseToken = body.GetString("baseToken");
        if (string.IsNullOrWhiteSpace(baseToken))
            throw new ApiCommandException(400, "baseToken is required (JWS format: header.payload.signature).");

        var stripSignature = body.GetBool("stripSignature");
        var stripExplicit = body.HasProperty("stripSignature");
        JsonElement? modifications = null;
        if (body.HasProperty("modifications") && body.GetJsonElement("modifications") is { } mods)
            modifications = mods;

        string? algorithmNote = null;
        var algorithm = body.GetString("algorithm");
        if (!string.IsNullOrWhiteSpace(algorithm))
        {
            var applied = Security.HttpSecurityProbes.ApplyTopLevelAlgorithm(
                modifications, algorithm, stripSignature, stripExplicit);
            modifications = applied.Modifications;
            stripSignature = applied.StripSignature;
            algorithmNote = applied.Note;
        }

        try
        {
            var result = Security.HttpSecurityProbes.ForgeJwt(baseToken, modifications, stripSignature);
            var notes = result.Notes.ToList();
            if (!string.IsNullOrEmpty(algorithmNote))
                notes.Insert(0, algorithmNote);
            return Task.FromResult<object>(new
            {
                token = result.Token,
                header = result.HeaderJson,
                payload = result.PayloadJson,
                signatureStripped = result.SignatureStripped,
                notes
            });
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityJwtAcceptanceSweep(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityJwtAcceptanceSweepAsync);

internal async Task<object> BuildSecurityJwtAcceptanceSweepAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "JWT acceptance sweep sends unauthenticated requests");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var endpoints = ParseJwtSweepEndpoints(body);

        bool? includeNetworkLog = null;
        if (body.HasProperty("includeNetworkLog"))
            includeNetworkLog = body.GetBool("includeNetworkLog", endpoints.Count == 0);

        return await Security.JwtAcceptanceSweep.RunAsync(_context, new Security.JwtAcceptanceSweep.SweepOptions
        {
            Host = body.GetString("host"),
            MaxEndpoints = body.GetInt("maxEndpoints", 15),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            BaseToken = body.GetString("baseToken") ?? body.GetString("token"),
            Token = body.GetString("token"),
            IncludeUnauthenticatedOnly = body.GetBool("includeUnauthenticatedOnly", false),
            IncludeAlgVariants = body.GetBool("includeAlgVariants", true),
            Verbose = body.GetBool("verbose", false),
            Endpoints = endpoints.Count > 0 ? endpoints : null,
            IncludeNetworkLog = includeNetworkLog,
            CookieName = body.GetString("cookieName")
        });
    }

    /// <summary>
    /// Accepts <c>endpoints</c> as string URLs or <c>{ "url": "..." }</c> objects.
    /// </summary>
    private static List<string> ParseJwtSweepEndpoints(JsonBody body)
    {
        var result = new List<string>();
        var arr = body.GetArray("endpoints");
        if (arr == null) return result;

        foreach (var doc in arr)
        {
            var el = doc.RootElement;
            if (el.ValueKind == JsonValueKind.String)
            {
                var s = el.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                    result.Add(s.Trim());
            }
            else if (el.ValueKind == JsonValueKind.Object
                     && el.TryGetProperty("url", out var u)
                     && u.ValueKind == JsonValueKind.String)
            {
                var s = u.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                    result.Add(s.Trim());
            }
        }

        return result
            .Where(s => !string.IsNullOrEmpty(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

private Task HandlePostSecurityJwtHeaderAbuse(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityJwtHeaderAbuseAsync);

internal async Task<object> BuildSecurityJwtHeaderAbuseAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "JWT header abuse probe sends forged JWTs");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        return await Security.JwtHeaderAbuseProbe.RunAsync(_context, new Security.JwtHeaderAbuseProbe.ProbeOptions
        {
            Host = body.GetString("host"),
            BaseToken = body.GetString("baseToken") ?? body.GetString("token"),
            MaxEndpoints = body.GetInt("maxEndpoints", 10),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            RegisterChainFindings = body.GetBool("registerChainFindings", true)
        });
    }

private Task HandlePostSecurityCookiePrefixBypass(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCookiePrefixBypassAsync);

internal async Task<object> BuildSecurityCookiePrefixBypassAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Cookie prefix bypass probe replays manipulated Cookie headers");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        return await Security.CookiePrefixBypassChecker.RunAsync(_context, new Security.CookiePrefixBypassChecker.BypassOptions
        {
            PageUrl = body.GetString("pageUrl"),
            TimeoutMs = body.GetInt("timeoutMs", 12000),
            RegisterChainFindings = body.GetBool("registerChainFindings", true)
        });
    }

private Task HandlePostSecurityOidcAnalyze(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityOidcAnalyzeAsync);

internal async Task<object> BuildSecurityOidcAnalyzeAsync(JsonBody body)
    {
        var testDynamicRegistration = body.GetBool("testDynamicRegistration");
        if (testDynamicRegistration)
        {
            var dcrGate = SafetyGate.RequireActive(body, "Dynamic client registration probe POSTs to the registration endpoint");
            if (dcrGate != null)
                throw new ApiCommandException(400, dcrGate.Value);
        }

        var options = new Security.OidcAnalyzer.OidcOptions
        {
            Issuer = body.GetString("issuer"),
            AutoDetect = body.GetBool("autoDetect", true),
            ProbeEndpoints = body.GetBool("probeEndpoints", true),
            TestDynamicRegistration = testDynamicRegistration,
            TestGrantTypes = body.GetBool("testGrantTypes"),
            ClientId = body.GetString("clientId"),
            ValidateRpTokens = body.GetBool("validateRpTokens", true),
            TimeoutMs = body.GetInt("timeoutMs", 20000)
        };

        try
        {
            var result = await Security.OidcAnalyzer.RunAsync(_context, options);
            return new
            {
                timestamp = result.Timestamp,
                issuer = result.Issuer,
                configurationUrl = result.ConfigurationUrl,
                configurationFound = result.ConfigurationFound,
                totalFindings = result.Findings.Count,
                findings = result.Findings.Select(f => new
                {
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Description,
                    f.Recommendation,
                    f.Detail
                }),
                summary = new
                {
                    result.Summary.Critical,
                    result.Summary.High,
                    result.Summary.Medium,
                    result.Summary.Low,
                    result.Summary.Info,
                    grantTypesSupported = result.Summary.GrantTypesSupported,
                    scopesSupported = result.Summary.ScopesSupported,
                    signingAlgorithms = result.Summary.SigningAlgorithms,
                    endpointsDiscovered = result.Summary.EndpointsDiscovered
                },
                endpointProbes = result.EndpointProbes.Select(p => new
                {
                    p.Name,
                    p.Url,
                    p.Reachable,
                    p.StatusCode,
                    p.Error
                }),
                grantTypeProbes = result.GrantTypeProbes.Count > 0 ? result.GrantTypeProbes.Select(p => new
                {
                    p.GrantType,
                    p.ClientId,
                    p.TokenEndpoint,
                    p.StatusCode,
                    p.ErrorCode,
                    p.ErrorDescription,
                    p.Verdict,
                    p.Error
                }) : null,
                session = result.Session == null ? null : new
                {
                    observed = result.Session.Observed,
                    binding = result.Session.Binding,
                    issuer = result.Session.Issuer,
                    loginUi = result.Session.LoginUi,
                    appHost = result.Session.AppHost,
                    sessionCookie = result.Session.SessionCookieName,
                    tokensVisibleInBrowser = result.Session.TokensVisibleInBrowser,
                    evidence = result.Session.Evidence,
                    claimTypes = result.Session.ClaimTypes,
                    findings = result.Session.Findings.Select(f => new
                    {
                        f.Severity,
                        f.Title,
                        f.Description,
                        f.Recommendation
                    }),
                    notTestable = result.Session.NotTestable,
                    nextActions = result.Session.NextActions
                },
                dossier = MapDossier(result.Dossier),
                rpTokenFindings = result.RpTokenFindings.Select(f => new
                {
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Description,
                    f.Recommendation,
                    artifact = f.ArtifactLocation
                }),
                errors = result.Errors,
                elapsedMs = result.ElapsedMs
            };
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"OIDC analysis failed: {ex.Message}");
        }
    }

    private static object? MapDossier(Security.OidcSessionDossier.DossierResult? dossier) =>
        dossier == null ? null : new
        {
            binding = dossier.Binding,
            issuer = dossier.Issuer,
            clientId = dossier.ClientId,
            redirectUri = dossier.RedirectUri,
            responseType = dossier.ResponseType,
            scope = dossier.Scope,
            pkceMethod = dossier.PkceMethod,
            noncePresent = dossier.NoncePresent,
            statePresent = dossier.StatePresent,
            tokenEndpoint = dossier.TokenEndpoint,
            userinfoEndpoint = dossier.UserinfoEndpoint,
            authorizationEndpoint = dossier.AuthorizationEndpoint,
            configurationFound = dossier.ConfigurationFound,
            configurationUrl = dossier.ConfigurationUrl,
            artifacts = dossier.Artifacts.Select(a => new { kind = a.Kind, location = a.Location }),
            notTestable = dossier.NotTestable,
            nextActions = dossier.NextActions
        };

private Task HandlePostSecurityOAuthFlowTest(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityOAuthFlowTestAsync);

internal async Task<object> BuildSecurityOAuthFlowTestAsync(JsonBody body)
    {
        var passiveOnly = SafetyGate.OAuthFlowTestIsPassiveOnly(body);

        if (!passiveOnly)
        {
            if (SafetyGate.RequireActive(body, "Active OAuth flow probes send manipulated authorize and token requests")
                is { } gateError)
            {
                throw new ApiCommandException(400, gateError with
                {
                    Message = gateError.Message +
                              " Set passiveOnly: true (or safetyMode: \"passive\") for network-log analysis only."
                });
            }
        }
        var options = new Security.OAuthFlowTester.OAuthFlowOptions
        {
            AuthorizationUrl = body.GetString("authorizationUrl"),
            TokenEndpoint = body.GetString("tokenEndpoint"),
            ClientId = body.GetString("clientId"),
            RedirectUri = body.GetString("redirectUri"),
            Issuer = body.GetString("issuer"),
            AutoDetect = body.GetBool("autoDetect", true),
            PassiveOnly = passiveOnly,
            CheckBrowserLeaks = body.GetBool("checkBrowserLeaks", true),
            SkipRedirectUriTests = body.GetBool("skipRedirectUriTests"),
            SkipStateTests = body.GetBool("skipStateTests"),
            SkipPkceTests = body.GetBool("skipPkceTests"),
            SkipScopeTests = body.GetBool("skipScopeTests"),
            SkipResponseTypeTests = body.GetBool("skipResponseTypeTests"),
            SkipTokenExchange = body.GetBool("skipTokenExchange"),
            UseCanaryTokenExchange = body.GetBool("useCanaryTokenExchange"),
            HoldCallback = body.GetBool("holdCallback"),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            FlowBreaker = body.GetBool("flowBreaker"),
            MaxBrowserSteps = Math.Clamp(body.GetInt("maxBrowserSteps", 2), 1, 5),
            FlowBreakerMutations = body.GetStringArray("mutations") is { Count: > 0 } muts
                ? muts : null
        };

        try
        {
            var result = await Security.OAuthFlowTester.RunAsync(_context, options);
            return new
            {
                timestamp = result.Timestamp,
                flowsCaptured = result.CapturedFlows.Count,
                capturedFlows = result.CapturedFlows.Select(f => new
                {
                    f.ClientId,
                    f.RedirectUri,
                    f.State,
                    f.CodeChallenge,
                    f.CodeChallengeMethod,
                    f.Scope,
                    f.ResponseType,
                    authorizationUrl = f.AuthorizationUrl,
                    tokenEndpoint = f.TokenEndpoint,
                    callbackUrls = f.CallbackUrls
                }),
                totalFindings = result.Findings.Count,
                findings = result.Findings.Select(f => new
                {
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Description,
                    f.Recommendation,
                    f.Detail
                }),
                probes = result.Probes.Select(p => new
                {
                    p.Test,
                    p.Url,
                    p.StatusCode,
                    p.Location,
                    p.Verdict,
                    p.Notes
                }),
                summary = new
                {
                    result.Summary.Critical,
                    result.Summary.High,
                    result.Summary.Medium,
                    result.Summary.Low,
                    result.Summary.Info,
                    result.Summary.FlowsCaptured,
                    result.Summary.ProbesRun
                },
                errors = result.Errors,
                authSignals = result.AuthSignals.Select(s => new
                {
                    s.Protocol,
                    s.Binding,
                    s.Evidence,
                    sampleUrl = s.SampleUrl,
                    recommendedTools = s.RecommendedTools
                }),
                nextActions = result.NextActions,
                dossier = MapDossier(result.Dossier),
                elapsedMs = result.ElapsedMs
            };
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"OAuth flow test failed: {ex.Message}");
        }
    }
}
