using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.ResourceUsage;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class McpHandler
{
private Task<object> ToolSecurityCsrf(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCsrfAsync);

private Task<object> ToolSecurityJwtAnalyze(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityJwtAnalyzeAsync);

private Task<object> ToolSecurityJwtForge(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityJwtForgeAsync);

private Task<object> ToolSecurityJwtAcceptanceSweep(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityJwtAcceptanceSweepAsync);

private Task<object> ToolSecurityJwtHeaderAbuse(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityJwtHeaderAbuseAsync);

private Task<object> ToolSecurityCookiePrefixBypass(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCookiePrefixBypassAsync);

private Task<object> ToolSecuritySessionFixationScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySessionFixationScanAsync);

private Task<object> ToolSecurityPasswordResetWeakScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityPasswordResetWeakScanAsync);

private Task<object> ToolSecurityAccountEnumerationScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityAccountEnumerationScanAsync);

private Task<object> ToolSecurityLogoutInvalidationProbe(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityLogoutInvalidationProbeAsync);

private Task<object> ToolSecurityOidcAnalyze(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityOidcAnalyzeAsync);

private Task<object> ToolSecurityOAuthFlowTest(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityOAuthFlowTestAsync);

private Task<object> ToolSecurityCookies() =>
    RenderHostSafe(default, h => h.BuildCookieAuditAsync);

private Task<object> ToolSecuritySessionId(JsonElement arguments) =>
    RenderHostSafe(arguments, h => h.BuildSessionIdAnalysisAsync);

private Task<object> ToolSecurityResetToken(JsonElement arguments) =>
    RenderHostSafe(arguments, h => h.BuildResetTokenAnalysisAsync);

private Task<object> ToolSecurityTokenEntropy(JsonElement arguments) =>
    RenderHostSafe(arguments, h => h.BuildTokenEntropyAnalysisAsync);

// SAML decode/capture/replay stay per-surface: the MCP variants expose extra modes (e.g. 'status')
// and XML-oriented text rendering distinct from the REST JSON shape, and capture/replay are stateful.

private Task<object> ToolSamlDecode(JsonElement args)
    {
        var source = GetString(args, "source") ?? "network";
        var findAll = GetBool(args, "findAll") || GetBool(args, "all");

        try
        {
            if (source.Equals("raw", StringComparison.OrdinalIgnoreCase))
            {
                var raw = GetString(args, "raw");
                if (string.IsNullOrEmpty(raw))
                    return Task.FromResult(ErrorContent("Missing required parameter: raw"));
                var encoding = GetString(args, "encoding") ?? "redirect";
                var result = SamlDecoder.DecodeRaw(raw, encoding);
                return Task.FromResult(TextContent(result.Format(includeXml: true)));
            }

            var urlFilter = GetString(args, "networkFilter") ?? GetString(args, "url");

            if (findAll)
            {
                var results = SamlDecoder.DecodeAllFromNetwork(_context.Network, urlFilter);
                if (results.Count == 0)
                {
                    var hint = urlFilter != null ? $" matching '{urlFilter}'" : "";
                    return Task.FromResult(TextContent($"No SAML messages found in network log{hint}."));
                }

                var lines = new List<string>
                {
                    $"=== Found {results.Count} SAML message(s) ===",
                    $"  Decoded successfully: {results.Count(r => r.Success)}",
                    $"  Failed to decode:     {results.Count(r => !r.Success)}",
                    ""
                };

                for (var i = 0; i < results.Count; i++)
                {
                    var r = results[i];
                    lines.Add($"--- Message {i + 1} (network entry #{r.NetworkEntryId}) ---");
                    if (r.Success)
                    {
                        lines.Add(r.Result!.Format(includeXml: false));
                    }
                    else
                    {
                        lines.Add($"  ERROR: {r.Error}");
                        lines.Add($"  URL:   {r.SourceUrl}");
                        lines.Add($"  Time:  {r.Timestamp:yyyy-MM-dd HH:mm:ss}");
                    }
                    lines.Add("");
                }

                return Task.FromResult(TextContent(string.Join(Environment.NewLine, lines)));
            }

            var single = SamlDecoder.DecodeFromNetwork(_context.Network, urlFilter);
            return Task.FromResult(TextContent(single.Format(includeXml: true)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(ErrorContent(ex.Message));
        }
    }

private Task<object> ToolSamlCapture(JsonElement args)
    {
        var mode = GetString(args, "mode") ?? "next-login";

        try
        {
            if (mode.Equals("next-login", StringComparison.OrdinalIgnoreCase))
            {
                var captureRequests = GetBool(args, "captureRequests");
                _context.SamlCapture.Arm(captureRequests);
                var extra = captureRequests
                    ? " Both outgoing SAMLRequest and incoming SAMLResponse will be captured."
                    : "";
                return Task.FromResult(TextContent(
                    "SAML capture armed. Navigate through a SAML login flow.\n" +
                    "The next SAMLResponse POST will be captured automatically." + extra + "\n" +
                    "Call browser_saml_capture with mode='status' to check, or after login completes."));
            }

            if (mode.Equals("network", StringComparison.OrdinalIgnoreCase))
            {
                var urlFilter = GetString(args, "url");
                var captured = _context.SamlCapture.CaptureFromNetworkLog(_context.Network, urlFilter);
                if (captured == null)
                    return Task.FromResult(ErrorContent(
                        "No SAML Response found in network log. Navigate through a SAML login flow first."));
                return Task.FromResult(TextContent(captured.Format(includeXml: true)));
            }

            if (mode.Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                var captured = _context.SamlCapture.GetCaptured();
                if (captured != null)
                {
                    var lines = new List<string>();
                    var capturedRequest = _context.SamlCapture.GetCapturedRequest();
                    if (capturedRequest != null)
                    {
                        lines.Add(capturedRequest.Format(includeXml: false));
                        lines.Add("");
                    }
                    lines.Add(captured.Format(includeXml: true));
                    return Task.FromResult(TextContent(string.Join(Environment.NewLine, lines)));
                }

                var isArmed = _context.SamlCapture.IsArmed;
                var status = isArmed
                    ? "SAML capture is armed and waiting for a SAML login. Navigate through the IdP flow."
                    : "No assertion captured. Use mode='next-login' to arm capture, or mode='network' to search existing log.";

                // Report captured request even if response hasn't arrived yet
                var pendingRequest = _context.SamlCapture.GetCapturedRequest();
                if (pendingRequest != null)
                    status += "\n\nOutgoing SAMLRequest already captured:\n" + pendingRequest.Format(includeXml: false);

                return Task.FromResult(TextContent(status));
            }

            if (mode.Equals("disarm", StringComparison.OrdinalIgnoreCase))
            {
                _context.SamlCapture.Disarm();
                return Task.FromResult(TextContent("SAML capture disarmed."));
            }

            return Task.FromResult(ErrorContent(
                $"Unknown mode: '{mode}'. Use 'next-login', 'network', 'status', or 'disarm'."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(ErrorContent(ex.Message));
        }
    }

private async Task<object> ToolSamlReplay(JsonElement args)
    {
        try
        {
            var captured = _context.SamlCapture.GetCaptured();

            var rawAssertion = GetString(args, "assertion");
            if (rawAssertion != null)
            {
                string xml;
                try
                {
                    xml = System.Xml.Linq.XDocument.Parse(rawAssertion).ToString();
                }
                catch
                {
                    var bytes = Convert.FromBase64String(rawAssertion);
                    xml = System.Text.Encoding.UTF8.GetString(bytes);
                }

                captured = new SamlCapturedAssertion
                {
                    RawSamlResponse = rawAssertion,
                    Xml = xml,
                    TargetUrl = GetString(args, "targetUrl") ?? "",
                    Binding = "POST",
                    Timestamp = DateTime.UtcNow,
                    Decoded = SamlDecoder.DecodeRaw(
                        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(xml)), "post")
                };
            }

            if (captured == null)
                return ErrorContent(
                    "No assertion available. Capture one first (browser_saml_capture) " +
                    "or provide an 'assertion' parameter with raw XML or Base64.");

            var targetUrl = GetString(args, "targetUrl") ?? captured.TargetUrl;
            if (string.IsNullOrEmpty(targetUrl))
                return ErrorContent("Missing required parameter: targetUrl");

            var payload = SamlCaptureManager.BuildReplay(captured,
                targetUrl: targetUrl,
                removeSignature: GetBool(args, "removeSignature"),
                changeSubject: GetString(args, "changeSubject"),
                expireAssertion: GetBool(args, "expireAssertion"),
                removeAudienceRestriction: GetBool(args, "removeAudienceRestriction"),
                changeIssuer: GetString(args, "changeIssuer"),
                extendValidityMinutes: args.TryGetProperty("extendValidityMinutes", out var evm)
                    && evm.ValueKind == System.Text.Json.JsonValueKind.Number
                    ? (int?)evm.GetInt32() : null,
                customXml: GetString(args, "customXml"));

            if (GetBool(args, "dryRun"))
            {
                var lines = new List<string>
                {
                    "=== SAML Replay (Dry Run) ===",
                    $"Target URL: {payload.TargetUrl}",
                    "",
                    "Modifications:"
                };
                foreach (var mod in payload.Modifications)
                    lines.Add($"  - {mod}");
                lines.Add("");
                lines.Add("Modified XML:");
                lines.Add(payload.ModifiedXml);
                lines.Add("=============================");
                return TextContent(string.Join(Environment.NewLine, lines));
            }

            if (SafetyGate.RequireActive(args, "SAML replay") is { } samlGateError)
                return ErrorContent(samlGateError);

            var result = await SamlCaptureManager.ExecuteReplayAsync(_context, payload);
            return TextContent(result.Format());
        }
        catch (Exception ex)
        {
            return ErrorContent(ex.Message);
        }
    }
}
