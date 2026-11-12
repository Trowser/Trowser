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
private Task<object> ToolSecurity() =>
    RenderHostSafe(default, h => h.BuildSecurityOverviewAsync);

private Task<object> ToolSecurityJsLibraries() =>
    RenderHostSafe(default, h => h.BuildSecurityJsLibrariesAsync);

private Task<object> ToolSecurityHeaders() =>
    RenderHostSafe(default, h => h.BuildSecurityHeadersAuditAsync);

private Task<object> ToolSecurityCors(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCorsAsync);

private Task<object> ToolSecurityForcedErrorScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityForcedErrorScanAsync);

private Task<object> ToolSecurityDiscover(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityDiscoverAsync);

private Task<object> ToolSecurityCrawlLight(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCrawlLightAsync);

private Task<object> ToolSecurityApiInventory(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityApiInventoryAsync);

private Task<object> ToolSecurityClickjackTest(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityClickjackTestAsync);

private async Task<object> ToolSecuritySseAudit(JsonElement args)
    {
        var checks = GetStringArray(args, "checks")?.ToHashSet(StringComparer.OrdinalIgnoreCase)
                     ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "all" };

        var options = new Trowser.Security.Sse.SseAuditor.AuditOptions
        {
            ConnectionId = args.TryGetProperty("connectionId", out var cid) && cid.TryGetInt32(out var id) && id > 0 ? id : null,
            Checks = checks,
            MaxEventsProbe = GetInt(args, "maxEvents", 50),
            MaxMsProbe = GetInt(args, "maxMs", 5000),
            SafetyMode = SafetyGate.Resolve(args),
            UseCapturedShapeHeaders = GetBool(args, "useCapturedShapeHeaders", true)
        };

        var result = await _context.RunSseAuditAsync(options, _context.PeerRegistry);
        return TextContent(JsonSerializer.Serialize(result, CompactJson));
    }

private async Task<object> ToolSecurityWebSocketAuthz(JsonElement args)
    {
        if (_context.PeerRegistry == null)
            return ErrorContent("PeerRegistry is not available in this context.");

        var peers = new List<string>();
        var peer = GetString(args, "peer");
        if (!string.IsNullOrWhiteSpace(peer)) peers.Add(peer);

        int? frameId = args.TryGetProperty("frameId", out var fid) && fid.TryGetInt32(out var frame) && frame > 0
            ? frame
            : null;
        var connectionId = args.TryGetProperty("connectionId", out var cid) && cid.TryGetInt32(out var id) ? id : 0;

        var report = await new WebSocketAuthzTester(_context, _context.PeerRegistry).RunAsync(new WebSocketAuthzRequest
        {
            ConnectionId = connectionId,
            FrameId = frameId,
            Message = GetString(args, "message"),
            Peers = peers.Count > 0 ? peers : null,
            ResponseWaitMs = GetInt(args, "responseWaitMs", 800),
            SafetyMode = SafetyGate.Resolve(args)
        });

        if (!report.Ok)
            return ErrorContent(report.Error ?? "WebSocket authz check failed.");

        WebSocketAuthzRecorder.Record(_context, report);
        return TextContent(JsonSerializer.Serialize(report, CompactJson));
    }

private async Task<object> ToolSecurityWebSocketFuzz(JsonElement args)
    {
        if (SafetyGate.RequireActive(args, "WebSocket fuzz") is { } gateError)
            return ErrorContent(gateError);

        int? connectionId = args.TryGetProperty("connectionId", out var cidEl) && cidEl.TryGetInt32(out var cid) && cid > 0
            ? cid
            : null;

        var options = new WebSocketFuzzOptions
        {
            ConnectionId = connectionId,
            PayloadSets = GetStringArray(args, "payloadSets")?.ToList(),
            MaxConnections = GetInt(args, "maxConnections", 3),
            MaxPayloadsPerSet = GetInt(args, "maxPayloadsPerSet", 8),
            MaxMessageTypes = GetInt(args, "maxMessageTypes", 6),
            ResponseWaitMs = GetInt(args, "responseWaitMs", 500),
            WrapJsonPayloads = GetBool(args, "wrapJsonPayloads", true),
            IncludeMessageTypeMatrix = GetBool(args, "includeMessageTypeMatrix", true),
            PayloadProfile = PayloadProfileExtensions.Parse(GetString(args, "payloadProfile")),
        };

        try
        {
            var result = await _context.RunWebSocketFuzz(options);
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== WebSocket Fuzz ===");
            sb.AppendLine(result.Message);
            if (result.SkippedReason != null)
                sb.AppendLine($"Skipped: {result.SkippedReason}");
            sb.AppendLine($"Connections: {result.ConnectionsFuzzed}, payloads sent: {result.PayloadsSent}");
            foreach (var f in result.Findings)
            {
                sb.AppendLine($"  [{f.Severity}/{f.Confidence}] {f.Indicator} ({f.PayloadSet})");
                sb.AppendLine($"    {f.Detail}");
                if (!string.IsNullOrEmpty(f.ReceivedSnippet))
                    sb.AppendLine($"    Received: {f.ReceivedSnippet}");
            }
            sb.AppendLine("======================");
            return TextContent(sb.ToString());
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

private Task<object> ToolSecurityMethods(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityMethodsAsync);

private Task<object> ToolSecurityNextJsRscScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityNextJsRscScanAsync);

private Task<object> ToolSecurityRaceConditionScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityRaceConditionScanAsync);

private Task<object> ToolSecurityCaptchaReplayScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCaptchaReplayScanAsync);

private Task<object> ToolSecurityRateLimitAudit(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityRateLimitAuditAsync);

private Task<object> ToolSecurityReDoSScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityReDoSScanAsync);

private Task<object> ToolSecurityBodySizeLimitScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityBodySizeLimitScanAsync);

private Task<object> ToolSecurityCostlyOperations(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityCostlyOperationsAsync);

private Task<object> ToolSecuritySwaggering(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySwaggeringAsync);

private Task<object> ToolSecurityWorkflowSkipScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityWorkflowSkipScanAsync);

private Task<object> ToolSecurityFailOpenScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityFailOpenScanAsync);

private Task<object> ToolSecurityAuthControlIdentifier(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityAuthControlIdentifierAsync);

private Task<object> ToolSecurityMissingParameterScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityMissingParameterScanAsync);

private Task<object> ToolSecurityAuthBypassPivot(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityAuthBypassPivotAsync);

private Task<object> ToolSecurityRestScaffold(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityRestScaffoldAsync);

private Task<object> ToolSecurityPathFilterBypass(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityPathFilterBypassAsync);

private Task<object> ToolSecurityHarvestIds(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityHarvestIdsAsync);

private Task<object> ToolSecurityBruteForce(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityBruteForceAsync);

private Task<object> ToolSecurityIdorScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityIdorScanAsync);

private Task<object> ToolSecurityMassAssignmentScan(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityMassAssignmentScanAsync);

private Task<object> ToolSecurityMassAssignmentPatch(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityMassAssignmentPatchAsync);

private Task<object> ToolSecurityMassAssignmentRegister(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityMassAssignmentRegisterAsync);

private Task<object> ToolSecurityBflaProbe(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityBflaProbeAsync);

private Task<object> ToolSecurityResponseFieldDiff(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityResponseFieldDiffAsync);

private Task<object> ToolSecurityAutoScan(JsonElement args)
{
    if (Host == null)
        return Task.FromResult<object>(ErrorContent(
            "This tool requires the REST API server to be running. " +
            "Enable the API server in Settings or restart Trowser with --api-port."));

    using var stream = new MemoryStream();
    using (var writer = new Utf8JsonWriter(stream))
    {
        writer.WriteStartObject();
        if (args.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in args.EnumerateObject())
                prop.WriteTo(writer);
        }
        writer.WriteBoolean("mcpBudgetCap", true);
        writer.WriteEndObject();
    }

    using var doc = JsonDocument.Parse(stream.ToArray());
    return RenderHostAsync(doc.RootElement, Host.BuildSecurityAutoScanAsync);
}

private Task<object> ToolSecuritySecretsHarvest(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecuritySecretsHarvestAsync);

private Task<object> ToolSecurityGraphqlAnalyze(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityGraphqlAnalyzeAsync);

private Task<object> ToolSecurityVerify(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityVerifyAsync);

private Task<object> ToolSecurityVerifyWorkflow(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityVerifyWorkflowAsync);

private Task<object> ToolSecurityChainProve(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildSecurityChainProveAsync);

private Task<object> ToolReproCapture(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildReproCaptureAsync);

private Task<object> ToolReproVerify(JsonElement args) =>
    RenderHostSafe(args, h => h.BuildReproVerifyAsync);

private async Task<object> ToolSecurityChainAnalyze(JsonElement args)
    {
        if (ChainCatalog == null)
            return ErrorContent("Chain pattern catalog not initialized.");

        var jb = JsonBody.FromToolArguments(args);
        var minChainedSeverity = jb.GetString("minChainedSeverity")?.Trim().ToLowerInvariant();
        if (minChainedSeverity is not (null or "critical" or "high" or "medium" or "low"))
            minChainedSeverity = null;

        var includePartial = jb.GetBool("includePartial", true);
        string? pageUrl = null;
        try { pageUrl = await _context.GetCurrentUrl(); } catch { /* best effort */ }

        var thirdParty = await _context.CheckThirdParty();
        var externalWithoutSri = thirdParty.Resources
            .Where(r => !r.HasSri && r.Type is "script" or "stylesheet")
            .ToList();
        var missingSriUrls = externalWithoutSri
            .Select(r => r.Url)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .ToList();

        var findings = ChainAnalysisService.CollectFindings(_context, SessionLogger);
        var result = ChainAnalysisService.Analyze(ChainCatalog, findings,
            new ChainAnalysisService.AnalyzeOptions(
                minChainedSeverity, includePartial, IdentityStore, pageUrl,
                thirdParty.TotalCount, externalWithoutSri.Count, missingSriUrls));
        var payload = ChainAnalysisService.BuildAnalyzePayload(result);
        return TextContent(JsonSerializer.Serialize(payload, CompactJson));
    }

private object ToolSecurityChainPatterns(JsonElement args)
    {
        if (ChainCatalog == null)
            return ErrorContent("Chain pattern catalog not initialized.");

        var jb = JsonBody.FromToolArguments(args);
        var action = jb.GetString("action") ?? "list";

        if (action is "add" or "remove" && SafeMode)
            return ErrorContent($"Blocked by safe mode: chain-patterns action={action}. Safe mode allows list/read only.");

        if (action == "add")
        {
            if (args.ValueKind != JsonValueKind.Object)
                return ErrorContent("Invalid arguments object.");

            var pattern = ChainPatternParser.TryBuildFromAddPayload(args, out var parseError);
            if (pattern == null)
                return ErrorContent(parseError ?? "Invalid pattern payload.");

            if (!ChainCatalog.Add(pattern))
                return ErrorContent($"Pattern id '{pattern.Id}' already exists.");

            return TextContent(JsonSerializer.Serialize(new
            {
                added = pattern.Id,
                totalPatterns = ChainCatalog.GetAll().Count
            }, CompactJson));
        }

        if (action == "remove")
        {
            var id = jb.GetString("id");
            if (string.IsNullOrEmpty(id))
                return ErrorContent("Required: id");

            var removed = ChainCatalog.Remove(id);
            return TextContent(JsonSerializer.Serialize(new { removed, id }, CompactJson));
        }

        var payload = ChainAnalysisService.BuildPatternsPayload(ChainCatalog.GetAll());
        return TextContent(JsonSerializer.Serialize(payload, CompactJson));
    }

private async Task<object> ToolSecurityStorage()
    {
        var result = await _context.CheckStorageSecurity();
        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolSecurityTechStack()
    {
        var result = await _context.CheckTechStack();
        return TextContent(result.Format(includeDetails: true));
    }
}
