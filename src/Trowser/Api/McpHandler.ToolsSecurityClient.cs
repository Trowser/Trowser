using System.Text.Json;
using Trowser.Security;
using Trowser.Security.DomFlow;
using Trowser.Security.Orchestration;
using Trowser.Security.GadgetChains;
using Trowser.Security.Runtime;
using Trowser.Security.XsLeaks;

namespace Trowser.Api;

public partial class McpHandler
{
    private Task<object> ToolServiceWorkerAudit(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildSecurityServiceWorkerAuditAsync);

    private Task<object> ToolSecurityXssiScan(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildSecurityXssiScanAsync);

    private async Task<object> ToolClientSurface(JsonElement args)
    {
        var installSensor = GetBool(args, "installSensor", true);
        var waitMs = GetInt(args, "waitMs", 400);
        var reloadForSensor = GetBool(args, "reloadForSensor", true);
        var reset = GetBool(args, "reset", false);
        var scopeToDocument = GetBool(args, "scopeToCurrentDocument", true);
        var mapper = new ClientSurfaceMapper(_context);
        var result = await mapper.MapAsync(installSensor, waitMs, reloadForSensor, reset, scopeToDocument);
        return TextContent(JsonSerializer.Serialize(result.ToApiResponse(), CompactJson));
    }

    private async Task<object> ToolPostMessageAudit(JsonElement args)
    {
        var mode = SafetyGate.Resolve(args);
        if (mode < SafetyMode.Safe)
            return ErrorContent(
                "postMessage audit requires safetyMode 'safe' or higher " +
                $"(current: '{mode.ToLabel()}').");

        var topologies = GetStringArray(args, "topologies");
        var options = new PostMessageAuditOptions
        {
            SafetyMode = mode.ToLabel(),
            Fuzz = GetBool(args, "fuzz", true),
            MaxPayloads = Math.Clamp(GetInt(args, "maxPayloads", 8), 1, 20),
            MaxPayloadsPerListener = Math.Clamp(GetInt(args, "maxPayloadsPerListener", 2), 1, 4),
            Depth = GetString(args, "depth") ?? SecurityScanDepth.Quick,
            SuggestOnly = GetBool(args, "suggestOnly"),
            IncludeOutbound = GetBool(args, "includeOutbound", true),
            MaxSeconds = GetInt(args, "maxSeconds", 0),
            ListenerFilter = GetString(args, "listenerFilter"),
            Topologies = topologies is { Count: > 0 } ? topologies : null,
            IncludeHistory = GetBool(args, "includeHistory"),
            Reset = GetBool(args, "reset"),
            AttackerOrigin = GetString(args, "attackerOrigin"),
            DescendIframes = !args.TryGetProperty("descendIframes", out var di) || di.ValueKind != JsonValueKind.False
        };
        var auditor = new PostMessageAuditor(_context);
        var result = await auditor.RunAsync(options);
        return TextContent(JsonSerializer.Serialize(result.ToApiResponse(), CompactJson));
    }

    private async Task<object> ToolClientPrototypePollution(JsonElement args)
    {
        if (SafetyGate.RequireActive(args,
                "Client prototype pollution navigates and mutates Object.prototype") is { } gateError)
            return ErrorContent(gateError);

        var baseUrl = GetString(args, "baseUrl") ?? GetString(args, "url");
        var tryGadgets = GetBool(args, "tryGadgets", true);
        var scanner = new ClientPrototypePollutionScanner(_context);
        var result = await scanner.RunAsync(baseUrl, tryGadgets);
        return TextContent(JsonSerializer.Serialize(result.ToApiResponse(), CompactJson));
    }

    private async Task<object> ToolDomFlows(JsonElement args)
    {
        if (Host == null)
            return ErrorContent("API host not wired.");
        var body = JsonBody.FromToolArguments(args);
        try
        {
            var payload = await Host.BuildSecurityDomFlowsAsync(body);
            return TextContent(JsonSerializer.Serialize(payload, CompactJson));
        }
        catch (ApiCommandException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolDomXssAudit(JsonElement args)
    {
        if (Host == null)
            return ErrorContent("API host not wired.");
        var body = JsonBody.FromToolArguments(args);
        try
        {
            var payload = await Host.BuildSecurityDomXssAuditAsync(body);
            return TextContent(JsonSerializer.Serialize(payload, CompactJson));
        }
        catch (ApiCommandException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolSecurityXsLeaks(JsonElement args)
    {
        if (Host == null)
            return ErrorContent("API host not wired.");
        var body = JsonBody.FromToolArguments(args);
        try
        {
            var payload = await Host.BuildSecurityXsLeaksAsync(body);
            return TextContent(JsonSerializer.Serialize(payload, CompactJson));
        }
        catch (ApiCommandException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolSecurityGadgetChains(JsonElement args)
    {
        if (Host == null)
            return ErrorContent("API host not wired.");
        var body = JsonBody.FromToolArguments(args);
        try
        {
            var payload = await Host.BuildSecurityGadgetChainsAsync(body);
            return TextContent(JsonSerializer.Serialize(payload, CompactJson));
        }
        catch (ApiCommandException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolGadgetRadar(JsonElement args)
    {
        if (Host == null)
            return ErrorContent("API host not wired.");
        var body = JsonBody.FromToolArguments(args);
        try
        {
            var payload = await Host.BuildSecurityGadgetRadarAsync(body);
            return TextContent(JsonSerializer.Serialize(payload, CompactJson));
        }
        catch (ApiCommandException ex)
        {
            return ErrorContent(ex.Message);
        }
    }
}
