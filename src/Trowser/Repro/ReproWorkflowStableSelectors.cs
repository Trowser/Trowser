using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Api;
using Trowser.Automation;

namespace Trowser.Repro;

/// <summary>
/// Rewrites <c>.trw</c> REST steps that still have only a ref number so replay uses a selector from the
/// current page. Steps that already carry a selector (resolved when the action ran) are left alone.
/// </summary>
public static class ReproWorkflowStableSelectors
{
    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static string EnrichTriggerSteps(string workflowJson, AutomationContext ctx)
    {
        var root = JsonNode.Parse(workflowJson)?.AsObject();
        if (root == null) return workflowJson;
        if (root["trigger"] is not JsonArray trigger) return workflowJson;

        foreach (var stepNode in trigger)
        {
            if (stepNode is not JsonObject step) continue;
            if (step["path"]?.GetValue<string>() is not { } path
                || !path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
                continue;
            if (step["body"] is not JsonObject bodyObj) continue;

            using var bodyDoc = JsonDocument.Parse(bodyObj.ToJsonString());
            var body = JsonBody.FromToolArguments(bodyDoc.RootElement);
            if (!body.HasProperty("ref")) continue;
            if (!string.IsNullOrWhiteSpace(body.GetString("selector"))) continue;

            var refIndex = body.GetInt("ref", -1);
            var selector = ctx.GetSelectorByRef(refIndex);
            if (string.IsNullOrWhiteSpace(selector)) continue;

            var frame = body.GetString("frame");
            if (string.IsNullOrWhiteSpace(frame))
                frame = ctx.GetFrameIdByRef(refIndex);
            bodyObj["selector"] = AutomationContext.ApplyFrame(selector, frame);
        }

        return root.ToJsonString(WriteOptions);
    }
}