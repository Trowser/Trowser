using Trowser.Security.Orchestration;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    private Task HandlePostAttackForm(System.Net.HttpListenerRequest request, System.Net.HttpListenerResponse response) =>
        RespondAsync(request, response, BuildAttackFormAsync);

    /// <summary>
    /// POST /api/attack-form - adaptive form attack. Discovers the editable fields wired to a
    /// form/submit control, infers each field's semantic type, and probes for client-side
    /// validation gaps. When <c>submit</c> is true, also replays the form server-side (mutates
    /// state; requires safetyMode: active).
    /// </summary>
    internal async Task<object> BuildAttackFormAsync(JsonBody body)
    {
        var target = body.GetString("target");
        var submit = body.GetBool("submit", false);
        var maxFields = body.GetInt("maxFields", 15);
        var perField = body.GetInt("perField", 18);

        if (submit)
        {
            var gateError = SafetyGate.RequireActive(body,
                "Adaptive form attack with submit=true replays the form to the server with attack payloads");
            if (gateError != null)
                throw new ApiCommandException(400, gateError.Value);
        }

        var result = await _context.AttackForm(target, submit, maxFields, perField);

        return new
        {
            formFound = result.FormFound,
            formLabel = result.FormLabel,
            action = result.Action,
            method = result.Method,
            fieldCount = result.FieldCount,
            submitted = result.Submitted,
            anomalyCount = result.Anomalies.Count,
            anomalies = result.Anomalies,
            summary = result.Summary,
            note = result.Note,
            fields = result.Fields.Select(f => new
            {
                name = f.Name,
                label = f.Label,
                type = f.Type,
                semantic = f.Semantic,
                required = f.Required,
                maxLength = f.MaxLength,
                pattern = f.Pattern,
                min = f.Min,
                max = f.Max,
                notes = f.Notes,
                probes = f.Probes.Select(p => new
                {
                    category = p.Category,
                    payload = p.Payload,
                    expectedInvalid = p.ExpectedInvalid,
                    rejected = p.Rejected,
                    validationMessage = p.ValidationMessage
                })
            })
        };
    }
}
