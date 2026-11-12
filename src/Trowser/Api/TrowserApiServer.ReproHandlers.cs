using System.IO;
using System.Net;
using System.Text.Json;
using Trowser.Repro;
using Trowser.Security.Orchestration;
using Trowser.Security.Workflow;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    private Task HandlePostReproCapture(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildReproCaptureAsync);

    private Task HandlePostReproVerify(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildReproVerifyAsync);

    /// <summary>
    /// Build a <c>.trw</c> from journal actions since a checkpoint.
    /// Backs <c>POST /api/repro/capture</c> and MCP <c>browser_repro_capture</c>.
    /// </summary>
    internal Task<object> BuildReproCaptureAsync(JsonBody body)
    {
        if (SessionLogger == null)
            throw new ApiCommandException(503, "Session logger not available.");

        var checkpointId = body.GetString("checkpointId");
        var name = body.GetString("name");
        var outputPath = body.GetString("path") ?? body.GetString("outputPath");
        JsonElement? oracle = null;
        if (body.TryGetRoot(out var root) && root.TryGetProperty("oracle", out var oracleEl)
            && oracleEl.ValueKind == JsonValueKind.Object)
            oracle = oracleEl.Clone();

        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            if (!ExportPathGuard.TryResolve(outputPath, SafeMode, out var full, out var guardError))
                throw new ApiCommandException(400, guardError ?? "Export path rejected.");
            outputPath = full;
        }

        try
        {
            var captured = ReproCaptureService.Capture(
                SessionLogger, PointerStore, checkpointId, name, outputPath, oracle);

            object workflow;
            using (var doc = JsonDocument.Parse(captured.WorkflowJson))
                workflow = JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText())!;

            return Task.FromResult<object>(new
            {
                checkpointId = captured.CheckpointId,
                journalIndex = captured.JournalIndex,
                stepCount = captured.StepCount,
                skipped = captured.Skipped,
                path = captured.Path,
                workflow
            });
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

    /// <summary>
    /// Run a captured <c>.trw</c> / evidence bundle / workflow body k times and return
    /// reproducible / flaky / not-reproducible with a pass rate.
    /// Backs <c>POST /api/repro/verify</c> and MCP <c>browser_repro_verify</c>.
    /// </summary>
    internal async Task<object> BuildReproVerifyAsync(JsonBody body)
    {
        if (!body.TryGetRoot(out var root))
            throw new ApiCommandException(400, "Invalid JSON body.");

        var gateError = SafetyGate.RequireActive(body, "Running a repro workflow");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var workflow = await LoadWorkflowAsync(body, root);
        var runs = Math.Clamp(body.GetInt("runs", 1), 1, 20);
        var clearSession = body.GetBool("clearSession", true);
        var identity = body.GetString("identity");
        var expect = body.GetString("expect");

        var result = await ReproVerifyService.VerifyAsync(
            workflow, BuildWorkflowDependencies(), _identityStore, runs, clearSession, identity, expect);

        return new
        {
            verdict = ReproVerifyService.ToApiString(result.Verdict),
            rate = result.Rate,
            passed = result.Passed,
            failed = result.Failed,
            runs = result.Runs.Select(r => new
            {
                run = r.Run,
                passed = r.Passed,
                error = r.Error,
                workflow = r.Workflow != null ? FormatWorkflowVerifyResponse(r.Workflow) : null
            }).ToList()
        };
    }

    private static async Task<JsonElement> LoadWorkflowAsync(JsonBody body, JsonElement root)
    {
        var trwPath = body.GetString("trwPath") ?? body.GetString("file");
        var bundlePath = body.GetString("bundlePath");

        if (!string.IsNullOrWhiteSpace(trwPath))
            return await ReadWorkflowFileAsync(trwPath);

        if (!string.IsNullOrWhiteSpace(bundlePath))
        {
            if (!ExportPathGuard.TryResolveRead(bundlePath, out _, out var bundleError))
                throw new ApiCommandException(400, bundleError ?? "Bundle path rejected.");
            var workflowFile = Path.Combine(bundlePath, "workflow.json");
            if (!File.Exists(workflowFile))
                workflowFile = Path.Combine(bundlePath, "scenario.trw");
            if (!File.Exists(workflowFile))
                throw new ApiCommandException(404, $"No workflow.json or scenario.trw in bundle: {bundlePath}");
            return await ReadWorkflowFileAsync(workflowFile);
        }

        if (root.TryGetProperty("workflow", out var nested) && nested.ValueKind == JsonValueKind.Object)
            return nested.Clone();

        if (root.TryGetProperty("setup", out _) || root.TryGetProperty("trigger", out _)
            || root.TryGetProperty("oracle", out _) || root.TryGetProperty("steps", out _))
        {
            return NormalizeFlatSteps(root);
        }

        throw new ApiCommandException(400,
            "Provide trwPath, bundlePath, a workflow object, or inline setup/trigger/oracle/steps.");
    }

    private static JsonElement NormalizeFlatSteps(JsonElement root)
    {
        if (root.TryGetProperty("trigger", out _) || root.TryGetProperty("setup", out _))
            return root.Clone();

        if (root.TryGetProperty("steps", out var steps) && steps.ValueKind == JsonValueKind.Array)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                foreach (var prop in root.EnumerateObject())
                {
                    if (prop.NameEquals("steps")) continue;
                    writer.WritePropertyName(prop.Name);
                    prop.Value.WriteTo(writer);
                }
                writer.WritePropertyName("trigger");
                steps.WriteTo(writer);
                if (!root.TryGetProperty("oracle", out _))
                {
                    writer.WritePropertyName("oracle");
                    writer.WriteStartObject();
                    writer.WriteString("type", "and");
                    writer.WriteStartArray("checks");
                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }
                writer.WriteEndObject();
            }
            using var doc = JsonDocument.Parse(stream.ToArray());
            return doc.RootElement.Clone();
        }

        return root.Clone();
    }

    private static async Task<JsonElement> ReadWorkflowFileAsync(string path)
    {
        if (!ExportPathGuard.TryResolveRead(path, out var full, out var pathError))
            throw new ApiCommandException(400, pathError ?? "Workflow path rejected.");
        path = full;
        if (!File.Exists(path))
            throw new ApiCommandException(404, $"File not found: {path}");
        var raw = await File.ReadAllTextAsync(path);
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        if (root.TryGetProperty("phases", out var phases) && phases.ValueKind == JsonValueKind.Object)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                foreach (var prop in root.EnumerateObject())
                {
                    if (prop.NameEquals("phases")) continue;
                    writer.WritePropertyName(prop.Name);
                    prop.Value.WriteTo(writer);
                }
                foreach (var phase in phases.EnumerateObject())
                {
                    writer.WritePropertyName(phase.Name);
                    phase.Value.WriteTo(writer);
                }
                writer.WriteEndObject();
            }
            using var lifted = JsonDocument.Parse(stream.ToArray());
            return NormalizeFlatSteps(lifted.RootElement);
        }
        return NormalizeFlatSteps(root);
    }
}
