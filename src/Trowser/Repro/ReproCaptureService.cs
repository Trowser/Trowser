using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Pointers;
using Trowser.SessionLog;

namespace Trowser.Repro;

/// <summary>
/// Builds a <c>.trw</c> workflow from the journal action slice since a checkpoint.
/// Checkpoints bound "what has happened since we last synced"; this is where that bound pays off.
/// </summary>
public static class ReproCaptureService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    public static ReproCaptureResult Capture(
        SessionLogger logger,
        PointerStore? store,
        string? checkpointId,
        string? name,
        string? outputPath,
        JsonElement? oracle)
    {
        Checkpoint? checkpoint = null;
        if (!string.IsNullOrWhiteSpace(checkpointId))
        {
            checkpoint = store?.GetCheckpoint(checkpointId);
            if (checkpoint == null)
                throw new InvalidOperationException($"Unknown checkpoint '{checkpointId}'.");
        }
        else
        {
            checkpoint = store?.LatestCheckpoint;
        }

        var since = checkpoint?.JournalIndex ?? -1;
        var actions = logger.GetJournal(since: since, type: "action");
        var steps = new List<object>();
        var skipped = 0;

        foreach (var entry in actions)
        {
            var step = TryBuildStep(entry);
            if (step != null) steps.Add(step);
            else skipped++;
        }

        if (steps.Count == 0)
            throw new InvalidOperationException(
                checkpoint == null
                    ? "No replayable journal actions to capture. Interact with the page (or pass a workflow body to /api/repro/verify)."
                    : $"No replayable journal actions since checkpoint '{checkpoint.Id}'.");

        var workflow = new Dictionary<string, object?>
        {
            ["name"] = string.IsNullOrWhiteSpace(name)
                ? (checkpoint?.Label ?? "Captured repro")
                : name.Trim(),
            ["checkpointId"] = checkpoint?.Id,
            ["capturedAt"] = DateTime.UtcNow.ToString("o"),
            ["setup"] = Array.Empty<object>(),
            ["trigger"] = steps,
            ["oracle"] = oracle.HasValue && oracle.Value.ValueKind == JsonValueKind.Object
                ? JsonSerializer.Deserialize<object>(oracle.Value.GetRawText())
                : new { type = "and", checks = Array.Empty<object>() }
        };

        var json = JsonSerializer.Serialize(workflow, JsonOptions);
        string? savedPath = null;
        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(outputPath, json);
            savedPath = Path.GetFullPath(outputPath);
        }

        return new ReproCaptureResult
        {
            CheckpointId = checkpoint?.Id,
            JournalIndex = since,
            StepCount = steps.Count,
            Skipped = skipped,
            Path = savedPath,
            WorkflowJson = json
        };
    }

    private static object? TryBuildStep(SessionLogger.JournalEntry entry)
    {
        var method = Field(entry, "method");
        var path = Field(entry, "path");
        var bodyRaw = Field(entry, "body");

        if (string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(path))
        {
            // Older action entries: summary is "POST /api/navigate".
            var summary = entry.Summary ?? "";
            var space = summary.IndexOf(' ');
            if (space <= 0) return null;
            method = summary[..space].Trim();
            path = summary[(space + 1)..].Trim();
        }

        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
            return null;

        object? body = null;
        if (!string.IsNullOrWhiteSpace(bodyRaw))
        {
            try { body = JsonSerializer.Deserialize<object>(bodyRaw); }
            catch { body = null; }
        }

        if (string.Equals(path, "/api/navigate", StringComparison.OrdinalIgnoreCase) && body is JsonElement nav
            && nav.ValueKind == JsonValueKind.Object && nav.TryGetProperty("url", out var urlEl))
        {
            var url = urlEl.GetString();
            if (!string.IsNullOrWhiteSpace(url))
                return new { type = "navigate", url };
        }

        return new
        {
            method = method!.ToUpperInvariant(),
            path,
            body
        };
    }

    private static string? Field(SessionLogger.JournalEntry entry, string key)
    {
        if (entry.Fields == null) return null;
        return entry.Fields.TryGetValue(key, out var v) ? v : null;
    }
}

public sealed class ReproCaptureResult
{
    public string? CheckpointId { get; init; }
    public int JournalIndex { get; init; }
    public int StepCount { get; init; }
    public int Skipped { get; init; }
    public string? Path { get; init; }
    public string WorkflowJson { get; init; } = "";
}
