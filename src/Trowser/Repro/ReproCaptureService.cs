using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Trowser.Bookmarks;
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
        JsonElement? oracle,
        int? sinceJournalIndex = null,
        int? tabId = null,
        string? setupNavigateUrl = null)
    {
        Checkpoint? checkpoint = null;
        if (!string.IsNullOrWhiteSpace(checkpointId))
        {
            checkpoint = store?.GetCheckpoint(checkpointId);
            if (checkpoint == null)
                throw new InvalidOperationException($"Unknown checkpoint '{checkpointId}'.");
        }
        else if (!sinceJournalIndex.HasValue)
        {
            checkpoint = store?.LatestCheckpoint;
        }

        var since = sinceJournalIndex ?? checkpoint?.JournalIndex ?? -1;
        var actions = logger.GetJournal(since: since, type: "action");
        var steps = new List<object>();
        var skipped = 0;

        foreach (var entry in actions)
        {
            if (tabId.HasValue && !BookmarkFields.ActionMatchesTab(entry, tabId.Value))
                continue;
            if (!ReproJournalFilter.ShouldCaptureJournalAction(entry))
                continue;
            var built = TryBuildSteps(entry);
            if (built != null) steps.AddRange(built);
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
            ["setup"] = BuildSetup(steps, setupNavigateUrl),
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

    /// <summary>Journal field on an action row: JSON map of ref number to the selector it pointed at when the action ran.</summary>
    public const string RefSelectorsField = "refSelectors";

    private static readonly HashSet<string> BatchReplayActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "click", "type", "select", "hover", "scroll"
    };

    /// <summary>
    /// A slice that starts mid-flow (no navigate first) only replays on the page it started on, so
    /// <c>setup</c> opens that page. Empty when the first step navigates anyway or the URL is not http(s).
    /// </summary>
    private static object[] BuildSetup(List<object> trigger, string? startUrl)
    {
        if (string.IsNullOrWhiteSpace(startUrl)
            || !Uri.TryCreate(startUrl, UriKind.Absolute, out var u)
            || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps))
            return [];
        if (trigger.Count > 0 && IsNavigateStep(trigger[0])) return [];
        return [new Dictionary<string, object?> { ["type"] = "navigate", ["url"] = startUrl }];
    }

    private static bool IsNavigateStep(object step) =>
        step is Dictionary<string, object?> d && d.TryGetValue("type", out var t) && t is "navigate";

    /// <summary>Replay steps for one journal action (a batch expands to several), or null when it cannot be replayed.</summary>
    internal static List<object>? TryBuildSteps(SessionLogger.JournalEntry entry)
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

        JsonObject? body = null;
        if (!string.IsNullOrWhiteSpace(bodyRaw))
        {
            try { body = JsonNode.Parse(bodyRaw) as JsonObject; }
            catch { body = null; }
        }

        var refSelectors = ParseRefSelectors(Field(entry, RefSelectorsField));

        if ((path.Equals("/api/navigate", StringComparison.OrdinalIgnoreCase)
             || path.Equals("/api/tabs/new", StringComparison.OrdinalIgnoreCase))
            && TryGetString(body, "url") is { } navUrl && !string.IsNullOrWhiteSpace(navUrl))
            return [new Dictionary<string, object?> { ["type"] = "navigate", ["url"] = navUrl }];

        // A new tab without a URL opens about:blank; nothing to replay.
        if (path.Equals("/api/tabs/new", StringComparison.OrdinalIgnoreCase))
            return [];

        if (path.Equals("/api/batch", StringComparison.OrdinalIgnoreCase))
            return BuildBatchSteps(body, refSelectors);

        if (body != null) ApplyRefSelector(body, refSelectors);
        return [RestStep(method!, path, body)];
    }

    private static List<object>? BuildBatchSteps(JsonObject? body, Dictionary<string, string>? refSelectors)
    {
        if (body?["actions"] is not JsonArray actions) return null;
        var steps = new List<object>();
        foreach (var node in actions)
        {
            if (node is not JsonObject action) continue;
            var name = TryGetString(action, "action");
            if (name == null || !BatchReplayActions.Contains(name)) continue; // reads and waits change nothing
            var stepBody = (JsonObject)action.DeepClone();
            stepBody.Remove("action");
            if (name.Equals("type", StringComparison.OrdinalIgnoreCase)
                && stepBody["text"] == null && stepBody["value"] == null)
                continue; // html-only type has no REST replay
            ApplyRefSelector(stepBody, refSelectors);
            steps.Add(RestStep("POST", "/api/" + name.ToLowerInvariant(), stepBody));
        }
        return steps.Count > 0 ? steps : null;
    }

    private static Dictionary<string, object?> RestStep(string method, string path, JsonObject? body) => new()
    {
        ["method"] = method.ToUpperInvariant(),
        ["path"] = path,
        ["body"] = body
    };

    /// <summary>Refs are only valid on the page they came from; replay uses the selector recorded when the action ran.</summary>
    private static void ApplyRefSelector(JsonObject body, Dictionary<string, string>? refSelectors)
    {
        if (refSelectors == null || body["ref"] == null) return;
        if (!string.IsNullOrWhiteSpace(TryGetString(body, "selector"))) return;
        var key = body["ref"]!.ToJsonString().Trim('"');
        if (refSelectors.TryGetValue(key, out var selector) && !string.IsNullOrWhiteSpace(selector))
            body["selector"] = selector;
    }

    internal static Dictionary<string, string>? ParseRefSelectors(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try { return JsonSerializer.Deserialize<Dictionary<string, string>>(raw); }
        catch { return null; }
    }

    private static string? TryGetString(JsonObject? obj, string key) =>
        obj?[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

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
