using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Recording;
using Trowser.Repro;
using Trowser.SessionLog;

namespace Trowser.Bookmarks;

/// <summary>Pure helpers for building and reading bookmark evidence. No WebView access.</summary>
public static class BookmarkEvidence
{
    /// <summary>Most narrated steps kept on the entry. The <c>.trw</c> keeps every replayable step.</summary>
    public const int MaxNarratedSteps = 50;

    public const string RedactedValue = "[redacted]";

    private static readonly JsonSerializerOptions StateJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    /// <summary>
    /// Narrate journal <c>action</c> entries into readable steps, keeping the last
    /// <paramref name="max"/>. Returns the steps and how many earlier ones were dropped.
    /// </summary>
    public static (List<string> Steps, int Omitted) NarrateSteps(
        IReadOnlyList<SessionLogger.JournalEntry> actions, int max = MaxNarratedSteps)
    {
        var all = new List<string>(actions.Count);
        foreach (var e in actions)
        {
            if (!IsAutomationSlice(e) || !ReproJournalFilter.ShouldNarrateJournalAction(e)) continue;
            var line = NarrateAction(e);
            if (string.Equals(e.Type, "error", StringComparison.OrdinalIgnoreCase))
                line += " (failed)";
            if (!string.IsNullOrWhiteSpace(line)) all.Add(line.Replace('\n', ' ').Replace('\r', ' ').Trim());
        }

        if (all.Count <= max) return (all, 0);
        var omitted = all.Count - max;
        return (all.GetRange(omitted, max), omitted);
    }

    private static bool IsAutomationSlice(SessionLogger.JournalEntry e) =>
        string.Equals(e.Type, "action", StringComparison.OrdinalIgnoreCase)
        || (string.Equals(e.Type, "error", StringComparison.OrdinalIgnoreCase)
            && e.Fields != null && e.Fields.ContainsKey("method"));

    private static string NarrateAction(SessionLogger.JournalEntry e)
    {
        string? F(string key) => e.Fields != null && e.Fields.TryGetValue(key, out var v) ? v : null;
        var method = F("method");
        var path = F("path");
        if (string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(path))
            return e.Summary;
        var line = ActionNarrator.DescribeApiAction(method, path, WithRefSelectors(F("body"), F(ReproCaptureService.RefSelectorsField)));
        if (e.Source == "gui" && !string.IsNullOrWhiteSpace(e.Details))
        {
            var human = e.Details.Trim();
            if (!line.Contains(human, StringComparison.OrdinalIgnoreCase))
                line += $" — {human}";
        }
        if (e.Source == "api") line += " (agent)";
        else if (e.Source == "gui") line += " (you)";
        return line;
    }

    /// <summary>Body with <c>selector</c> filled in from the ref map recorded at action time, so narration names the element.</summary>
    private static string? WithRefSelectors(string? body, string? refSelectorsRaw)
    {
        if (string.IsNullOrWhiteSpace(body) || string.IsNullOrWhiteSpace(refSelectorsRaw)) return body;
        var map = ReproCaptureService.ParseRefSelectors(refSelectorsRaw);
        if (map == null || map.Count == 0) return body;
        try
        {
            if (System.Text.Json.Nodes.JsonNode.Parse(body) is not System.Text.Json.Nodes.JsonObject obj) return body;
            Fill(obj);
            if (obj["actions"] is System.Text.Json.Nodes.JsonArray actions)
                foreach (var a in actions)
                    if (a is System.Text.Json.Nodes.JsonObject ao) Fill(ao);
            return obj.ToJsonString();
        }
        catch { return body; }

        void Fill(System.Text.Json.Nodes.JsonObject o)
        {
            if (o["ref"] == null || o["selector"] != null) return;
            if (map.TryGetValue(o["ref"]!.ToJsonString().Trim('"'), out var sel) && !string.IsNullOrWhiteSpace(sel))
                o["selector"] = sel;
        }
    }

    /// <summary>Fields for a new bookmark entry. Empty values are left out.</summary>
    public static Dictionary<string, string> BuildFields(
        string bookmarkId,
        int bookmarkNumber,
        string? checkpointId,
        IReadOnlyList<string> steps,
        int stepsOmitted,
        NetworkEntry? lastRequest,
        string directory,
        string? screenshotPath,
        string? trwPath,
        string? statePath,
        int? tabId = null,
        string? startUrl = null,
        string? startsFrom = null)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [BookmarkFields.BookmarkId] = bookmarkId,
            [BookmarkFields.BookmarkNumber] = bookmarkNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [BookmarkFields.Directory] = directory,
            [BookmarkFields.StepCount] = (steps.Count + stepsOmitted).ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrEmpty(checkpointId)) fields[BookmarkFields.CheckpointId] = checkpointId;
        if (steps.Count > 0) fields[BookmarkFields.CapturedSteps] = string.Join("\n", steps);
        if (stepsOmitted > 0)
            fields[BookmarkFields.StepsOmitted] = stepsOmitted.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (lastRequest != null && !string.IsNullOrEmpty(lastRequest.Url))
        {
            var agentUrl = AgentUrlPolicy.ForAgent(lastRequest.Url);
            if (!string.IsNullOrEmpty(agentUrl))
            {
                fields[BookmarkFields.RequestMethod] = lastRequest.Method;
                fields[BookmarkFields.RequestStatus] = lastRequest.StatusCode.ToString(System.Globalization.CultureInfo.InvariantCulture);
                fields[BookmarkFields.RequestUrl] = agentUrl;
            }
        }
        if (!string.IsNullOrEmpty(screenshotPath)) fields[BookmarkFields.Screenshot] = screenshotPath;
        if (!string.IsNullOrEmpty(trwPath)) fields[BookmarkFields.TrwPath] = trwPath;
        if (!string.IsNullOrEmpty(statePath)) fields[BookmarkFields.StatePath] = statePath;
        if (tabId.HasValue)
            fields[BookmarkFields.TabId] = tabId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var agentStart = AgentUrlPolicy.ForAgent(startUrl);
        if (!string.IsNullOrEmpty(agentStart)) fields[BookmarkFields.StartUrl] = agentStart;
        if (!string.IsNullOrEmpty(startsFrom)) fields[BookmarkFields.StartsFrom] = startsFrom;
        return fields;
    }

    /// <summary>New bookmark id. Safe as a folder name.</summary>
    public static string NewId() => "bm-" + Guid.NewGuid().ToString("N")[..10];

    /// <summary>True when <paramref name="id"/> looks like an id this class issues (used before touching the file system).</summary>
    public static bool IsValidId(string? id) =>
        !string.IsNullOrEmpty(id) && id.Length <= 40
        && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_');

    public static string SerializeState(BrowserSessionSnapshot snapshot) =>
        JsonSerializer.Serialize(snapshot, StateJsonOptions);

    public static BrowserSessionSnapshot DeserializeState(string json) =>
        JsonSerializer.Deserialize<BrowserSessionSnapshot>(json, StateJsonOptions)
        ?? throw new InvalidOperationException("Bookmark state file is empty.");

    /// <summary>Copy of <paramref name="snapshot"/> with every cookie and storage value replaced. Names stay.</summary>
    public static BrowserSessionSnapshot Redact(BrowserSessionSnapshot snapshot) => new()
    {
        Id = snapshot.Id,
        CapturedAt = snapshot.CapturedAt,
        Scope = snapshot.Scope,
        AnchorUrl = snapshot.AnchorUrl,
        AnchorOrigin = snapshot.AnchorOrigin,
        AnchorHost = snapshot.AnchorHost,
        Cookies = snapshot.Cookies.Select(c => new BrowserSessionCookieRecord
        {
            Name = c.Name,
            Value = RedactedValue,
            Domain = c.Domain,
            Path = c.Path,
            Secure = c.Secure,
            HttpOnly = c.HttpOnly,
            SameSite = c.SameSite,
            Session = c.Session,
            Expires = c.Expires
        }).ToList(),
        LocalStorage = snapshot.LocalStorage.ToDictionary(kv => kv.Key, _ => RedactedValue, StringComparer.Ordinal),
        SessionStorage = snapshot.SessionStorage.ToDictionary(kv => kv.Key, _ => RedactedValue, StringComparer.Ordinal)
    };

    /// <summary>
    /// Prefer the last interesting API/document request for bookmarks (not a trailing static GET).
    /// </summary>
    /// <remarks>
    /// Requests to the page's own site win over third-party ones (analytics and error beacons fire
    /// last on many pages); a third-party request is used only when the site made none.
    /// </remarks>
    public static NetworkEntry? PickLastMeaningfulRequest(IReadOnlyList<NetworkEntry> entries, string? pageUrl = null)
    {
        if (entries.Count == 0) return null;
        var pageHost = Uri.TryCreate(pageUrl, UriKind.Absolute, out var pu) ? pu.Host : null;
        if (!string.IsNullOrEmpty(pageHost))
        {
            for (var i = entries.Count - 1; i >= 0; i--)
            {
                var e = entries[i];
                if (AgentUrlPolicy.IsOmittedUrl(e.Url)) continue;
                if (IsInterestingRequest(e) && IsSameSite(e.Url, pageHost)) return e;
            }
        }

        for (var i = entries.Count - 1; i >= 0; i--)
        {
            var e = entries[i];
            if (AgentUrlPolicy.IsOmittedUrl(e.Url)) continue;
            if (IsInterestingRequest(e)) return e;
        }

        for (var i = entries.Count - 1; i >= 0; i--)
        {
            if (!AgentUrlPolicy.IsOmittedUrl(entries[i].Url))
                return entries[i];
        }

        return null;
    }

    /// <summary>Same host, or both hosts share their last two labels (<c>api.example.com</c> / <c>www.example.com</c>).</summary>
    internal static bool IsSameSite(string? url, string pageHost)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
        if (string.Equals(u.Host, pageHost, StringComparison.OrdinalIgnoreCase)) return true;
        static string Site(string host)
        {
            var parts = host.Split('.');
            return parts.Length >= 2 ? parts[^2] + "." + parts[^1] : host;
        }
        return System.Net.IPAddress.TryParse(pageHost, out _) == false
               && string.Equals(Site(u.Host), Site(pageHost), StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInterestingRequest(NetworkEntry e)
    {
        if (string.Equals(e.ResourceType, "Ping", StringComparison.OrdinalIgnoreCase)) return false;
        if (NetworkEntry.MethodMayHaveRequestBody(e.Method)
            && !e.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            return true;

        var t = e.ResourceType ?? "";
        return t.Equals("Document", StringComparison.OrdinalIgnoreCase)
               || t.Equals("Fetch", StringComparison.OrdinalIgnoreCase)
               || t.Equals("XHR", StringComparison.OrdinalIgnoreCase)
               || t.Equals("EventSource", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when a .trw has at least one step Verify can replay (not housekeeping-only).</summary>
    public static bool TrwPathIsVerifiable(string? trwPath)
    {
        if (string.IsNullOrWhiteSpace(trwPath) || !File.Exists(trwPath)) return false;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(trwPath));
            return CountVerifiableTriggerSteps(doc.RootElement) > 0;
        }
        catch
        {
            return false;
        }
    }

    public static int CountVerifiableTriggerSteps(JsonElement workflow)
    {
        if (!workflow.TryGetProperty("trigger", out var trigger) || trigger.ValueKind != JsonValueKind.Array)
            return 0;

        var count = 0;
        foreach (var step in trigger.EnumerateArray())
        {
            if (step.TryGetProperty("type", out var typeEl) && typeEl.ValueKind == JsonValueKind.String)
            {
                var t = typeEl.GetString();
                if (string.Equals(t, "navigate", StringComparison.OrdinalIgnoreCase))
                {
                    var url = step.TryGetProperty("url", out var u) ? u.GetString() : null;
                    if (!IsTrivialNavigate(url)) count++;
                }
                else
                    count++;
                continue;
            }

            if (step.TryGetProperty("path", out var pathEl) && pathEl.ValueKind == JsonValueKind.String
                && step.TryGetProperty("method", out var methEl) && methEl.ValueKind == JsonValueKind.String
                && string.Equals(methEl.GetString(), "POST", StringComparison.OrdinalIgnoreCase))
            {
                var path = pathEl.GetString()!;
                if (!ReproJournalFilter.IsHousekeepingApiPath(path))
                {
                    if (path.Equals("/api/navigate", StringComparison.OrdinalIgnoreCase)
                        && step.TryGetProperty("body", out var body)
                        && body.ValueKind == JsonValueKind.Object
                        && body.TryGetProperty("url", out var urlEl))
                    {
                        if (!IsTrivialNavigate(urlEl.GetString())) count++;
                    }
                    else if (RestApiReplayer.IsSupportedPath(path))
                        count++;
                }
            }
        }

        return count;
    }

    private static bool IsTrivialNavigate(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;
        var t = url.Trim();
        return t.Equals("about:blank", StringComparison.OrdinalIgnoreCase)
               || AgentUrlPolicy.IsInternalDisplayUrl(t);
    }

}
