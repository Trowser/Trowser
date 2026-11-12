using System.Text.Json.Serialization;

namespace Trowser.Security.RaceLab;

public static class RaceLabRoles
{
    public const string Observe = "observe";
    public const string Mutate = "mutate";
    public const string Check = "check";

    public static IReadOnlyList<string> All { get; } = [Observe, Mutate, Check];

    public static string Normalize(string? role) =>
        (role ?? "").Trim().ToLowerInvariant() switch
        {
            Mutate => Mutate,
            Check => Check,
            _ => Observe
        };

    public static bool IsRaceCandidate(string? role) =>
        string.Equals(Normalize(role), Mutate, StringComparison.OrdinalIgnoreCase);
}

public static class RaceLabSessions
{
    public const string Driver = "driver";
    public const string AllPeers = "all-peers";

    public static IReadOnlyList<string> BuiltInOptions { get; } = [AllPeers, Driver];

    public static string Normalize(string? session) =>
        string.IsNullOrWhiteSpace(session) ? AllPeers : session.Trim();

    public static bool IsAllPeers(string? session) =>
        string.Equals(Normalize(session), AllPeers, StringComparison.OrdinalIgnoreCase);

    public static IEnumerable<string> Expand(string? session, IReadOnlyList<string> peerNames)
    {
        if (!IsAllPeers(session))
            yield return Normalize(session);
        else
        {
            yield return Driver;
            foreach (var peer in peerNames)
            {
                if (!string.IsNullOrWhiteSpace(peer)
                    && !string.Equals(peer, Driver, StringComparison.OrdinalIgnoreCase))
                    yield return peer;
            }
        }
    }
}

public enum RaceLabMode
{
    Hammer,
    Spike,
    Sequential,
    Random,
    Custom
}

public sealed class RaceLabRequest
{
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public string Method { get; set; } = "POST";

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Body { get; set; }

    /// <summary><see cref="RaceLabSessions.Driver"/> or a registered peer name.</summary>
    public string Session { get; set; } = RaceLabSessions.AllPeers;

    /// <summary><see cref="RaceLabRoles.Observe"/>, <see cref="RaceLabRoles.Mutate"/>, or <see cref="RaceLabRoles.Check"/>.</summary>
    public string Role { get; set; } = RaceLabRoles.Observe;

    /// <summary>Optional .NET regex; when set, the response body must match (any role). Empty = no check.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResponsePattern { get; set; }

    public RaceLabRequest Clone() => new()
    {
        Name = Name,
        Url = Url,
        Method = Method,
        Headers = Headers != null ? new Dictionary<string, string>(Headers, StringComparer.OrdinalIgnoreCase) : null,
        Body = Body,
        Session = Session,
        Role = Role,
        ResponsePattern = ResponsePattern
    };
}

public sealed class RaceLabParameters
{
    public RaceLabMode Mode { get; set; } = RaceLabMode.Hammer;
    public int RequestsPerBatch { get; set; } = 15;
    public int DelayPerRequestMs { get; set; }
    public int DelayBetweenBatchesMs { get; set; }
    public int TotalBatches { get; set; } = 3;
    public int DurationMs { get; set; }
    public bool RandomizeOrder { get; set; }
    public int JitterMs { get; set; }
    public int TimeoutMs { get; set; } = 8000;
    public bool IncludeBrowserCookies { get; set; } = true;

    public const int MaxRequestsPerBatch = 100;
    public const int MaxTotalBatches = 50;
    public const int MaxDurationMs = 120_000;

    /// <summary>
    /// Copy bounded to limits that keep a run from exhausting local sockets or flooding the
    /// target far beyond what a race test needs.
    /// </summary>
    public RaceLabParameters Clamped()
    {
        var p = Clone();
        p.RequestsPerBatch = Math.Clamp(p.RequestsPerBatch, 1, MaxRequestsPerBatch);
        p.TotalBatches = Math.Clamp(p.TotalBatches, 1, MaxTotalBatches);
        p.DurationMs = Math.Clamp(p.DurationMs, 0, MaxDurationMs);
        p.DelayPerRequestMs = Math.Clamp(p.DelayPerRequestMs, 0, 60_000);
        p.DelayBetweenBatchesMs = Math.Clamp(p.DelayBetweenBatchesMs, 0, 60_000);
        p.JitterMs = Math.Clamp(p.JitterMs, 0, 10_000);
        p.TimeoutMs = Math.Clamp(p.TimeoutMs, 500, 60_000);
        return p;
    }

    public RaceLabParameters Clone() => new()
    {
        Mode = Mode,
        RequestsPerBatch = RequestsPerBatch,
        DelayPerRequestMs = DelayPerRequestMs,
        DelayBetweenBatchesMs = DelayBetweenBatchesMs,
        TotalBatches = TotalBatches,
        DurationMs = DurationMs,
        RandomizeOrder = RandomizeOrder,
        JitterMs = JitterMs,
        TimeoutMs = TimeoutMs,
        IncludeBrowserCookies = IncludeBrowserCookies
    };

    public static RaceLabParameters ForMode(RaceLabMode mode, int requestCount = 1)
    {
        return mode switch
        {
            RaceLabMode.Spike => new RaceLabParameters
            {
                Mode = RaceLabMode.Spike,
                RequestsPerBatch = Math.Max(1, requestCount),
                TotalBatches = 5,
                DelayBetweenBatchesMs = 250
            },
            RaceLabMode.Sequential => new RaceLabParameters
            {
                Mode = RaceLabMode.Sequential,
                RequestsPerBatch = 1,
                DelayPerRequestMs = 100,
                TotalBatches = 3,
                DelayBetweenBatchesMs = 500
            },
            RaceLabMode.Random => new RaceLabParameters
            {
                Mode = RaceLabMode.Random,
                RequestsPerBatch = 10,
                RandomizeOrder = true,
                JitterMs = 50,
                TotalBatches = 5,
                DelayBetweenBatchesMs = 200
            },
            RaceLabMode.Hammer => new RaceLabParameters
            {
                Mode = RaceLabMode.Hammer,
                RequestsPerBatch = 15,
                TotalBatches = 3
            },
            _ => new RaceLabParameters { Mode = RaceLabMode.Custom }
        };
    }
}

public sealed class RaceLabProfile
{
    public string Name { get; set; } = "";
    public List<RaceLabRequest> Requests { get; set; } = [];
    public RaceLabParameters Parameters { get; set; } = RaceLabParameters.ForMode(RaceLabMode.Hammer);

    public bool IsBuiltIn => RaceLabSettings.IsBuiltInName(Name);

    public RaceLabProfile Clone() => new()
    {
        Name = Name,
        Requests = Requests.Select(r => r.Clone()).ToList(),
        Parameters = Parameters.Clone()
    };
}

public sealed class RaceLabTimelineEntry
{
    public long OffsetMs { get; init; }
    public int BatchIndex { get; init; }
    public int ShotIndex { get; init; }
    public string RequestName { get; init; } = "";
    public string Url { get; init; } = "";
    public string Method { get; init; } = "POST";
    public string Session { get; init; } = RaceLabSessions.Driver;
    public string Role { get; init; } = RaceLabRoles.Observe;
    public int Status { get; init; }
    public double LatencyMs { get; init; }
    public string BodyHash { get; init; } = "";
    public string? BodySnippet { get; init; }
    public bool Accepted { get; init; }
    public string Phase { get; init; } = "burst";
    public string? ResourceId { get; init; }
    /// <summary>Order/charge/booking ids and Location tokens from this response. Request ids are omitted.</summary>
    public List<string> SideEffectIds { get; init; } = [];
    /// <summary>Cookie names sent with this shot. Values are never included.</summary>
    public List<string> CookiesSent { get; init; } = [];
    /// <summary>Which session identity was on the wire, e.g. <c>driver/browser-session</c> or <c>peer/anonymous</c>.</summary>
    public string? IdentityUsed { get; init; }
    public string? Error { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResponsePattern { get; init; }
    public bool? ResponsePatternMatched { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResponsePatternError { get; init; }
}

public sealed class RaceLabSyncResult
{
    public Dictionary<string, double> MedianRttMs { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int> DispatchOffsetMs { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class RaceLabRunResult
{
    public string Message { get; init; } = "";
    public int ElapsedMs { get; init; }
    public RaceLabSyncResult? Sync { get; init; }
    public List<RaceLabTimelineEntry> Baseline { get; init; } = [];
    public List<RaceLabTimelineEntry> Timeline { get; init; } = [];
    public List<UnifiedSecurityFinding> Findings { get; init; } = [];
    public List<string> Summary { get; init; } = [];

    public SecurityScanResult ToScanResult(string profileName)
    {
        var details = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["profile"] = profileName,
            ["baseline"] = Baseline.Select(RaceLabJson.TimelineEntryToApi).ToList(),
            ["timeline"] = Timeline.Select(RaceLabJson.TimelineEntryToApi).ToList()
        };
        if (Sync != null)
        {
            details["sync"] = new
            {
                medianRttMs = Sync.MedianRttMs,
                dispatchOffsetMs = Sync.DispatchOffsetMs
            };
        }

        return new SecurityScanResult
        {
            Message = Message,
            Depth = SecurityScanDepth.Standard,
            CandidatesProbed = Baseline.Count,
            PayloadsSent = Timeline.Count,
            ElapsedMs = ElapsedMs,
            Findings = Findings,
            Summary = Summary,
            Details = details
        };
    }
}

public sealed class RaceLabRunOptions
{
    public bool RunSync { get; set; } = true;
    public bool RunBaseline { get; set; } = true;
    public bool EnsurePeerOrigin { get; set; } = true;
}
