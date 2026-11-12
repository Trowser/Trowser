using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Trowser.Api;

namespace Trowser.Security.RaceLab;

internal static class RaceLabJson
{
    public static RaceLabProfile ParseProfile(JsonBody body)
    {
        if (body.GetJsonElement("profile") is { } profileEl)
            return ParseProfileElement(profileEl);

        return new RaceLabProfile
        {
            Name = body.GetString("name") ?? "custom",
            Requests = ParseRequests(body),
            Parameters = ParseParameters(body)
        };
    }

    public static RaceLabProfile ParseProfileElement(JsonElement el)
    {
        var profile = new RaceLabProfile
        {
            Name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : ""
        };

        if (el.TryGetProperty("requests", out var reqs) && reqs.ValueKind == JsonValueKind.Array)
            profile.Requests = ParseRequestsArray(reqs);

        if (el.TryGetProperty("parameters", out var p))
            profile.Parameters = ParseParametersElement(p);
        else
            profile.Parameters = ParseParametersFromRoot(el);

        return profile;
    }

    public static List<RaceLabRequest> ParseRequests(JsonBody body)
    {
        if (!body.HasProperty("requests"))
            return [];

        if (body.GetJsonElement("requests") is not { } raw)
            return [];

        return ParseRequestsArray(raw);
    }

    private static List<RaceLabRequest> ParseRequestsArray(JsonElement arr)
    {
        var list = new List<RaceLabRequest>();
        foreach (var item in arr.EnumerateArray())
        {
            list.Add(new RaceLabRequest
            {
                Name = item.TryGetProperty("name", out var nm) ? nm.GetString() ?? "" : "",
                Url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                Method = item.TryGetProperty("method", out var m) ? m.GetString() ?? "POST" : "POST",
                Body = item.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.String
                    ? b.GetString()
                    : null,
                Session = RaceLabSessions.Normalize(
                    item.TryGetProperty("session", out var s) ? s.GetString() : null),
                Role = RaceLabRoles.Normalize(
                    item.TryGetProperty("role", out var r) ? r.GetString() : null),
                ResponsePattern = item.TryGetProperty("responsePattern", out var rp) && rp.ValueKind == JsonValueKind.String
                    ? rp.GetString()
                    : null,
                Headers = ParseHeaders(item)
            });
        }

        return list;
    }

    private static Dictionary<string, string>? ParseHeaders(JsonElement item)
    {
        if (!item.TryGetProperty("headers", out var h) || h.ValueKind != JsonValueKind.Object)
            return null;

        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in h.EnumerateObject())
            dict[prop.Name] = prop.Value.GetString() ?? "";
        return dict.Count > 0 ? dict : null;
    }

    public static RaceLabParameters ParseParameters(JsonBody body) =>
        body.GetJsonElement("parameters") is { } p
            ? ParseParametersElement(p)
            : ParseParametersFromRoot(body.RootElement);

    private static RaceLabParameters ParseParametersFromRoot(JsonElement root)
    {
        var modeStr = root.TryGetProperty("mode", out var m) ? m.GetString() : null;
        var mode = ParseMode(modeStr);
        var p = RaceLabParameters.ForMode(mode);
        p.Mode = mode;
        if (root.TryGetProperty("requestsPerBatch", out var rpb) && rpb.TryGetInt32(out var rpbv))
            p.RequestsPerBatch = rpbv;
        if (root.TryGetProperty("delayPerRequestMs", out var dpr) && dpr.TryGetInt32(out var dprv))
            p.DelayPerRequestMs = dprv;
        if (root.TryGetProperty("delayBetweenBatchesMs", out var dbb) && dbb.TryGetInt32(out var dbbv))
            p.DelayBetweenBatchesMs = dbbv;
        if (root.TryGetProperty("totalBatches", out var tb) && tb.TryGetInt32(out var tbv))
            p.TotalBatches = tbv;
        if (root.TryGetProperty("durationMs", out var dm) && dm.TryGetInt32(out var dmv))
            p.DurationMs = dmv;
        if (root.TryGetProperty("randomizeOrder", out var ro))
            p.RandomizeOrder = ro.ValueKind == JsonValueKind.True;
        if (root.TryGetProperty("jitterMs", out var j) && j.TryGetInt32(out var jv))
            p.JitterMs = jv;
        if (root.TryGetProperty("timeoutMs", out var tm) && tm.TryGetInt32(out var tmv))
            p.TimeoutMs = tmv;
        if (root.TryGetProperty("includeBrowserCookies", out var ibc))
            p.IncludeBrowserCookies = ibc.ValueKind != JsonValueKind.False;
        return p;
    }

    private static RaceLabParameters ParseParametersElement(JsonElement el) =>
        ParseParametersFromRoot(el);

    private static RaceLabMode ParseMode(string? mode) =>
        (mode ?? "").Trim().ToLowerInvariant() switch
        {
            "hammer" => RaceLabMode.Hammer,
            "spike" => RaceLabMode.Spike,
            "sequential" => RaceLabMode.Sequential,
            "random" => RaceLabMode.Random,
            "custom" => RaceLabMode.Custom,
            _ => RaceLabMode.Custom
        };

    public static string HashBody(string? body)
    {
        body ??= "";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(body));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    public static object TimelineEntryToApi(RaceLabTimelineEntry e) => new
    {
        e.OffsetMs,
        e.BatchIndex,
        e.ShotIndex,
        e.RequestName,
        e.Url,
        e.Method,
        e.Session,
        e.Role,
        e.Status,
        e.LatencyMs,
        e.BodyHash,
        e.BodySnippet,
        e.Accepted,
        e.Phase,
        e.ResourceId,
        sideEffectIds = e.SideEffectIds,
        cookiesSent = e.CookiesSent,
        identityUsed = e.IdentityUsed,
        e.Error,
        e.ResponsePattern,
        e.ResponsePatternMatched,
        e.ResponsePatternError
    };
}
