using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

/// <summary>Detects search/query URL pairs that already differ in status or size in session traffic.</summary>
internal static class XsLeakSearchTrafficOracle
{
    private static readonly string[] SearchParamKeys = ["q", "query", "search", "term", "keyword", "s"];

    public sealed class ObservedPair
    {
        public string ParamKey { get; init; } = "";
        public string HitUrl { get; init; } = "";
        public string MissUrl { get; init; } = "";
        public string Detail { get; init; } = "";
        public XsLeakScanner.StateSpec? HitState { get; init; }
        public XsLeakScanner.StateSpec? MissState { get; init; }
    }

    public static ObservedPair? TryFindPair(IReadOnlyList<NetworkEntry> entries, string host)
    {
        var candidates = entries
            .Where(e => !e.IsTrowserGenerated
                        && e.Method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                        && Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                        && string.Equals(u.Host, host, StringComparison.OrdinalIgnoreCase)
                        && !ProtectedResourceOracle.IsUnreliableProtectedOracle(e.Url)
                        && !string.IsNullOrEmpty(u.Query))
            .ToList();

        ObservedPair? best = null;
        var bestScore = 0;

        foreach (var key in SearchParamKeys)
        {
            var byPath = new Dictionary<string, List<(NetworkEntry Entry, Uri Uri)>>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in candidates)
            {
                if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u))
                    continue;
                if (!QueryContainsParam(u, key))
                    continue;
                var pathKey = u.GetLeftPart(UriPartial.Path) + "?" + key;
                if (!byPath.TryGetValue(pathKey, out var list))
                {
                    list = [];
                    byPath[pathKey] = list;
                }
                list.Add((e, u));
            }

            foreach (var (_, group) in byPath)
            {
                if (group.Count < 2)
                    continue;

                for (var i = 0; i < group.Count; i++)
                {
                    for (var j = i + 1; j < group.Count; j++)
                    {
                        var (ea, ua) = group[i];
                        var (eb, ub) = group[j];
                        if (string.Equals(NormalizeQueryValue(ua, key), NormalizeQueryValue(ub, key),
                                StringComparison.Ordinal))
                            continue;

                        if (!TryScoreDelta(ea, eb, out var score, out var detail))
                            continue;

                        if (score <= bestScore) continue;
                        bestScore = score;
                        var (hit, miss) = PickHitMiss(ea, eb);
                        best = new ObservedPair
                        {
                            ParamKey = key,
                            HitUrl = hit,
                            MissUrl = miss,
                            Detail = detail
                        };
                    }
                }
            }
        }

        var post = TryFindPostBodyPair(entries, host);
        if (post != null && post.Score > bestScore)
        {
            bestScore = post.Score;
            best = post.Pair;
        }

        return best;
    }

    private sealed class ScoredPostPair
    {
        public ObservedPair Pair { get; init; } = null!;
        public int Score { get; init; }
    }

    private static ScoredPostPair? TryFindPostBodyPair(IReadOnlyList<NetworkEntry> entries, string host)
    {
        var candidates = entries
            .Where(e => !e.IsTrowserGenerated
                        && NetworkEntry.MethodMayHaveRequestBody(e.Method)
                        && !string.IsNullOrWhiteSpace(e.RequestBody)
                        && Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                        && string.Equals(u.Host, host, StringComparison.OrdinalIgnoreCase)
                        && !ProtectedResourceOracle.IsUnreliableProtectedOracle(e.Url))
            .ToList();

        ScoredPostPair? best = null;
        var byUrl = candidates.GroupBy(e => e.Url, StringComparer.OrdinalIgnoreCase);
        foreach (var group in byUrl)
        {
            var list = group.ToList();
            if (list.Count < 2) continue;

            for (var i = 0; i < list.Count; i++)
            {
                for (var j = i + 1; j < list.Count; j++)
                {
                    var ea = list[i];
                    var eb = list[j];
                    if (string.Equals(NormalizeBody(ea.RequestBody), NormalizeBody(eb.RequestBody),
                            StringComparison.Ordinal))
                        continue;

                    if (!TryScoreDelta(ea, eb, out var score, out var detail))
                        continue;

                    var hitEntry = PreferHitEntry(ea, eb);
                    var missEntry = ReferenceEquals(hitEntry, ea) ? eb : ea;
                    if (!string.Equals(hitEntry.Url, missEntry.Url, StringComparison.OrdinalIgnoreCase))
                        continue;

                    var ct = hitEntry.RequestHeaders.TryGetValue("Content-Type", out var ct1) ? ct1
                        : hitEntry.RequestHeaders.TryGetValue("content-type", out var ct2) ? ct2
                        : "application/json";

                    var pair = new ObservedPair
                    {
                        ParamKey = "(POST body)",
                        HitUrl = hitEntry.Url,
                        MissUrl = missEntry.Url,
                        Detail = detail + " Observed POST body delta on same endpoint.",
                        HitState = new XsLeakScanner.StateSpec
                        {
                            Label = "search-hit",
                            Url = hitEntry.Url,
                            Method = hitEntry.Method,
                            Body = hitEntry.RequestBody,
                            ContentType = ct,
                            Role = "hit"
                        },
                        MissState = new XsLeakScanner.StateSpec
                        {
                            Label = "search-miss",
                            Url = missEntry.Url,
                            Method = missEntry.Method,
                            Body = missEntry.RequestBody,
                            ContentType = ct,
                            Role = "miss"
                        }
                    };

                    if (best == null || score > best.Score)
                        best = new ScoredPostPair { Pair = pair, Score = score };
                }
            }
        }

        return best;
    }

    private static string NormalizeBody(string? body) =>
        string.IsNullOrWhiteSpace(body) ? "" : body.Trim();

    private static bool QueryContainsParam(Uri u, string key)
    {
        var q = u.Query.TrimStart('?');
        if (string.IsNullOrEmpty(q)) return false;
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var name = eq < 0 ? part : part[..eq];
            if (name.Equals(key, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string NormalizeQueryValue(Uri u, string key)
    {
        foreach (var part in u.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var name = part[..eq];
            if (!name.Equals(key, StringComparison.OrdinalIgnoreCase)) continue;
            return Uri.UnescapeDataString(part[(eq + 1)..]);
        }
        return "";
    }

    private static long EffectiveLength(NetworkEntry e)
    {
        if (e.ContentLengthBytes is > 0)
            return e.ContentLengthBytes.Value;
        if (!string.IsNullOrEmpty(e.ResponseBody))
            return e.ResponseBody.Length;
        return 0;
    }

    private static bool TryScoreDelta(NetworkEntry a, NetworkEntry b, out int score, out string detail)
    {
        score = 0;
        detail = "";
        var statusDiff = a.StatusCode != b.StatusCode;
        var lenA = EffectiveLength(a);
        var lenB = EffectiveLength(b);
        var lenDiff = Math.Abs(lenA - lenB);
        const long minLenDelta = 32;

        if (statusDiff)
        {
            score = 100 + (int)Math.Min(lenDiff, 999);
            detail = $"Observed status {a.StatusCode} vs {b.StatusCode} (length {lenA} vs {lenB} bytes).";
            return true;
        }

        if (lenDiff >= minLenDelta)
        {
            score = 50 + (int)Math.Min(lenDiff, 999);
            detail = $"Observed same status {a.StatusCode} but response length {lenA} vs {lenB} bytes.";
            return true;
        }

        return false;
    }

    private static (string Hit, string Miss) PickHitMiss(NetworkEntry a, NetworkEntry b)
    {
        var hit = PreferHitEntry(a, b);
        var miss = ReferenceEquals(hit, a) ? b : a;
        return (hit.Url, miss.Url);
    }

    private static NetworkEntry PreferHitEntry(NetworkEntry a, NetworkEntry b)
    {
        var lenA = EffectiveLength(a);
        var lenB = EffectiveLength(b);
        var aLooksHit = a.StatusCode is >= 200 and < 300 && (lenA >= lenB || b.StatusCode >= 400);
        if (aLooksHit && !(b.StatusCode is >= 200 and < 300 && lenB > lenA))
            return a;
        if (b.StatusCode is >= 200 and < 300 && lenB >= lenA)
            return b;
        return lenA >= lenB ? a : b;
    }
}
