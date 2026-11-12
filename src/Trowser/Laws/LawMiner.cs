using Trowser.Automation;

namespace Trowser.Laws;

/// <summary>
/// Passive observation of network and page patterns to propose Law candidates.
/// </summary>
public sealed class LawMiner
{
    private readonly LawProposalStore _proposals;
    private readonly Dictionary<string, int> _jsonFieldSeen = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _jsonFieldNull = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _endpointResponses = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _endpointNon2xx = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _jsonFieldPresent = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _hostActivity = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _hostConsoleErrors = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>Upper bound per counter so a long session (or a site with unbounded URLs) cannot grow memory forever.</summary>
    internal const int MaxKeysPerCounter = 5000;

    public LawMiner(LawProposalStore proposals) => _proposals = proposals;

    public void ObserveResponse(NetworkEntry entry, string pageHost)
    {
        if (IsNonMinableUrl(entry.Url))
            return;

        var path = NormalizeEndpointPath(entry.Url);
        lock (_lock)
        {
            if (!string.IsNullOrWhiteSpace(pageHost))
                Bump(_hostActivity, pageHost);

            if (!string.IsNullOrWhiteSpace(entry.Method) && !string.IsNullOrWhiteSpace(path))
            {
                var endpointKey = $"{pageHost}|{entry.Method}|{path}";
                Bump(_endpointResponses, endpointKey);
                if (entry.StatusCode < 200 || entry.StatusCode >= 300)
                    Bump(_endpointNon2xx, endpointKey);
            }

            ObserveJsonBody(entry, pageHost, path);
        }
    }

    public void ObserveConsole(ConsoleEntry entry, string pageHost)
    {
        if (string.IsNullOrWhiteSpace(pageHost))
            return;
        if (entry.Level == ConsoleLevel.Error)
        {
            lock (_lock)
                Bump(_hostConsoleErrors, pageHost);
        }
    }

    private static void Bump(Dictionary<string, int> counter, string key)
    {
        if (counter.TryGetValue(key, out var n))
            counter[key] = n + 1;
        else if (counter.Count < MaxKeysPerCounter)
            counter[key] = 1;
    }

    /// <summary>
    /// Path without query string, with id-like segments (numbers, GUIDs, long hex/base64 tokens) folded
    /// to <c>*</c>, so <c>/api/orders/123</c> and <c>/api/orders/456</c> count as one endpoint.
    /// </summary>
    internal static string NormalizeEndpointPath(string url)
    {
        var path = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.AbsolutePath : url.Split('?', '#')[0];
        var segments = path.Split('/');
        for (var i = 0; i < segments.Length; i++)
        {
            if (IsIdLikeSegment(segments[i]))
                segments[i] = "*";
        }
        return string.Join('/', segments);
    }

    private static bool IsIdLikeSegment(string seg)
    {
        if (seg.Length == 0)
            return false;
        if (seg.All(char.IsDigit))
            return true;
        if (Guid.TryParse(seg, out _))
            return true;
        if (seg.Length >= 16 && seg.All(Uri.IsHexDigit))
            return true;
        // Opaque tokens: long, mixed letters+digits, no separators typical of words.
        return seg.Length >= 20
               && seg.Any(char.IsDigit)
               && seg.Any(char.IsLetter)
               && seg.All(c => char.IsLetterOrDigit(c) || c is '_' or '-');
    }

    private void ObserveJsonBody(NetworkEntry entry, string pageHost, string path)
    {
        if (entry.StatusCode < 200 || entry.StatusCode >= 300)
            return;
        if (string.IsNullOrWhiteSpace(entry.ResponseBody))
            return;
        if (!entry.ContentType.Contains("json", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(entry.ResponseBody);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
                return;

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                var key = $"{pageHost}|{entry.Method}|{path}|{prop.Name}";
                Bump(_jsonFieldSeen, key);

                if (prop.Value.ValueKind == System.Text.Json.JsonValueKind.Null)
                    Bump(_jsonFieldNull, key);
                else
                    Bump(_jsonFieldPresent, key);
            }
        }
        catch
        {
            /* ignore parse errors */
        }
    }

    public void RankAndPropose(int minObservations = 5)
    {
        lock (_lock)
        {
            ProposeJsonNonNull(minObservations);
            ProposeHttpSuccess(minObservations);
            ProposeNoConsoleErrors(minObservations);
        }
    }

    private void ProposeJsonNonNull(int minObservations)
    {
        foreach (var (key, count) in _jsonFieldSeen)
        {
            if (count < minObservations)
                continue;
            var nulls = _jsonFieldNull.GetValueOrDefault(key);
            if (nulls > 0)
                continue;

            if (!TryParseFieldKey(key, out var host, out var method, out var path, out var field))
                continue;

            var id = $"mining:json-non-null:{key}";
            var code = $$"""
                Site("{{Escape(host)}}");

                Law("{{Escape(field)}} is never null on {{Escape(method)}} {{Escape(path)}}")
                    .OnResponse("{{Escape(method)}} {{Escape(path)}}")
                    .When((ResponseFacts r) => r.Status >= 200 && r.Status < 300 && r.Json.IsValid)
                    .Expect((ResponseFacts r) => r.Json.HasValue("{{Escape(field)}}"))
                    .Severity(Severity.Low);
                """;

            var evidence = new[]
            {
                $"Observed {count} JSON responses on {method} {path}.",
                $"Field '{field}' was never null in those bodies.",
                "Counterexamples (null values): 0."
            };

            _proposals.Add(new LawProposal
            {
                Id = id,
                Title = $"{field} non-null on {method} {path}",
                Code = code,
                Source = "mining",
                Kind = "json-non-null",
                Observations = count,
                Counterexamples = nulls,
                Host = host,
                Rationale =
                    $"While browsing {host}, '{field}' appeared in every sampled JSON response for {method} {path} and was never null ({count} samples).",
                Evidence = evidence
            });
        }
    }

    private void ProposeHttpSuccess(int minObservations)
    {
        foreach (var (key, total) in _endpointResponses)
        {
            if (total < minObservations)
                continue;
            if (_endpointNon2xx.GetValueOrDefault(key) > 0)
                continue;

            var parts = key.Split('|', 3);
            if (parts.Length < 3)
                continue;

            var host = parts[0];
            var method = parts[1];
            var path = parts[2];
            var id = $"mining:http-2xx:{key}";
            var code = $$"""
                Site("{{Escape(host)}}");

                Law("{{Escape(method)}} {{Escape(path)}} stays successful")
                    .OnResponse("{{Escape(method)}} {{Escape(path)}}")
                    .Expect((ResponseFacts r) => r.Status >= 200 && r.Status < 300);
                """;

            _proposals.Add(new LawProposal
            {
                Id = id,
                Title = $"{method} {path} always 2xx",
                Code = code,
                Source = "mining",
                Kind = "http-2xx",
                Observations = total,
                Counterexamples = 0,
                Host = host,
                Rationale =
                    $"All {total} captured responses for {method} {path} on {host} returned HTTP 2xx (no 4xx/5xx seen while mining).",
                Evidence =
                [
                    $"Sample size: {total} response(s) in this session.",
                    "Non-2xx responses: 0."
                ]
            });
        }
    }

    private void ProposeNoConsoleErrors(int minObservations)
    {
        foreach (var (host, responses) in _hostActivity)
        {
            if (responses < minObservations)
                continue;
            var errors = _hostConsoleErrors.GetValueOrDefault(host);
            if (errors > 0)
                continue;

            var id = $"mining:console-clean:{host}";
            var code = $$"""
                Site("{{Escape(host)}}");

                Law("No console errors on {{Escape(host)}}")
                    .OnConsole("error")
                    .Forbid((ConsoleFacts c) => true);
                """;

            _proposals.Add(new LawProposal
            {
                Id = id,
                Title = $"No console errors on {host}",
                Code = code,
                Source = "mining",
                Kind = "console-clean",
                Observations = responses,
                Counterexamples = errors,
                Host = host,
                Rationale =
                    $"Across {responses} network responses while browsing {host}, Shadow did not record console error-level messages. Consider this only after exercising key flows.",
                Evidence =
                [
                    $"Network responses observed on {host}: {responses}.",
                    "Console errors observed while mining: 0."
                ]
            });
        }
    }

    private static bool TryParseFieldKey(string key, out string host, out string method, out string path, out string field)
    {
        host = method = path = field = "";
        var parts = key.Split('|', 4);
        if (parts.Length < 4)
            return false;
        host = parts[0];
        method = parts[1];
        path = parts[2];
        field = parts[3];
        return true;
    }

    private static bool IsNonMinableUrl(string url) =>
        url.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
        || url.StartsWith("blob:", StringComparison.OrdinalIgnoreCase)
        || url.StartsWith("about:", StringComparison.OrdinalIgnoreCase);

    /// <summary>Escapes text for a C# string literal (URLs are attacker-controlled; never let them break out).</summary>
    private static string Escape(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var c in s)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                default:
                    if (char.IsControl(c)) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }
}
