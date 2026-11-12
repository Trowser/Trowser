using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Probes CSRF defenses that rely on custom headers (X-Requested-With) or non-simple Content-Type.
/// </summary>
public sealed class CsrfCustomHeaderProber
{
    private static readonly string[] CustomHeaderNames =
    [
        "X-Requested-With", "X-Request-With", "X-HTTP-Method-Override"
    ];

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CsrfCustomHeaderProber(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<List<CsrfScenario>> RunAsync(
        IReadOnlyList<CsrfProbeCandidate> candidates,
        int maxProbes,
        IReadOnlySet<string>? skipHeaderOmitKeys = null,
        CancellationToken ct = default)
    {
        var scenarios = new List<CsrfScenario>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var budget = maxProbes;

        foreach (var candidate in candidates)
        {
            if (budget <= 0) break;
            ct.ThrowIfCancellationRequested();

            var omitKey = $"{candidate.Method}|{candidate.Url}";
            var skipOmit = skipHeaderOmitKeys != null && skipHeaderOmitKeys.Contains(omitKey);
            if (!skipOmit)
            {
            foreach (var headerName in CustomHeaderNames)
            {
                if (budget <= 0) break;
                if (!candidate.RequestHeaders.Keys.Any(k => k.Equals(headerName, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var key = $"{candidate.Method}|{candidate.Url}|omit-{headerName}";
                if (!seen.Add(key)) continue;

                var headers = new Dictionary<string, string>(candidate.RequestHeaders, StringComparer.OrdinalIgnoreCase);
                headers.Remove(headerName);
                headers.Remove("Cookie");
                headers.Remove("cookie");

                var (status, body) = await FetchAsync(candidate.Url, candidate.Method, headers, candidate.RequestBody);
                budget--;

                var eval = CsrfProbeResponseEvaluator.EvaluateMissingTokenProbe(
                    candidate.OriginalStatus, candidate.OriginalBody ?? "",
                    status, body);

                scenarios.Add(new CsrfScenario
                {
                    Url = candidate.Url,
                    Path = candidate.Path,
                    Method = candidate.Method,
                    TestType = eval.Vulnerable ? "custom-header-omitted" : "custom-header-omitted-inconclusive",
                    Severity = eval.Vulnerable ? "medium" : "info",
                    Description =
                        $"Request without {headerName} header (baseline had it). {eval.Summary} " +
                        "If the server accepts the request without this header, CSRF may be possible from simple cross-site forms.",
                    OriginalStatus = candidate.OriginalStatus,
                    TestStatus = status,
                    Vulnerable = eval.Vulnerable,
                    TokenLocation = $"header: {headerName}",
                });
            }
            }

            if (budget <= 0) break;
            if (candidate.RequestBody == null || candidate.Method is not ("POST" or "PUT" or "PATCH"))
                continue;

            var ctKey = $"{candidate.Method}|{candidate.Url}|text-plain";
            if (!seen.Add(ctKey)) continue;

            var plainHeaders = new Dictionary<string, string>(candidate.RequestHeaders, StringComparer.OrdinalIgnoreCase);
            plainHeaders.Remove("Cookie");
            plainHeaders.Remove("cookie");
            plainHeaders["Content-Type"] = "text/plain";

            string plainBody;
            if (candidate.RequestBody.TrimStart().StartsWith('{'))
            {
                plainBody = candidate.RequestBody;
            }
            else if (candidate.RequestBody.Contains('='))
            {
                plainBody = candidate.RequestBody;
            }
            else
            {
                plainBody = candidate.RequestBody;
            }

            var (plainStatus, plainBodyText) = await FetchAsync(candidate.Url, candidate.Method, plainHeaders, plainBody);
            budget--;

            var plainEval = CsrfProbeResponseEvaluator.EvaluateMissingTokenProbe(
                candidate.OriginalStatus, candidate.OriginalBody ?? "",
                plainStatus, plainBodyText);

            if (plainStatus is >= 200 and < 300)
            {
                scenarios.Add(new CsrfScenario
                {
                    Url = candidate.Url,
                    Path = candidate.Path,
                    Method = candidate.Method,
                    TestType = plainEval.Vulnerable ? "simple-content-type-accepted" : "simple-content-type-inconclusive",
                    Severity = plainEval.Vulnerable ? "high" : "low",
                    Description =
                        $"POST with Content-Type: text/plain (simple request). {plainEval.Summary} " +
                        "Simple cross-site requests may forge this endpoint if cookies are sent.",
                    OriginalStatus = candidate.OriginalStatus,
                    TestStatus = plainStatus,
                    Vulnerable = plainEval.Vulnerable,
                    TokenLocation = "Content-Type: text/plain",
                });
            }
        }

        return scenarios;
    }

    private async Task<(int Status, string Body)> FetchAsync(
        string url, string method, Dictionary<string, string> headers, string? body)
    {
        try
        {
            var json = await _ctx.Fetch(url, method, headers, body, 10000);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.GetProperty("status").GetInt32();
            var text = doc.RootElement.TryGetProperty("body", out var b)
                ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
                : "";
            return (status, text);
        }
        catch
        {
            return (0, "");
        }
    }
}
