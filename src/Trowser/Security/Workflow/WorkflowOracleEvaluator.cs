using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Api;
using Trowser.Security.Runtime;

namespace Trowser.Security.Workflow;

public sealed class WorkflowOracleEvaluator
{
    private static readonly JsonSerializerOptions CompactJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public async Task<OracleCheckResult> EvaluateAsync(
        JsonElement oracle,
        WorkflowExecutionContext ctx,
        WorkflowDependencies deps)
    {
        if (oracle.ValueKind != JsonValueKind.Object)
            return Fail("oracle", "Oracle must be a JSON object.");

        var type = oracle.TryGetProperty("type", out var tEl) ? tEl.GetString()?.ToLowerInvariant() : null;
        if (string.IsNullOrEmpty(type))
            return Fail("oracle", "Oracle requires 'type'.");

        return type switch
        {
            "and" => await EvaluateCompositeAsync(oracle, ctx, deps, all: true),
            "or" => await EvaluateCompositeAsync(oracle, ctx, deps, all: false),
            "effectcheck" or "effect-check" or "expression" => await EvaluateExpressionAsync(oracle, ctx, deps),
            "fetch" => await EvaluateFetchAsync(oracle, ctx, deps, useLastTrigger: oracle.TryGetProperty("lastTrigger", out var lt) && lt.ValueKind == JsonValueKind.True),
            "peerfetch" or "peer-fetch" => await EvaluatePeerFetchAsync(oracle, ctx, deps),
            "domdiff" or "dom-diff" => EvaluateDomDiff(oracle, ctx, deps),
            "networkmatch" or "network-match" => EvaluateNetworkMatch(oracle, ctx, deps),
            "cookiedelta" or "cookie-delta" => await EvaluateCookieDeltaAsync(oracle, ctx, deps),
            "storagedelta" or "storage-delta" => await EvaluateStorageDeltaAsync(oracle, ctx, deps),
            "screenshotcompare" or "screenshot-compare" => await EvaluateScreenshotCompareAsync(oracle, ctx, deps),
            "sinkreached" or "sink-reached" => EvaluateSinkReached(oracle, ctx, deps),
            "messagedelivered" or "message-delivered" => EvaluateMessageDelivered(oracle, ctx, deps),
            "prototypepolluted" or "prototype-polluted" => await EvaluatePrototypePollutedAsync(oracle, ctx, deps),
            _ => Fail(type, $"Unknown oracle type: {type}")
        };
    }

    private async Task<OracleCheckResult> EvaluateCompositeAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps, bool all)
    {
        if (!oracle.TryGetProperty("checks", out var checks) || checks.ValueKind != JsonValueKind.Array)
            return Fail("composite", "Composite oracle requires 'checks' array.");

        var results = new List<OracleCheckResult>();
        foreach (var check in checks.EnumerateArray())
        {
            var r = await EvaluateAsync(check, ctx, deps);
            results.Add(r);
            if (all && !r.Passed) return CompositeResult(all ? "and" : "or", false, results);
            if (!all && r.Passed) return CompositeResult(all ? "and" : "or", true, results);
        }

        return CompositeResult(all ? "and" : "or", !all ? false : true, results);
    }

    private static OracleCheckResult CompositeResult(string type, bool passed, List<OracleCheckResult> results) =>
        new()
        {
            Type = type,
            Passed = passed,
            Evidence = new { checkCount = results.Count, passedCount = results.Count(r => r.Passed), results },
            Artifacts = results.SelectMany(r => r.Artifacts).ToList()
        };

    private async Task<OracleCheckResult> EvaluateExpressionAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        if (oracle.TryGetProperty("effectCheck", out var ecEl) && ecEl.ValueKind == JsonValueKind.String)
        {
            var expr = WorkflowVarSubstitution.Substitute(ecEl.GetString(), ctx.Vars);
            var timeoutMs = oracle.TryGetProperty("timeoutMs", out var tmEl) && tmEl.ValueKind == JsonValueKind.Number
                ? Math.Clamp(tmEl.GetInt32(), 250, 60_000) : 8_000;
            var pollMs = oracle.TryGetProperty("pollMs", out var pmEl) && pmEl.ValueKind == JsonValueKind.Number
                ? Math.Clamp(pmEl.GetInt32(), 50, 2_000) : 250;

            string? raw = null;
            var passed = false;
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            do
            {
                raw = await deps.Context.ExecuteJs(expr);
                passed = IsTruthyJsResult(raw);
                if (passed) break;
                if (DateTime.UtcNow >= deadline) break;
                await Task.Delay(pollMs, deps.Cancellation);
            } while (true);

            return new OracleCheckResult
            {
                Type = "effectCheck",
                Passed = passed,
                Evidence = new { expression = expr, result = raw, timeoutMs, pollMs },
                Artifacts = [new { kind = "jsResult", value = raw }]
            };
        }

        var leftRaw = oracle.TryGetProperty("left", out var lEl) ? lEl.GetString() : null;
        var left = leftRaw != null ? WorkflowVarSubstitution.Substitute(leftRaw, ctx.Vars) : null;
        if (left == null)
            return Fail("expression", "expression oracle requires effectCheck or left.");

        var capturedVars = ctx.Vars.ToDictionary(kv => kv.Key, kv => kv.Value);

        if (oracle.TryGetProperty("contains", out var cEl))
        {
            var needleRaw = cEl.GetString();
            var needle = WorkflowVarSubstitution.Substitute(needleRaw, ctx.Vars);
            var passed = !string.IsNullOrEmpty(needle) && left.Contains(needle, StringComparison.Ordinal);
            return new OracleCheckResult
            {
                Type = "expression", Passed = passed,
                Evidence = new { left, leftRaw, contains = needle, needleRaw, capturedVars }
            };
        }

        if (oracle.TryGetProperty("equals", out var eqEl))
        {
            var expectedRaw = eqEl.GetString();
            var expected = WorkflowVarSubstitution.Substitute(expectedRaw, ctx.Vars);
            var passed = string.Equals(left, expected, StringComparison.Ordinal);
            return new OracleCheckResult
            {
                Type = "expression", Passed = passed,
                Evidence = new { left, leftRaw, expected, expectedRaw, capturedVars }
            };
        }

        if (oracle.TryGetProperty("matches", out var mEl))
        {
            var patternRaw = mEl.GetString();
            var pattern = WorkflowVarSubstitution.Substitute(patternRaw, ctx.Vars);
            var passed = !string.IsNullOrEmpty(pattern) && Regex.IsMatch(left, pattern);
            return new OracleCheckResult
            {
                Type = "expression", Passed = passed,
                Evidence = new { left, leftRaw, pattern, patternRaw, capturedVars }
            };
        }

        if (oracle.TryGetProperty("notMatches", out var nmEl))
        {
            var patternRaw = nmEl.GetString();
            var pattern = WorkflowVarSubstitution.Substitute(patternRaw, ctx.Vars);
            var passed = string.IsNullOrEmpty(pattern) || !Regex.IsMatch(left ?? "", pattern);
            return new OracleCheckResult
            {
                Type = "expression", Passed = passed,
                Evidence = new { left, leftRaw, notMatches = pattern, patternRaw, capturedVars }
            };
        }

        return Fail("expression", "expression oracle requires contains, equals, matches, or notMatches.");
    }

    private async Task<OracleCheckResult> EvaluateFetchAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps, bool useLastTrigger)
    {
        JsonElement fetch;
        if (useLastTrigger && ctx.LastTriggerFetch != null)
            fetch = ctx.LastTriggerFetch.Value;
        else if (oracle.TryGetProperty("url", out _))
        {
            var step = WorkflowVarSubstitution.SubstituteElement(oracle, ctx.Vars);
            var exec = new WorkflowStepExecutor();
            var result = await exec.ExecuteAsync(step, 0, "oracle", ctx, deps);
            if (result.TryGetValue("success", out var ok) && ok is false)
                return Fail("fetch", result.TryGetValue("error", out var err) ? err?.ToString() ?? "fetch failed" : "fetch failed");
            fetch = ctx.LastFetch!.Value;
        }
        else if (ctx.LastFetch != null)
            fetch = ctx.LastFetch.Value;
        else
            return Fail("fetch", "No fetch result available for oracle.");

        var status = fetch.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
        var body = fetch.TryGetProperty("body", out var b) ? b.GetString() : null;

        if (oracle.TryGetProperty("expect", out var expect) && expect.ValueKind == JsonValueKind.Object)
        {
            if (expect.TryGetProperty("status", out var es) && es.ValueKind == JsonValueKind.Number && status != es.GetInt32())
                return new OracleCheckResult { Type = "fetch", Passed = false, Evidence = new { status, expectedStatus = es.GetInt32() } };

            if (expect.TryGetProperty("bodyContains", out var bc))
            {
                var needle = WorkflowVarSubstitution.Substitute(bc.GetString(), ctx.Vars);
                if (string.IsNullOrEmpty(body) || !body.Contains(needle, StringComparison.Ordinal))
                    return new OracleCheckResult { Type = "fetch", Passed = false, Evidence = new { status, bodyContains = needle } };
            }
        }

        return new OracleCheckResult
        {
            Type = "fetch",
            Passed = true,
            Evidence = new { status, bodyLength = body?.Length ?? 0, bodyHash = WorkflowVarSubstitution.BodyHash(body) }
        };
    }

    private async Task<OracleCheckResult> EvaluatePeerFetchAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var peer = oracle.TryGetProperty("peer", out var pEl) ? pEl.GetString() : null;
        var url = WorkflowVarSubstitution.Substitute(oracle.TryGetProperty("url", out var uEl) ? uEl.GetString() : null, ctx.Vars);
        if (string.IsNullOrWhiteSpace(peer) || string.IsNullOrWhiteSpace(url) || deps.Peers == null)
            return Fail("peerFetch", "peerFetch requires peer, url, and registered peers.");

        var method = oracle.TryGetProperty("method", out var mEl) ? mEl.GetString() ?? "GET" : "GET";
        var fetchTimeout = oracle.TryGetProperty("timeout", out var tEl) && tEl.TryGetInt32(out var tm) ? tm : 0;
        var fetchBody = new Dictionary<string, object?> { ["url"] = url, ["method"] = method };
        if (fetchTimeout > 0) fetchBody["timeout"] = fetchTimeout;
        var resp = await deps.Peers.ForwardAsync(peer, "POST", "/api/fetch-direct", JsonSerializer.Serialize(fetchBody, CompactJson),
            timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(fetchTimeout));
        if (!resp.Success && resp.StatusCode != 200)
            return Fail("peerFetch", resp.Body ?? "peer fetch failed");

        using var doc = JsonDocument.Parse(resp.Body ?? "{}");
        var data = doc.RootElement.TryGetProperty("data", out var d) ? d : doc.RootElement;
        var status = data.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
        var body = data.TryGetProperty("body", out var b) ? b.GetString() : null;

        if (oracle.TryGetProperty("expect", out var expect) && expect.TryGetProperty("status", out var es) && es.ValueKind == JsonValueKind.Number)
        {
            var passed = status == es.GetInt32();
            return new OracleCheckResult { Type = "peerFetch", Passed = passed, Evidence = new { peer, status, url } };
        }

        return new OracleCheckResult { Type = "peerFetch", Passed = true, Evidence = new { peer, status, bodyLength = body?.Length ?? 0 } };
    }

    private OracleCheckResult EvaluateDomDiff(JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var before = ctx.RefGenerationBeforeTrigger;
        var after = deps.Context.RefGeneration;
        if (before <= 0 || after <= 0)
            return Fail("domDiff", "Missing refGeneration markers. Capture refGeneration before trigger.");

        var diff = deps.Context.BuildRefGenerationDiff(before, after, out var error);
        if (diff == null)
            return Fail("domDiff", error ?? "domDiff failed");

        var changed = diff.TryGetValue("changedCount", out var cc) && cc is int n ? n : 0;
        var expectChanges = !oracle.TryGetProperty("expectChanges", out var ec) || ec.ValueKind != JsonValueKind.False;
        var passed = expectChanges ? changed > 0 : changed == 0;
        return new OracleCheckResult { Type = "domDiff", Passed = passed, Evidence = diff, Artifacts = [diff] };
    }

    private OracleCheckResult EvaluateNetworkMatch(JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var entries = deps.Context.GetNetworkLog();
        var slice = entries.Skip(Math.Min(ctx.NetworkMarkerIndex, entries.Count)).ToList();

        var urlPattern = oracle.TryGetProperty("url", out var u) ? u.GetString() : null;
        var method = oracle.TryGetProperty("method", out var m) ? m.GetString() : null;
        int? status = oracle.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : null;

        var matches = slice.Where(e =>
            (urlPattern == null || (e.Url?.Contains(urlPattern, StringComparison.OrdinalIgnoreCase) ?? false)) &&
            (method == null || string.Equals(e.Method, method, StringComparison.OrdinalIgnoreCase)) &&
            (status == null || e.StatusCode == status)).ToList();

        var minCount = oracle.TryGetProperty("minCount", out var mc) && mc.ValueKind == JsonValueKind.Number ? mc.GetInt32() : 1;
        var passed = matches.Count >= minCount;
        return new OracleCheckResult
        {
            Type = "networkMatch",
            Passed = passed,
            Evidence = new { matchCount = matches.Count, minCount, sample = matches.Take(3).Select(e => new { e.Method, e.Url, status = e.StatusCode }) }
        };
    }

    private async Task<OracleCheckResult> EvaluateCookieDeltaAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var cookies = await deps.Context.GetCookies();
        var expectName = oracle.TryGetProperty("added", out var a) ? a.GetString() : null;
        if (!string.IsNullOrEmpty(expectName))
        {
            var passed = cookies.Any(c => c.TryGetValue("name", out var n) && n?.ToString()?.Equals(expectName, StringComparison.OrdinalIgnoreCase) == true);
            return new OracleCheckResult { Type = "cookieDelta", Passed = passed, Evidence = new { cookieCount = cookies.Count, added = expectName } };
        }
        return new OracleCheckResult { Type = "cookieDelta", Passed = cookies.Count > 0, Evidence = new { cookieCount = cookies.Count } };
    }

    private async Task<OracleCheckResult> EvaluateStorageDeltaAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var kind = oracle.TryGetProperty("storage", out var sk) ? sk.GetString() ?? "local" : "local";
        var storage = await deps.Context.GetAllStorage(kind);
        var key = oracle.TryGetProperty("key", out var k) ? k.GetString() : null;
        if (!string.IsNullOrEmpty(key))
        {
            var passed = storage.ContainsKey(key);
            return new OracleCheckResult { Type = "storageDelta", Passed = passed, Evidence = new { storage = kind, key, present = passed } };
        }
        return new OracleCheckResult { Type = "storageDelta", Passed = storage.Count > 0, Evidence = new { storage = kind, count = storage.Count } };
    }

    private async Task<OracleCheckResult> EvaluateScreenshotCompareAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var beforePath = ctx.ScreenshotBeforeTrigger;
        if (string.IsNullOrEmpty(beforePath) || !File.Exists(beforePath))
            return Fail("screenshotCompare", "Missing before-trigger screenshot.");

        var beforeBytes = await File.ReadAllBytesAsync(beforePath, deps.Cancellation);
        var afterBytes = await deps.Context.ScreenshotToBytes();
        var threshold = oracle.TryGetProperty("threshold", out var th) && th.ValueKind == JsonValueKind.Number ? th.GetInt32() : 30;
        var result = await deps.Context.CompareScreenshots(beforeBytes, afterBytes, threshold);

        var maxDiff = oracle.TryGetProperty("maxDiffPercent", out var md) && md.ValueKind == JsonValueKind.Number ? md.GetDouble() : 100.0;
        var passed = oracle.TryGetProperty("expectMatch", out var em) && em.ValueKind == JsonValueKind.True
            ? result.DiffPercent == 0
            : result.DiffPercent <= maxDiff;

        return new OracleCheckResult
        {
            Type = "screenshotCompare",
            Passed = passed,
            Evidence = new { result.DiffPercent, result.ChangedPixels, result.TotalPixels, threshold },
            Artifacts = [new { kind = "screenshotDiff", diffPercent = result.DiffPercent }]
        };
    }

    private static OracleCheckResult EvaluateSinkReached(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var log = deps.Context.ActiveTab.RuntimeEvents;
        var slice = log.SliceSinceMark();
        var sinkFilter = oracle.TryGetProperty("sink", out var sEl) ? sEl.GetString() : null;
        var contains = oracle.TryGetProperty("contains", out var cEl) ? cEl.GetString() : null;

        var sinks = slice.Where(e => e.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase)).ToList();
        if (!string.IsNullOrEmpty(sinkFilter))
            sinks = sinks.Where(e => e.Name.Equals(sinkFilter, StringComparison.OrdinalIgnoreCase)).ToList();
        if (!string.IsNullOrEmpty(contains))
            sinks = sinks.Where(e => e.Data != null && e.Data.Contains(contains, StringComparison.OrdinalIgnoreCase)).ToList();

        return new OracleCheckResult
        {
            Type = "sinkReached",
            Passed = sinks.Count > 0,
            Evidence = new
            {
                hitCount = sinks.Count,
                sinks = sinks.Take(10).Select(e => new { e.Name, e.Data, e.Stack }).ToList()
            }
        };
    }

    private static OracleCheckResult EvaluateMessageDelivered(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var slice = deps.Context.ActiveTab.RuntimeEvents.SliceSinceMark();
        var origin = oracle.TryGetProperty("origin", out var oEl) ? oEl.GetString() : null;
        var contains = oracle.TryGetProperty("contains", out var cEl) ? cEl.GetString() : null;

        var messages = slice
            .Where(e => e.Kind.Equals("message", StringComparison.OrdinalIgnoreCase) && !e.IsSensorInternalMessage)
            .ToList();
        if (!string.IsNullOrEmpty(origin))
            messages = messages.Where(e =>
                e.Extra.TryGetValue("origin", out var o) &&
                o != null &&
                o.Equals(origin, StringComparison.OrdinalIgnoreCase)).ToList();
        if (!string.IsNullOrEmpty(contains))
            messages = messages.Where(e => e.Data != null && e.Data.Contains(contains, StringComparison.OrdinalIgnoreCase)).ToList();

        return new OracleCheckResult
        {
            Type = "messageDelivered",
            Passed = messages.Count > 0,
            Evidence = new
            {
                hitCount = messages.Count,
                messages = messages.Take(10).Select(e => new { e.Data, origin = e.Extra.GetValueOrDefault("origin"), isTrusted = e.Extra.GetValueOrDefault("isTrusted") }).ToList()
            }
        };
    }

    private static async Task<OracleCheckResult> EvaluatePrototypePollutedAsync(
        JsonElement oracle, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var key = oracle.TryGetProperty("key", out var kEl) ? kEl.GetString() ?? "trowserPp" : "trowserPp";
        var expect = oracle.TryGetProperty("value", out var vEl) ? vEl.GetString() : null;
        var script = expect == null
            ? $@"(function(){{ try {{ return JSON.stringify({{ polluted: Object.prototype[{JsonSerializer.Serialize(key)}] !== undefined, value: Object.prototype[{JsonSerializer.Serialize(key)}] }}); }} catch(e){{ return JSON.stringify({{polluted:false}}); }} }})()"
            : $@"(function(){{ try {{ return JSON.stringify({{ polluted: Object.prototype[{JsonSerializer.Serialize(key)}] === {JsonSerializer.Serialize(expect)}, value: Object.prototype[{JsonSerializer.Serialize(key)}] }}); }} catch(e){{ return JSON.stringify({{polluted:false}}); }} }})()";

        try
        {
            var raw = await deps.Context.ExecuteJs(script);
            using var doc = JsonDocument.Parse(UnquoteJs(raw));
            var polluted = doc.RootElement.TryGetProperty("polluted", out var p) && p.ValueKind == JsonValueKind.True;
            return new OracleCheckResult
            {
                Type = "prototypePolluted",
                Passed = polluted,
                Evidence = new { key, polluted, value = doc.RootElement.TryGetProperty("value", out var v) ? v.ToString() : null }
            };
        }
        catch (Exception ex)
        {
            return Fail("prototypePolluted", ex.Message);
        }
    }

    private static string UnquoteJs(string? json)
    {
        if (string.IsNullOrEmpty(json)) return "{}";
        var s = json.Trim();
        if (s.Length >= 2 && s[0] == '"')
        {
            try { return JsonSerializer.Deserialize<string>(s) ?? "{}"; }
            catch { return "{}"; }
        }
        return s;
    }

    private static OracleCheckResult Fail(string type, string error) =>
        new() { Type = type, Passed = false, Error = error, Evidence = new { error } };

    private static bool IsTruthyJsResult(string? raw) =>
        raw != null && (
            raw.Equals("true", StringComparison.OrdinalIgnoreCase)
            || raw == "1"
            || raw.Equals("\"true\"", StringComparison.OrdinalIgnoreCase));
}
