using Trowser.Security;
using Trowser.Security.Orchestration;

namespace Trowser.Api;

internal static class TraceInputRequestParser
{
    public static bool TryParse(JsonBody body, out TraceInputOptions options, out List<string>? batchPayloads, out string? error)
    {
        options = null!;
        batchPayloads = null;
        error = null;

        var sourceRaw = body.GetString("source") ?? "form";
        TraceSourceType source;
        try
        {
            source = ParseSource(sourceRaw);
        }
        catch (ArgumentException ex)
        {
            error = ex.Message;
            return false;
        }

        var payload = body.GetString("payload");
        batchPayloads = body.GetStringArray("payloads");
        var autoBypass = body.GetBool("autoBypass", true);

        if (string.IsNullOrEmpty(payload) && (batchPayloads == null || batchPayloads.Count == 0) && !autoBypass)
        {
            error = "Missing 'payload' or 'payloads'.";
            return false;
        }

        if (autoBypass && batchPayloads is { Count: > 0 })
        {
            error = "autoBypass cannot be used with 'payloads'.";
            return false;
        }

        if (source == TraceSourceType.Form)
        {
            var target = body.GetString("target") ?? body.GetString("selector");
            if (string.IsNullOrEmpty(target))
            {
                error = "Missing 'target' — CSS selector for the input element (required when source is 'form').";
                return false;
            }

            options = BuildCommon(body, source, payload ?? XssBypassProbes.DefaultPrimaryPayload) with
            {
                TargetSelector = target,
                SubmitSelector = body.GetString("submit"),
                SubmitAction = body.GetString("submitAction") ?? "click"
            };
            return true;
        }

        options = BuildCommon(body, source, payload ?? XssBypassProbes.DefaultPrimaryPayload) with
        {
            BaseUrl = body.GetString("baseUrl") ?? body.GetString("url"),
            QueryParam = body.GetString("queryParam") ?? body.GetString("param") ?? "q",
            HashParam = body.GetString("hashParam"),
            StorageKey = body.GetString("storageKey") ?? "trowser_probe",
            StorageKind = body.GetString("storageKind") ?? "local",
            QueryEncode = UrlPayloadInjector.ParseEncodeMode(body.GetString("queryEncode"), UrlPayloadEncodeMode.None),
            FragmentEncode = UrlPayloadInjector.ParseEncodeMode(body.GetString("fragmentEncode"), UrlPayloadEncodeMode.None),
            PathEncode = UrlPayloadInjector.ParseEncodeMode(body.GetString("pathEncode"), UrlPayloadEncodeMode.Component),
            ExtraQuery = ParseExtraQuery(body)
        };
        return true;
    }

    private static TraceInputOptions BuildCommon(JsonBody body, TraceSourceType source, string payload)
    {
        var mode = SafetyGate.Resolve(body);
        var confirmExecution = body.HasProperty("confirmExecution")
            ? body.GetBool("confirmExecution")
            : mode >= SafetyMode.Aggressive;

        return new TraceInputOptions
        {
            Source = source,
            Payload = payload,
            ProbeUrlSources = body.GetBool("probeUrlSources", true),
            TimeoutMs = body.HasProperty("timeout") ? body.GetInt("timeout") : 10_000,
            CheckCsp = body.GetBool("checkCsp", true),
            DetectSqli = body.GetBool("detectSqli"),
            MonitorSinks = body.GetBool("monitorSinks", true),
            TwoPhase = body.GetBool("twoPhase", true),
            ProbeAllUrlParams = body.GetBool("probeAllUrlParams"),
            FireEvents = body.GetBool("fireEvents"),
            AutoBypass = body.GetBool("autoBypass", true),
            ConfirmExecution = confirmExecution,
            MaxBypassAttempts = Math.Clamp(body.GetInt("maxBypassAttempts", 10), 1, 15)
        };
    }

    private static Dictionary<string, string>? ParseExtraQuery(JsonBody body)
    {
        if (!body.HasProperty("extraQuery")) return null;
        var raw = body.GetRawJson("extraQuery");
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
                return null;
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in doc.RootElement.EnumerateObject())
                dict[prop.Name] = prop.Value.GetString() ?? prop.Value.ToString();
            return dict.Count > 0 ? dict : null;
        }
        catch
        {
            return null;
        }
    }

    private static TraceSourceType ParseSource(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "form" => TraceSourceType.Form,
        "url-query" or "query" => TraceSourceType.UrlQuery,
        "url-hash" or "hash" or "fragment" => TraceSourceType.UrlHash,
        "url-path" or "path" => TraceSourceType.UrlPath,
        "window-name" or "name" => TraceSourceType.WindowName,
        "storage" or "localstorage" or "sessionstorage" => TraceSourceType.Storage,
        "post-message" or "postmessage" or "message" => TraceSourceType.PostMessage,
        "referrer" => TraceSourceType.Referrer,
        _ => throw new ArgumentException(
            $"Unknown source '{raw}'. Use form, url-query, url-hash, url-path, window-name, storage, post-message, or referrer.")
    };
}
