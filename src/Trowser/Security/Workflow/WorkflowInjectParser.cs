using System.Text.Json;
using Trowser.Security;

namespace Trowser.Security.Workflow;

internal static class WorkflowInjectParser
{
    public static bool TryParse(JsonElement step, out ExploitVerifyOptions opt, out string? error)
    {
        opt = null!;
        error = null;

        var renderUrl = GetString(step, "renderUrl");
        if (string.IsNullOrWhiteSpace(renderUrl))
        {
            error = "inject step requires renderUrl.";
            return false;
        }

        var effectCheck = GetString(step, "effectCheck");
        if (string.IsNullOrWhiteSpace(effectCheck))
        {
            error = "inject step requires effectCheck.";
            return false;
        }

        var renderInjection = ParseUrlInjection(step);
        var hasInjection = step.TryGetProperty("injection", out var injEl) && injEl.ValueKind == JsonValueKind.Object;
        var skipInjection = GetBool(step, "skipInjection")
                            || renderInjection != null && !hasInjection;

        string injectionUrl;
        string injMethod = "GET";
        Dictionary<string, string>? injectionHeaders = null;
        string? injBody = null;

        if (hasInjection)
        {
            injectionUrl = GetString(injEl, "url") ?? "";
            if (string.IsNullOrWhiteSpace(injectionUrl) && !skipInjection)
            {
                error = "injection.url is required unless skipInjection is true.";
                return false;
            }
            injMethod = GetString(injEl, "method") ?? "GET";
            injectionHeaders = GetStringDict(injEl, "headers");
            injBody = GetString(injEl, "body");
            if (injBody == null && injEl.TryGetProperty("json", out var jsonEl))
            {
                injBody = jsonEl.GetRawText();
                injectionHeaders ??= new Dictionary<string, string>();
                injectionHeaders.TryAdd("Content-Type", "application/json");
            }
        }
        else if (skipInjection)
        {
            injectionUrl = "about:blank";
        }
        else
        {
            error = "inject step requires injection { url } or skipInjection/renderInjection.";
            return false;
        }

        opt = new ExploitVerifyOptions
        {
            InjectionUrl = injectionUrl,
            InjectionMethod = injMethod,
            InjectionHeaders = injectionHeaders,
            InjectionBody = injBody,
            EncodePayloadInUrl = !step.TryGetProperty("encodePayloadInUrl", out var ep) || ep.ValueKind != JsonValueKind.False,
            RenderUrl = renderUrl,
            RenderInjection = renderInjection,
            QueryEncode = UrlPayloadInjector.ParseEncodeMode(GetString(step, "queryEncode"), UrlPayloadEncodeMode.Component),
            FragmentEncode = UrlPayloadInjector.ParseEncodeMode(GetString(step, "fragmentEncode"), UrlPayloadEncodeMode.None),
            SkipInjection = skipInjection,
            EffectCheck = effectCheck,
            CleanupUrl = step.TryGetProperty("cleanup", out var cuEl) ? GetString(cuEl, "url") : GetString(step, "cleanupUrl"),
            WaitAfterRenderMs = GetInt(step, "waitAfterRenderMs", 0),
            WaitForIdleAfterRender = GetBool(step, "waitForIdleAfterRender"),
            WaitForIdleTimeoutMs = GetInt(step, "waitForIdleTimeoutMs", 10_000),
            IncludeScreenshot = !step.TryGetProperty("includeScreenshot", out var ishot) || ishot.ValueKind != JsonValueKind.False,
            ScreenshotFormat = GetString(step, "screenshotFormat") ?? "jpeg",
            ScreenshotQuality = GetInt(step, "screenshotQuality", 70),
            FetchTimeoutMs = GetInt(step, "fetchTimeoutMs", 30_000)
        };
        return true;
    }

    private static UrlInjectionSpec? ParseUrlInjection(JsonElement step)
    {
        if (!step.TryGetProperty("renderInjection", out var el) || el.ValueKind != JsonValueKind.Object)
            return null;
        var partRaw = GetString(el, "part");
        if (string.IsNullOrWhiteSpace(partRaw)) return null;
        if (!Enum.TryParse<UrlInjectionPart>(partRaw, ignoreCase: true, out var part))
            return null;
        return new UrlInjectionSpec
        {
            Part = part,
            Param = GetString(el, "param"),
            Encode = UrlPayloadInjector.ParseEncodeMode(GetString(el, "encode"), UrlPayloadEncodeMode.Component),
            Append = GetBool(el, "append")
        };
    }

    private static string? GetString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static bool GetBool(JsonElement el, string name, bool defaultValue = false)
    {
        if (!el.TryGetProperty(name, out var p)) return defaultValue;
        return p.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => defaultValue
        };
    }

    private static int GetInt(JsonElement el, string name, int defaultValue)
    {
        if (!el.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.Number) return defaultValue;
        return p.GetInt32();
    }

    private static Dictionary<string, string>? GetStringDict(JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.Object) return null;
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in p.EnumerateObject())
            d[prop.Name] = prop.Value.GetString() ?? prop.Value.ToString();
        return d.Count > 0 ? d : null;
    }
}
