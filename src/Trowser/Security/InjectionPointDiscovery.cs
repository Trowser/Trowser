using System.IO;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Discovers injectable string parameters from the network log for canary and SSTI probes.
/// </summary>
public static class InjectionPointDiscovery
{
    public sealed class InjectionPoint
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string ParamName { get; init; } = "";
        public string? UrlTemplate { get; init; }
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public string Source { get; init; } = "network";
    }

    public static readonly string[] CmdParamHints =
    [
        "cmd", "command", "exec", "execute", "shell", "run", "spawn", "ping", "host", "hostname", "ip",
        "address", "target", "dest", "destination", "file", "path",
        "dir", "folder", "url", "query", "search", "export", "template", "name", "input", "data",
        "arg", "args", "process", "program", "script", "bin", "binary"
    ];

    public static HashSet<string> CmdParamHintSet { get; } =
        new(CmdParamHints, StringComparer.OrdinalIgnoreCase);

    public static List<InjectionPoint> DiscoverFromNetwork(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        HashSet<string>? paramNameHints = null,
        bool jsonBodiesOnly = false,
        bool prioritizeCmdParams = false,
        bool restrictToCmdHints = false)
    {
        paramNameHints ??= CmdParamHintSet;
        var list = new List<InjectionPoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            // Keep 5xx endpoints — command/RCE sinks often surface as 500 with shell output.
            if (entry.StatusCode <= 0) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var method = string.IsNullOrWhiteSpace(entry.Method) ? "GET" : entry.Method.ToUpperInvariant();

            foreach (var pt in ExtractQueryPoints(uri, method, paramNameHints, prioritizeCmdParams, restrictToCmdHints))
            {
                var key = $"{pt.Method}|{pt.Url}|{pt.ParamName}|query";
                if (!seen.Add(key)) continue;
                list.Add(pt);
                if (list.Count >= maxCandidates) return SortByPriority(list, prioritizeCmdParams);
            }

            if (method is not ("POST" or "PUT" or "PATCH") || string.IsNullOrEmpty(entry.RequestBody))
                continue;

            var ct = GetContentType(entry.RequestHeaders);
            if (jsonBodiesOnly && !ct.Contains("json", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var pt in ExtractBodyPoints(entry, paramNameHints, prioritizeCmdParams, restrictToCmdHints))
            {
                var key = $"{pt.Method}|{pt.Url}|{pt.ParamName}|body";
                if (!seen.Add(key)) continue;
                list.Add(pt);
                if (list.Count >= maxCandidates) return SortByPriority(list, prioritizeCmdParams);
            }
        }

        return SortByPriority(list, prioritizeCmdParams);
    }

    /// <summary>
    /// Harvest injectable sinks from live DOM <c>&lt;form method=POST|PUT|PATCH&gt;</c> fields
    /// even when the form was never submitted (so it never appears in the network log).
    /// </summary>
    public static async Task<List<InjectionPoint>> DiscoverFromDomFormsAsync(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        bool prioritizeCmdParams = false,
        bool restrictToCmdHints = false,
        CancellationToken ct = default)
    {
        var list = new List<InjectionPoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ct.ThrowIfCancellationRequested();

        List<FormProbeCloner.CapturedForm> forms;
        try
        {
            forms = await FormProbeCloner.CaptureFormsAsync(ctx);
        }
        catch
        {
            return list;
        }

        foreach (var form in forms)
        {
            if (form.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (!Uri.TryCreate(form.Action, UriKind.Absolute, out var actionUri)) continue;
            if (!string.Equals(actionUri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var injectable = form.Fields
                .Where(f => !f.IsSubmit
                            && !string.IsNullOrWhiteSpace(f.Name)
                            && !f.Type.Equals("hidden", StringComparison.OrdinalIgnoreCase)
                            && IsInjectableParam(f.Name, CmdParamHintSet, prioritizeCmdParams, restrictToCmdHints))
                .ToList();
            if (injectable.Count == 0) continue;

            foreach (var field in injectable)
            {
                var key = $"{form.Method}|{actionUri.GetLeftPart(UriPartial.Path)}|{field.Name}|dom-form";
                if (!seen.Add(key)) continue;

                var bodyParts = new List<string>();
                foreach (var f in form.Fields.Where(x => !string.IsNullOrWhiteSpace(x.Name)))
                {
                    var val = f.Name.Equals(field.Name, StringComparison.OrdinalIgnoreCase)
                        ? "§INJECT§"
                        : (string.IsNullOrEmpty(f.Value) && f.IsSubmit ? f.Name : f.Value);
                    bodyParts.Add($"{Uri.EscapeDataString(f.Name)}={val}");
                }

                list.Add(new InjectionPoint
                {
                    Url = actionUri.GetLeftPart(UriPartial.Path),
                    Method = form.Method,
                    ParamName = field.Name,
                    BodyTemplate = string.Join("&", bodyParts),
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Content-Type"] = "application/x-www-form-urlencoded"
                    },
                    Source = "dom-form"
                });

                if (list.Count >= maxCandidates)
                    return SortByPriority(list, prioritizeCmdParams);
            }
        }

        return SortByPriority(list, prioritizeCmdParams);
    }

    public static List<InjectionPoint> DiscoverJsonEndpoints(
        AutomationContext ctx,
        string origin,
        int maxCandidates)
    {
        var list = new List<InjectionPoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (string.IsNullOrEmpty(entry.RequestBody)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var ct = GetContentType(entry.RequestHeaders);
            if (!ct.Contains("json", StringComparison.OrdinalIgnoreCase)) continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            var headers = CopyHeaders(entry.RequestHeaders);
            headers["Content-Type"] = ct.Contains(';') ? ct : "application/json";

            list.Add(new InjectionPoint
            {
                Url = entry.Url,
                Method = entry.Method.ToUpperInvariant(),
                ParamName = "",
                BodyTemplate = entry.RequestBody,
                Headers = headers,
                Source = "network-json"
            });

            if (list.Count >= maxCandidates) break;
        }

        return list;
    }

    private static IEnumerable<InjectionPoint> ExtractQueryPoints(
        Uri uri, string method, HashSet<string> paramHints, bool prioritizeCmd, bool restrictToCmdHints)
    {
        var query = uri.Query;
        if (string.IsNullOrEmpty(query) || query == "?") yield break;

        foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(part[..eq]);
            if (!IsInjectableParam(key, paramHints, prioritizeCmd, restrictToCmdHints)) continue;

            var urlTemplate = ReplaceQueryValue(uri, key, "§INJECT§");
            yield return new InjectionPoint
            {
                Url = uri.GetLeftPart(UriPartial.Path),
                Method = method,
                ParamName = key,
                UrlTemplate = urlTemplate,
                Source = "network-query"
            };
        }
    }

    private static IEnumerable<InjectionPoint> ExtractBodyPoints(
        NetworkEntry entry, HashSet<string> paramHints, bool prioritizeCmd, bool restrictToCmdHints)
    {
        var ct = GetContentType(entry.RequestHeaders);
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var pt in ExtractJsonBodyPoints(entry, ct, paramHints, prioritizeCmd, restrictToCmdHints))
                yield return pt;
        }
        else if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var qs = System.Web.HttpUtility.ParseQueryString(entry.RequestBody!);
            foreach (string? key in qs)
            {
                if (key == null) continue;
                if (!IsInjectableParam(key, paramHints, prioritizeCmd, restrictToCmdHints)) continue;

                var body = InjectionFormBody.ReplaceFormField(entry.RequestBody!, key, "§INJECT§");
                var headers = CopyHeaders(entry.RequestHeaders);
                headers["Content-Type"] = "application/x-www-form-urlencoded";

                yield return new InjectionPoint
                {
                    Url = entry.Url,
                    Method = entry.Method.ToUpperInvariant(),
                    ParamName = key,
                    BodyTemplate = body,
                    Headers = headers,
                    Source = "network-form"
                };
            }
        }
        else if (!restrictToCmdHints
                 && LooksLikePlainTextBody(ct, entry.RequestBody)
                 && IsBodyMethod(entry.Method))
        {
            // Raw text/plain (or empty CT with non-JSON body) — e.g. template render endpoints.
            var headers = CopyHeaders(entry.RequestHeaders);
            headers["Content-Type"] = string.IsNullOrWhiteSpace(ct) ? "text/plain" : ct;

            yield return new InjectionPoint
            {
                Url = entry.Url,
                Method = entry.Method.ToUpperInvariant(),
                ParamName = "body",
                BodyTemplate = "§INJECT§",
                Headers = headers,
                Source = "network-plaintext-body"
            };
        }
    }

    private static bool IsBodyMethod(string method) =>
        method.Equals("POST", StringComparison.OrdinalIgnoreCase)
        || method.Equals("PUT", StringComparison.OrdinalIgnoreCase)
        || method.Equals("PATCH", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikePlainTextBody(string contentType, string? body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase)) return false;
        if (contentType.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)) return false;
        if (contentType.Contains("multipart", StringComparison.OrdinalIgnoreCase)) return false;
        if (contentType.Contains("text/plain", StringComparison.OrdinalIgnoreCase)) return true;
        // Empty/missing Content-Type with a short non-JSON body is often a template/render sink.
        if (string.IsNullOrWhiteSpace(contentType)
            && body.Length <= 4096
            && body.TrimStart().Length > 0
            && body.TrimStart()[0] is not ('{' or '['))
            return true;
        return false;
    }

    private static IEnumerable<InjectionPoint> ExtractJsonBodyPoints(
        NetworkEntry entry, string ct, HashSet<string> paramHints, bool prioritizeCmd, bool restrictToCmdHints)
    {
        List<InjectionPoint> points;
        try
        {
            using var doc = JsonDocument.Parse(entry.RequestBody!);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return [];

            points = new List<InjectionPoint>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.String) continue;
                if (!IsInjectableParam(prop.Name, paramHints, prioritizeCmd, restrictToCmdHints)) continue;

                var body = InjectJsonField(entry.RequestBody!, prop.Name, "§INJECT§");
                var headers = CopyHeaders(entry.RequestHeaders);
                headers["Content-Type"] = ct.Contains(';') ? ct : "application/json";

                points.Add(new InjectionPoint
                {
                    Url = entry.Url,
                    Method = entry.Method.ToUpperInvariant(),
                    ParamName = prop.Name,
                    BodyTemplate = body,
                    Headers = headers,
                    Source = "network-json-field"
                });
            }
        }
        catch
        {
            return [];
        }

        return points;
    }

    private static bool IsInjectableParam(string name, HashSet<string> hints, bool prioritizeCmd, bool restrictToCmdHints)
    {
        if (restrictToCmdHints)
            return InjectionParamClassifier.Classify(name) == InjectionParamKind.Cmd;
        return true;
    }

    private static List<InjectionPoint> SortByPriority(List<InjectionPoint> list, bool prioritizeCmd)
    {
        if (!prioritizeCmd) return list;
        return list
            .OrderByDescending(p => CmdParamHintSet.Contains(p.ParamName) ? 1 : 0)
            .ThenBy(p => p.Url)
            .ToList();
    }

    private static string GetContentType(Dictionary<string, string> headers) =>
        headers.TryGetValue("Content-Type", out var ct) ? ct :
        headers.TryGetValue("content-type", out var ct2) ? ct2 : "";

    private static Dictionary<string, string> CopyHeaders(Dictionary<string, string> source)
    {
        var copy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in source)
        {
            if (kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            copy[kv.Key] = kv.Value;
        }
        return copy;
    }

    private static string ReplaceQueryValue(Uri uri, string paramName, string marker)
    {
        var baseUrl = uri.GetLeftPart(UriPartial.Path);
        var parts = new List<string>();
        var replaced = false;

        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) { parts.Add(part); continue; }
            var key = Uri.UnescapeDataString(part[..eq]);
            if (key.Equals(paramName, StringComparison.OrdinalIgnoreCase))
            {
                // Keep §NAME§ / {{NAME}} literal so RequestMarkerSubstitute can find them.
                parts.Add($"{Uri.EscapeDataString(key)}={RequestMarkerSubstitute.EscapeDataStringPreservingMarkers(marker)}");
                replaced = true;
            }
            else
            {
                parts.Add(part);
            }
        }

        if (!replaced)
            parts.Add($"{Uri.EscapeDataString(paramName)}={RequestMarkerSubstitute.EscapeDataStringPreservingMarkers(marker)}");

        return parts.Count > 0 ? $"{baseUrl}?{string.Join("&", parts)}" : baseUrl;
    }

    private static string InjectJsonField(string json, string fieldName, string marker) =>
        InjectionJsonBody.InjectMarkerIntoFirstStringField(json, marker, fieldName);
}
