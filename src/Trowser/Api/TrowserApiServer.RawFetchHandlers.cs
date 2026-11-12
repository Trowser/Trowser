using System.Net;
using System.Text.Json;
using Trowser.Security;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    private async Task HandlePostFetchRaw(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            await WriteError(response, 400, "Missing or invalid url — must be an absolute http or https URL.");
            return;
        }

        string? headerBlock = null;
        if (body.HasProperty("headers"))
        {
            try
            {
                var raw = body.GetRawJson("headers");
                if (raw != null)
                {
                    using var doc = JsonDocument.Parse(raw);
                    if (doc.RootElement.ValueKind == JsonValueKind.String)
                        headerBlock = doc.RootElement.GetString();
                    else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        await WriteError(response, 400,
                            "headers must be a raw header block string (not an object) so duplicate names can be sent.");
                        return;
                    }
                    else
                        headerBlock = body.GetString("headers");
                }
            }
            catch
            {
                headerBlock = body.GetString("headers");
            }
        }

        var requestLine = body.GetString("requestLine");
        var method = body.GetString("method") ?? "GET";
        var fetchBody = body.GetString("body");
        var timeout = body.GetInt("timeout", 15000);
        var normalizeHeaders = !body.HasProperty("normalizeHeaders") || body.GetBool("normalizeHeaders", true);

        if (string.IsNullOrWhiteSpace(requestLine))
            requestLine = RawHttpClient.DefaultRequestLine(method, uri);

        try
        {
            var result = await RawHttpClient.SendAsync(uri, requestLine, headerBlock, fetchBody, timeout,
                new RawHttpClient.BuildOptions { NormalizeHeaders = normalizeHeaders },
                _context.OperationCancellation);

            await WriteSuccess(response, new
            {
                ok = result.Error == null && !result.TimedOut && result.Status is >= 200 and < 300,
                status = result.Status,
                statusText = result.StatusText,
                headers = result.Headers,
                body = result.Body,
                bodyRaw = result.BodyRaw,
                bodyWasChunked = result.BodyWasChunked,
                requestSent = result.RequestSent,
                timedOut = result.TimedOut,
                hostWasAdded = result.HostWasAdded,
                durationMs = result.DurationMs,
                error = result.Error,
                type = "raw"
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 500, $"Raw request failed: {ex.Message}");
        }
    }

    private async Task HandleGetHeaderOverrides(HttpListenerResponse response)
    {
        var items = HeaderOverrideSettings.GetAll();
        await WriteSuccess(response, new
        {
            count = items.Count,
            enabledCount = HeaderOverrideSettings.EnabledCount,
            headers = items.Select(h => new { name = h.Name, value = h.Value, enabled = h.Enabled })
        });
    }

    private async Task HandlePutHeaderOverrides(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var items = ParseHeaderOverrideList(body);
        if (items == null)
        {
            await WriteError(response, 400, "Provide headers: [{ \"name\", \"value\", \"enabled\" }].");
            return;
        }

        HeaderOverrideSettings.Replace(items);
        await HandleGetHeaderOverrides(response);
    }

    private async Task HandleDeleteHeaderOverrides(HttpListenerResponse response)
    {
        HeaderOverrideSettings.Clear();
        await WriteSuccess(response, new { count = 0, enabledCount = 0, headers = Array.Empty<object>() });
    }

    private static List<HeaderOverride>? ParseHeaderOverrideList(JsonBody body)
    {
        if (!body.HasProperty("headers"))
            return null;
        try
        {
            var raw = body.GetRawJson("headers");
            if (raw == null) return null;
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
                return null;
            var list = new List<HeaderOverride>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                if (el.ValueKind != JsonValueKind.Object) continue;
                var name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                var value = el.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
                var enabled = !el.TryGetProperty("enabled", out var en) || en.ValueKind != JsonValueKind.False;
                if (name.Trim().Length == 0) continue;
                list.Add(new HeaderOverride { Name = name.Trim(), Value = value, Enabled = enabled });
            }
            return list;
        }
        catch
        {
            return null;
        }
    }
}
