using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;

namespace Trowser.Security;

public sealed class AuthzBoundarySpec
{
    public required string UrlTemplate { get; init; }
    public required string Parameter { get; init; }
    public List<string> AuthorizedValues { get; init; } = [];
    public List<string> UnauthorizedValues { get; init; } = [];
    public string Method { get; init; } = "GET";
    public Dictionary<string, string>? Headers { get; init; }
    public string? Body { get; init; }
    public string? BodyTemplate { get; init; }
    public string? JsonBody { get; init; }
    public string? Peer { get; init; }
}

public sealed class AuthzBoundarySingleResult
{
    public required string Url { get; init; }
    public string? Endpoint { get; init; }
    public required string Parameter { get; init; }
    public required List<object> Baseline { get; init; }
    public required List<object> Findings { get; init; }
    public required object Summary { get; init; }
}

public static class AuthzBoundaryService
{
    public static List<AuthzBoundarySpec> ParseSpecs(JsonElement root, out string? error)
    {
        error = null;
        if (root.ValueKind != JsonValueKind.Object)
        {
            error = "Request body must be a JSON object.";
            return [];
        }

        if (root.TryGetProperty("endpoints", out var endpoints) && endpoints.ValueKind == JsonValueKind.Array)
        {
            var specs = new List<AuthzBoundarySpec>();
            var index = 0;
            foreach (var ep in endpoints.EnumerateArray())
            {
                if (!TryParseEndpointSpec(ep, root, out var spec, out var epError))
                {
                    error = $"endpoints[{index}]: {epError}";
                    return [];
                }

                specs.Add(spec);
                index++;
            }

            if (specs.Count == 0)
            {
                error = "Field 'endpoints' must contain at least one boundary test.";
                return [];
            }

            return specs;
        }

        if (!TryParseLegacySpec(root, out var legacy, out var legacyError))
        {
            error = legacyError;
            return [];
        }

        return [legacy];
    }

    public static async Task<object> RunAsync(
        AutomationContext context,
        PeerRegistry? peers,
        IReadOnlyList<AuthzBoundarySpec> specs,
        AuthzBodyMatchOptions bodyMatch,
        int timeoutMs = 30_000)
    {
        var results = new List<AuthzBoundarySingleResult>();
        foreach (var spec in specs)
        {
            results.Add(await RunSingleAsync(context, peers, spec, bodyMatch, timeoutMs));
        }

        if (results.Count == 1)
        {
            var single = results[0];
            return new Dictionary<string, object?>
            {
                ["endpoint"] = single.Endpoint ?? single.Url,
                ["url"] = single.Url,
                ["parameter"] = single.Parameter,
                ["baseline"] = single.Baseline,
                ["findings"] = single.Findings,
                ["summary"] = single.Summary,
                ["bodyMatch"] = DescribeBodyMatch(bodyMatch)
            };
        }

        var totalAuthorized = 0;
        var totalUnauthorized = 0;
        var properlyDenied = 0;
        var accessGranted = 0;
        var identicalToAuthorized = 0;
        var errors = 0;

        foreach (var result in results)
        {
            if (result.Summary is Dictionary<string, object?> summary)
            {
                totalAuthorized += ReadInt(summary, "authorizedCount");
                totalUnauthorized += ReadInt(summary, "unauthorizedCount");
                properlyDenied += ReadInt(summary, "properlyDenied");
                accessGranted += ReadInt(summary, "accessGranted");
                identicalToAuthorized += ReadInt(summary, "identicalToAuthorized");
                errors += ReadInt(summary, "errors");
            }
        }

        return new Dictionary<string, object?>
        {
            ["results"] = results.Select(r => new Dictionary<string, object?>
            {
                ["url"] = r.Url,
                ["endpoint"] = r.Endpoint ?? r.Url,
                ["parameter"] = r.Parameter,
                ["baseline"] = r.Baseline,
                ["findings"] = r.Findings,
                ["summary"] = r.Summary
            }),
            ["summary"] = new
            {
                totalEndpoints = results.Count,
                authorizedCount = totalAuthorized,
                unauthorizedCount = totalUnauthorized,
                properlyDenied,
                accessGranted,
                identicalToAuthorized,
                errors
            },
            ["bodyMatch"] = DescribeBodyMatch(bodyMatch)
        };
    }

    private static async Task<AuthzBoundarySingleResult> RunSingleAsync(
        AutomationContext context,
        PeerRegistry? peers,
        AuthzBoundarySpec spec,
        AuthzBodyMatchOptions bodyMatch,
        int timeoutMs)
    {
        var baselineResults = new List<(string value, int status, string body, string hash)>();
        foreach (var val in spec.AuthorizedValues)
        {
            var (url, headers, reqBody) = BuildRequest(spec, val);
            var (status, bodyText) = await FetchLocalAsync(context, url, spec.Method, headers, reqBody, timeoutMs);
            baselineResults.Add((val, status, bodyText, AuthzBodyMatcher.ComputeMatchHash(bodyText, bodyMatch)));
        }

        var findings = new List<object>();
        int properlyDenied = 0, accessGranted = 0, sameResponse = 0, errorsCount = 0;

        foreach (var val in spec.UnauthorizedValues)
        {
            var (url, headers, reqBody) = BuildRequest(spec, val);
            int status;
            string bodyText;

            if (!string.IsNullOrWhiteSpace(spec.Peer) && peers != null)
            {
                (status, bodyText) = await FetchViaPeerAsync(peers, spec.Peer, url, spec.Method, headers, reqBody, timeoutMs);
            }
            else
            {
                (status, bodyText) = await FetchLocalAsync(context, url, spec.Method, headers, reqBody, timeoutMs);
            }

            var hash = AuthzBodyMatcher.ComputeMatchHash(bodyText, bodyMatch);
            // 404 is a common hide-existence denial for unauthorized IDs (same as authz/diff).
            var isDenied = status is 401 or 403 or 404;
            var isOk = status is >= 200 and < 300;
            var matchesBaseline = baselineResults.Any(b =>
                b.status == status && AuthzBodyMatcher.BodiesMatch(b.body, bodyText, bodyMatch));

            string finding;
            if (isDenied)
            {
                finding = "PROPERLY_DENIED";
                properlyDenied++;
            }
            else if (isOk && matchesBaseline)
            {
                finding = "IDENTICAL_TO_AUTHORIZED";
                sameResponse++;
            }
            else if (isOk)
            {
                finding = "ACCESS_GRANTED";
                accessGranted++;
            }
            else
            {
                finding = "ERROR";
                errorsCount++;
            }

            findings.Add(new Dictionary<string, object?>
            {
                ["value"] = val,
                ["url"] = url,
                ["status"] = status,
                ["bodyLength"] = bodyText.Length,
                ["bodyHash"] = hash,
                ["finding"] = finding,
                ["matchesAuthorizedResponse"] = matchesBaseline
            });
        }

        return new AuthzBoundarySingleResult
        {
            Url = spec.UrlTemplate,
            Endpoint = spec.UrlTemplate,
            Parameter = spec.Parameter,
            Baseline = baselineResults.Select(b => (object)new
            {
                value = b.value,
                status = b.status,
                bodyLength = b.body.Length,
                bodyHash = b.hash
            }).ToList(),
            Findings = findings,
            Summary = new Dictionary<string, object?>
            {
                ["authorizedCount"] = spec.AuthorizedValues.Count,
                ["unauthorizedCount"] = spec.UnauthorizedValues.Count,
                ["properlyDenied"] = properlyDenied,
                ["accessGranted"] = accessGranted,
                ["identicalToAuthorized"] = sameResponse,
                ["errors"] = errorsCount
            }
        };
    }

    private static (string url, Dictionary<string, string>? headers, string? body) BuildRequest(AuthzBoundarySpec spec, string value)
    {
        var url = spec.UrlTemplate.Replace($"{{{spec.Parameter}}}", Uri.EscapeDataString(value));
        var headers = spec.Headers != null ? new Dictionary<string, string>(spec.Headers) : null;
        string? reqBody = spec.Body;

        if (spec.BodyTemplate != null)
        {
            reqBody = spec.BodyTemplate.Replace($"{{{spec.Parameter}}}", value);
            if (reqBody.TrimStart().StartsWith('{') || reqBody.TrimStart().StartsWith('['))
            {
                headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                headers.TryAdd("Content-Type", "application/json");
            }
        }
        else if (spec.JsonBody != null)
        {
            reqBody = spec.JsonBody;
            headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            headers.TryAdd("Content-Type", "application/json");
        }

        return (url, headers, reqBody);
    }

    private static async Task<(int status, string body)> FetchLocalAsync(
        AutomationContext context,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        int timeoutMs)
    {
        var result = await DirectFetchHelper.FetchAsync(context, url, method, headers, body, timeoutMs);
        if (result.Error != null)
            return (0, result.Error);

        return (result.Status, result.Body);
    }

    private static async Task<(int status, string body)> FetchViaPeerAsync(
        PeerRegistry peers,
        string peerName,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        int timeoutMs)
    {
        var peerFetchBody = new Dictionary<string, object?> { ["url"] = url, ["method"] = method, ["timeout"] = timeoutMs };
        if (headers != null) peerFetchBody["headers"] = headers;
        if (body != null)
        {
            var ct = headers?.GetValueOrDefault("Content-Type") ?? "";
            if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                try { peerFetchBody["json"] = JsonSerializer.Deserialize<object>(body); }
                catch { peerFetchBody["body"] = body; }
            }
            else
            {
                peerFetchBody["body"] = body;
            }
        }

        var json = JsonSerializer.Serialize(peerFetchBody);
        var peerResp = await peers.ForwardAsync(peerName, "POST", "/api/fetch-direct", json,
            timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(timeoutMs));
        if (!peerResp.Success && peerResp.StatusCode != 200)
            return (0, peerResp.Body ?? "Peer request failed.");

        try
        {
            using var doc = JsonDocument.Parse(peerResp.Body ?? "{}");
            if (doc.RootElement.TryGetProperty("data", out var data))
            {
                var status = data.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
                var respBody = data.TryGetProperty("body", out var pb) ? pb.GetString() ?? "" : "";
                return (status, respBody);
            }
        }
        catch
        {
            /* fall through */
        }

        return (0, peerResp.Body ?? "");
    }

    private static bool TryParseLegacySpec(JsonElement root, out AuthzBoundarySpec spec, out string error)
    {
        spec = null!;
        error = "";

        var url = ReadString(root, "url") ?? ReadString(root, "endpoint") ?? ReadString(root, "urlTemplate");
        url = AttackSurfaceMapper.DecodeTemplateBraces(url);
        if (string.IsNullOrWhiteSpace(url))
        {
            error = "Field 'endpoint' or 'url' is required (URL template with {parameter} placeholder), or provide 'endpoints[]'.";
            return false;
        }

        var parameter = ReadString(root, "parameter");
        if (string.IsNullOrWhiteSpace(parameter))
        {
            error = "Field 'parameter' is required (the placeholder name in the URL or body).";
            return false;
        }

        var authorizedValues = ReadValueList(root, "authorizedValues", "authorizedIds");
        if (authorizedValues.Count == 0)
        {
            error = "Field 'authorizedValues' (alias: authorizedIds) is required: at least one value the session should have access to.";
            return false;
        }

        var unauthorizedValues = ReadValueList(root, "unauthorizedValues", "unauthorizedIds");
        if (unauthorizedValues.Count == 0)
        {
            error = "Field 'unauthorizedValues' (alias: unauthorizedIds) is required: values the session should NOT have access to.";
            return false;
        }

        spec = BuildSpecFromParts(
            url,
            parameter,
            authorizedValues,
            unauthorizedValues,
            ReadString(root, "method") ?? "GET",
            ReadStringDictionary(root, "headers"),
            ReadString(root, "body"),
            ReadString(root, "bodyTemplate"),
            root.TryGetProperty("json", out var jsonEl) ? jsonEl.GetRawText() : null,
            ReadString(root, "peer"));
        return true;
    }

    private static bool TryParseEndpointSpec(JsonElement ep, JsonElement root, out AuthzBoundarySpec spec, out string error)
    {
        spec = null!;
        error = "";

        if (ep.ValueKind != JsonValueKind.Object)
        {
            error = "Each endpoints[] item must be an object.";
            return false;
        }

        var url = ep.TryGetProperty("url", out var urlEl) ? urlEl.GetString()
            : ep.TryGetProperty("endpoint", out var endpointEl) ? endpointEl.GetString()
            : ep.TryGetProperty("urlTemplate", out var templateEl) ? templateEl.GetString()
            : null;
        url = AttackSurfaceMapper.DecodeTemplateBraces(url);
        if (string.IsNullOrWhiteSpace(url))
        {
            error = "url (or endpoint/urlTemplate) is required.";
            return false;
        }

        var parameter = ep.TryGetProperty("parameter", out var paramEl) ? paramEl.GetString() : null;
        if (string.IsNullOrWhiteSpace(parameter))
        {
            error = "parameter is required.";
            return false;
        }

        var authorizedValues = ReadValueList(ep, "authorizedValues", "authorizedIds");
        if (authorizedValues.Count == 0)
        {
            error = "authorizedValues (alias: authorizedIds) is required.";
            return false;
        }

        var unauthorizedValues = ReadValueList(ep, "unauthorizedValues", "unauthorizedIds");
        if (unauthorizedValues.Count == 0)
        {
            error = "unauthorizedValues (alias: unauthorizedIds) is required.";
            return false;
        }

        Dictionary<string, string>? headers = null;
        if (ep.TryGetProperty("headers", out var headersEl) && headersEl.ValueKind == JsonValueKind.Object)
        {
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in headersEl.EnumerateObject())
                headers[prop.Name] = prop.Value.GetString() ?? "";
        }

        string? body = ep.TryGetProperty("body", out var bodyEl) && bodyEl.ValueKind == JsonValueKind.String
            ? bodyEl.GetString()
            : null;
        string? bodyTemplate = ep.TryGetProperty("bodyTemplate", out var bodyTemplateEl) && bodyTemplateEl.ValueKind == JsonValueKind.String
            ? bodyTemplateEl.GetString()
            : null;
        string? jsonBody = ep.TryGetProperty("json", out var jsonEl) ? jsonEl.GetRawText() : null;
        var method = ep.TryGetProperty("method", out var methodEl) ? methodEl.GetString() ?? "GET" : "GET";
        var peer = ep.TryGetProperty("peer", out var peerEl) ? peerEl.GetString() : ReadString(root, "peer");

        spec = BuildSpecFromParts(url, parameter, authorizedValues, unauthorizedValues, method, headers, body, bodyTemplate, jsonBody, peer);
        return true;
    }

    private static AuthzBoundarySpec BuildSpecFromParts(
        string urlTemplate,
        string parameter,
        List<string> authorizedValues,
        List<string> unauthorizedValues,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        string? bodyTemplate,
        string? jsonBody,
        string? peer) => new()
    {
        UrlTemplate = urlTemplate,
        Parameter = parameter,
        AuthorizedValues = authorizedValues,
        UnauthorizedValues = unauthorizedValues,
        Method = method,
        Headers = headers,
        Body = body,
        BodyTemplate = bodyTemplate,
        JsonBody = jsonBody,
        Peer = peer
    };

    private static List<string> ReadValueList(JsonElement el, params string[] propertyNames)
    {
        foreach (var property in propertyNames)
        {
            if (!el.TryGetProperty(property, out var arr) || arr.ValueKind != JsonValueKind.Array)
                continue;

            var values = new List<string>();
            foreach (var item in arr.EnumerateArray())
            {
                switch (item.ValueKind)
                {
                    case JsonValueKind.String when item.GetString() is { } s:
                        values.Add(s);
                        break;
                    case JsonValueKind.Number:
                        values.Add(item.GetRawText());
                        break;
                    case JsonValueKind.True:
                        values.Add("true");
                        break;
                    case JsonValueKind.False:
                        values.Add("false");
                        break;
                }
            }

            if (values.Count > 0)
                return values;
        }

        return [];
    }

    private static string? ReadString(JsonElement el, string property) =>
        el.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static Dictionary<string, string>? ReadStringDictionary(JsonElement el, string property)
    {
        if (!el.TryGetProperty(property, out var obj) || obj.ValueKind != JsonValueKind.Object)
            return null;

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in obj.EnumerateObject())
            result[prop.Name] = prop.Value.GetString() ?? "";
        return result;
    }

    private static object DescribeBodyMatch(AuthzBodyMatchOptions options) => new
    {
        strategy = options.Strategy.ToString(),
        ignoreFields = options.IgnoreFields
    };

    private static int ReadInt(Dictionary<string, object?> dict, string key) =>
        dict.TryGetValue(key, out var value) && value is int n ? n : 0;
}
