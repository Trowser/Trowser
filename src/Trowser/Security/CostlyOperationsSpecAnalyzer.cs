using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Passive cost hints from OpenAPI/Swagger and GraphQL schema documents in the network log (or explicit spec URLs).
/// </summary>
internal static class CostlyOperationsSpecAnalyzer
{
    internal sealed class SpecDocument
    {
        public string Url { get; init; } = "";
        public string Body { get; init; } = "";
        public string Kind { get; init; } = "openapi";
    }

    private static readonly string[] LimitParamNames =
    [
        "limit", "pageSize", "pagesize", "page_size", "per_page", "perPage", "size", "top", "$top", "take", "count", "max"
    ];

    internal static List<SpecDocument> CollectFromNetwork(
        IReadOnlyList<NetworkEntry> all,
        string origin,
        IReadOnlyList<string>? specUrls,
        bool includeSpecsFromNetwork)
    {
        var docs = new List<SpecDocument>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        IEnumerable<NetworkEntry> q = all.Where(e => e is { StatusCode: >= 200 and < 300 }
                                                   && e.ResponseBody is { Length: > 80 });

        if (specUrls is { Count: > 0 })
        {
            var set = new HashSet<string>(specUrls.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()),
                StringComparer.OrdinalIgnoreCase);
            q = q.Where(e => set.Any(u => UrlMatches(e.Url, u)));
        }
        else if (includeSpecsFromNetwork)
        {
            q = q.Where(e =>
                Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)
                && string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            return docs;
        }

        foreach (var e in q)
        {
            var body = e.ResponseBody!;
            if (LooksLikeOpenApi(e.Url, e.ContentType, body))
            {
                if (seen.Add($"openapi|{e.Url}"))
                    docs.Add(new SpecDocument { Url = e.Url, Body = body, Kind = "openapi" });
            }
            else if (LooksLikeGraphQlIntrospection(body))
            {
                if (seen.Add($"graphql|{e.Url}"))
                    docs.Add(new SpecDocument { Url = e.Url, Body = body, Kind = "graphql-introspection" });
            }
        }

        return docs;
    }

    internal static IEnumerable<CostlyOperationsProbe.CostlyFinding> Analyze(
        IReadOnlyList<SpecDocument> docs,
        int maxCandidates)
    {
        var count = 0;
        foreach (var doc in docs)
        {
            if (count >= maxCandidates) yield break;
            if (doc.Kind == "openapi")
            {
                foreach (var f in AnalyzeOpenApiDocument(doc, maxCandidates - count))
                {
                    if (count >= maxCandidates) yield break;
                    count++;
                    yield return f;
                }
            }
            else if (doc.Kind == "graphql-introspection")
            {
                if (count >= maxCandidates) yield break;
                count++;
                yield return SpecFinding(
                    "spec-limits", "costly-spec-graphql", "medium", "observed",
                    "GraphQL schema (introspection) captured — review list field cost",
                    doc.Url, "GET",
                    null,
                    "Introspection exposes query shape; unbounded list fields and deep nesting are single-request cost risks.",
                    doc.Url,
                    "Run graphql-analyze; add server-side depth/complexity limits.",
                    "graphql-analyze");
            }
        }
    }

    private static List<CostlyOperationsProbe.CostlyFinding> AnalyzeOpenApiDocument(
        SpecDocument doc,
        int maxFindings)
    {
        var findings = new List<CostlyOperationsProbe.CostlyFinding>();
        if (maxFindings <= 0) return findings;

        JsonDocument? jd = null;
        try
        {
            jd = JsonDocument.Parse(doc.Body);
        }
        catch (JsonException)
        {
            return findings;
        }

        using (jd)
        {
            var root = jd!.RootElement;
            if (!root.TryGetProperty("paths", out var paths) || paths.ValueKind != JsonValueKind.Object)
                return findings;

            var serverUrl = FirstServerUrl(root);
            foreach (var pathProp in paths.EnumerateObject())
            {
                if (findings.Count >= maxFindings) break;
                if (pathProp.Value.ValueKind != JsonValueKind.Object) continue;

                foreach (var opProp in pathProp.Value.EnumerateObject())
                {
                    if (findings.Count >= maxFindings) break;
                    var opName = opProp.Name.ToLowerInvariant();
                    if (opName is not ("get" or "post" or "put" or "patch" or "delete" or "head" or "options"))
                        continue;

                    var op = opProp.Value;
                    if (op.TryGetProperty("parameters", out var parameters) && parameters.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var param in parameters.EnumerateArray())
                        {
                            if (findings.Count >= maxFindings) break;
                            var finding = AnalyzeOpenApiParameter(doc.Url, serverUrl, pathProp.Name, opName, param);
                            if (finding != null) findings.Add(finding);
                        }
                    }

                    if (op.TryGetProperty("requestBody", out var rb))
                        findings.AddRange(AnalyzeOpenApiRequestBody(doc.Url, serverUrl, pathProp.Name, opName, rb, maxFindings - findings.Count));
                }
            }
        }

        return findings;
    }

    private static CostlyOperationsProbe.CostlyFinding? AnalyzeOpenApiParameter(
        string specUrl,
        string? serverUrl,
        string path,
        string method,
        JsonElement param)
    {
        var name = param.TryGetProperty("name", out var n) ? n.GetString() : null;
        if (string.IsNullOrEmpty(name)) return null;

        var location = param.TryGetProperty("in", out var loc) ? loc.GetString() : "query";
        if (!string.Equals(location, "query", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(location, "path", StringComparison.OrdinalIgnoreCase))
            return null;

        var schema = param.TryGetProperty("schema", out var sch) ? sch : default;
        if (schema.ValueKind == JsonValueKind.Undefined && param.TryGetProperty("type", out _))
            schema = param;

        var isLimitName = LimitParamNames.Any(p => name.Equals(p, StringComparison.OrdinalIgnoreCase)
                                                  || name.Equals("$" + p, StringComparison.OrdinalIgnoreCase));

        if (schema.ValueKind != JsonValueKind.Undefined)
        {
            if (schema.TryGetProperty("type", out var typeEl) && typeEl.GetString() == "array")
            {
                if (!schema.TryGetProperty("maxItems", out _))
                {
                    return SpecFinding(
                        "spec-limits", "costly-spec-unbounded", "high", "inferred",
                        $"OpenAPI array parameter without maxItems ({name})",
                        ResolveOperationUrl(specUrl, serverUrl, path), method.ToUpperInvariant(), name,
                        $"{method.ToUpperInvariant()} {path} — array query param '{name}' has no documented maxItems.",
                        $"{path}?{name}=[] spec={specUrl}",
                        "Document and enforce maxItems; reject oversized arrays server-side.",
                        null);
                }
            }

            if (isLimitName && !HasNumericMaximum(schema))
            {
                return SpecFinding(
                    "spec-limits", "costly-spec-unbounded", "high", "inferred",
                    $"OpenAPI paging/limit parameter without maximum ({name})",
                    ResolveOperationUrl(specUrl, serverUrl, path), method.ToUpperInvariant(), name,
                    $"{method.ToUpperInvariant()} {path} — '{name}' has no schema maximum in the spec.",
                    $"{path} spec={specUrl}",
                    "Add maximum to the contract and enforce it server-side.",
                    null);
            }
        }
        else if (isLimitName)
        {
            return SpecFinding(
                "spec-limits", "costly-spec-unbounded", "medium", "inferred",
                $"OpenAPI limit parameter without schema ({name})",
                ResolveOperationUrl(specUrl, serverUrl, path), method.ToUpperInvariant(), name,
                $"{method.ToUpperInvariant()} {path} — '{name}' is not typed with a maximum in OpenAPI.",
                $"{path} spec={specUrl}",
                "Add schema with maximum for paging parameters.",
                null);
        }

        return null;
    }

    private static List<CostlyOperationsProbe.CostlyFinding> AnalyzeOpenApiRequestBody(
        string specUrl,
        string? serverUrl,
        string path,
        string method,
        JsonElement requestBody,
        int maxFindings)
    {
        var findings = new List<CostlyOperationsProbe.CostlyFinding>();
        if (maxFindings <= 0) return findings;
        if (!requestBody.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object)
            return findings;

        foreach (var media in content.EnumerateObject())
        {
            if (findings.Count >= maxFindings) break;
            if (!media.Name.Contains("json", StringComparison.OrdinalIgnoreCase)) continue;
            if (!media.Value.TryGetProperty("schema", out var schema)) continue;

            foreach (var issue in FindUnboundedSchemaNodes(schema, maxDepth: 6))
            {
                findings.Add(SpecFinding(
                    "spec-limits", "costly-spec-unbounded", "medium", "inferred",
                    $"OpenAPI request body: unbounded {issue}",
                    ResolveOperationUrl(specUrl, serverUrl, path), method.ToUpperInvariant(), issue,
                    $"{method.ToUpperInvariant()} {path} — request schema may allow large single-request payloads ({issue}).",
                    $"{path} spec={specUrl}",
                    "Add maxItems/maxLength/maximum in the spec and validate on the server.",
                    null));
                break;
            }
        }

        return findings;
    }

    private static IEnumerable<string> FindUnboundedSchemaNodes(JsonElement schema, int maxDepth, int depth = 0)
    {
        if (depth > maxDepth) yield break;

        if (schema.TryGetProperty("type", out var typeEl))
        {
            var type = typeEl.GetString();
            if (type == "array" && !schema.TryGetProperty("maxItems", out _))
                yield return "array without maxItems";
            if (type == "string" && !schema.TryGetProperty("maxLength", out _))
            {
                if (schema.TryGetProperty("format", out var fmt)
                    && fmt.GetString() is "byte" or "binary")
                    yield return "binary string without maxLength";
            }
            if (type == "integer" && !schema.TryGetProperty("maximum", out _))
                yield return "integer without maximum";
        }

        if (schema.TryGetProperty("properties", out var props) && props.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in props.EnumerateObject())
            {
                foreach (var inner in FindUnboundedSchemaNodes(p.Value, maxDepth, depth + 1))
                    yield return $"{p.Name}: {inner}";
            }
        }
    }

    private static bool HasNumericMaximum(JsonElement schema) =>
        schema.TryGetProperty("maximum", out _)
        || schema.TryGetProperty("exclusiveMaximum", out _);

    private static bool LooksLikeOpenApi(string url, string contentType, string body) =>
        OpenApiSpecHeuristics.BodyLooksLikeOpenApi(contentType, body)
        && (OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(url)
            || body.Contains("\"paths\"", StringComparison.OrdinalIgnoreCase)
            || body.Contains("paths:", StringComparison.OrdinalIgnoreCase));

    private static bool LooksLikeGraphQlIntrospection(string body) =>
        body.Contains("\"__schema\"", StringComparison.Ordinal)
        && body.Contains("\"types\"", StringComparison.Ordinal)
        && (body.Contains("\"queryType\"", StringComparison.Ordinal) || body.Contains("Query", StringComparison.Ordinal));

    private static bool UrlMatches(string entryUrl, string scope) =>
        entryUrl.Equals(scope, StringComparison.OrdinalIgnoreCase)
        || (Uri.TryCreate(entryUrl, UriKind.Absolute, out var a)
            && Uri.TryCreate(scope, UriKind.Absolute, out var b)
            && string.Equals(a.AbsolutePath, b.AbsolutePath, StringComparison.OrdinalIgnoreCase));

    private static string? FirstServerUrl(JsonElement root)
    {
        if (!root.TryGetProperty("servers", out var servers) || servers.ValueKind != JsonValueKind.Array)
            return null;
        foreach (var server in servers.EnumerateArray())
        {
            if (server.ValueKind != JsonValueKind.Object) continue;
            if (server.TryGetProperty("url", out var url) && url.ValueKind == JsonValueKind.String)
            {
                var value = url.GetString();
                if (!string.IsNullOrWhiteSpace(value)) return value;
            }
        }

        return null;
    }

    internal static string ResolveOperationUrl(string specUrl, string? serverUrl, string path)
    {
        if (!path.StartsWith('/')) path = "/" + path;
        if (!Uri.TryCreate(specUrl, UriKind.Absolute, out var spec))
            return path;

        string baseUrl;
        if (string.IsNullOrWhiteSpace(serverUrl))
            baseUrl = spec.GetLeftPart(UriPartial.Authority);
        else if (Uri.TryCreate(serverUrl, UriKind.Absolute, out var absolute))
            baseUrl = absolute.GetLeftPart(UriPartial.Path).TrimEnd('/');
        else if (serverUrl.StartsWith('/'))
            baseUrl = spec.GetLeftPart(UriPartial.Authority) + serverUrl.TrimEnd('/');
        else
            baseUrl = spec.GetLeftPart(UriPartial.Authority);

        return baseUrl + path;
    }

    private static CostlyOperationsProbe.CostlyFinding SpecFinding(
        string checkId,
        string category,
        string severity,
        string confidence,
        string title,
        string endpoint,
        string method,
        string? parameter,
        string detail,
        string? evidence,
        string remediation,
        string? relatedProbe) => new()
    {
        CheckId = checkId,
        Category = category,
        Severity = severity,
        Confidence = confidence,
        Title = title,
        Endpoint = endpoint,
        Method = string.IsNullOrWhiteSpace(method) ? "GET" : method.ToUpperInvariant(),
        Parameter = parameter,
        Detail = detail,
        Evidence = evidence,
        Remediation = remediation,
        RelatedProbe = relatedProbe
    };
}
