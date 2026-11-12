using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.RepresentationModel;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Parses OpenAPI/Swagger JSON documents into probe-ready operations and synthesizes HTTP requests.
/// </summary>
public static class OpenApiOperationCatalog
{
    private static readonly HashSet<string> HttpVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "get", "put", "post", "delete", "options", "head", "patch", "trace"
    };

    private static readonly Regex PathBraceParams = new(@"\{([^/}]+)}", RegexOptions.Compiled);

    private static readonly string[] LimitParamNames =
    [
        "limit", "pageSize", "pagesize", "page_size", "per_page", "perPage", "size", "top", "$top", "take", "count", "max"
    ];

    public sealed class SpecDocument
    {
        public string Url { get; init; } = "";
        public string Body { get; init; } = "";
    }

    public sealed class OpenApiParameter
    {
        public string Name { get; init; } = "";
        public string In { get; init; } = "query";
        public bool Required { get; init; }
        /// <summary>Detached copy of parameter schema (survives after parse <see cref="JsonDocument"/> is disposed).</summary>
        public string? SchemaJson { get; init; }
        public string? SchemaType { get; init; }
        public bool IsLimitLike { get; init; }
    }

    public sealed class OpenApiRequestBody
    {
        public string ContentType { get; init; } = "application/json";
        public string? SchemaJson { get; init; }
        public string? ExampleJson { get; init; }
    }

    public sealed class OpenApiOperation
    {
        public string SpecUrl { get; init; } = "";
        public string BaseUrl { get; init; } = "";
        public string PathTemplate { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string? OperationId { get; init; }
        public bool Deprecated { get; init; }
        public bool RequiresSecurity { get; init; }
        public List<OpenApiParameter> Parameters { get; init; } = [];
        public OpenApiRequestBody? RequestBody { get; init; }
        public int PriorityScore { get; set; }
    }

    public enum RequestVariant
    {
        Minimal,
        Example,
        Edge,
        Malformed,
        OmitField
    }

    public sealed class BuiltRequest
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string? Body { get; init; }
        public string Variant { get; init; } = "minimal";
        public string? OmittedField { get; init; }
        public OpenApiOperation Operation { get; init; } = null!;
    }

    public static (List<OpenApiOperation> Operations, List<string> ParseErrors) ParseAll(
        IEnumerable<SpecDocument> docs,
        string fallbackAuthority)
    {
        var ops = new List<OpenApiOperation>();
        var errors = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var doc in docs)
        {
            if (string.IsNullOrWhiteSpace(doc.Body)) continue;
            Uri docUri;
            if (!Uri.TryCreate(doc.Url, UriKind.Absolute, out docUri!))
                docUri = Uri.TryCreate(fallbackAuthority, UriKind.Absolute, out var fb)
                    ? fb
                    : new Uri("https://localhost/", UriKind.Absolute);

            List<OpenApiOperation> parsed;
            try
            {
                parsed = ParseDocument(doc.Body, doc.Url, docUri, fallbackAuthority);
            }
            catch (JsonException ex)
            {
                errors.Add($"{doc.Url}: JSON parse failed — {ex.Message}. Try re-fetching the spec (truncated capture?)");
                continue;
            }
            catch (Exception ex)
            {
                errors.Add($"{doc.Url}: {ex.Message}");
                continue;
            }

            if (parsed.Count == 0)
                errors.Add($"{doc.Url}: no operations parsed (unsupported or empty spec)");

            foreach (var op in parsed)
            {
                var key = $"{op.Method}|{op.BaseUrl}|{op.PathTemplate}";
                if (seen.Add(key))
                {
                    op.PriorityScore = ScoreOperation(op);
                    ops.Add(op);
                }
            }
        }

        return (ops.OrderByDescending(o => o.PriorityScore).ToList(), errors);
    }

    public static List<OpenApiOperation> ParseDocument(string body, string specUrl, Uri documentUri, string fallbackAuthority)
    {
        var trim = body.TrimStart();
        if (trim.StartsWith('{'))
            return ParseJsonDocument(body, specUrl, documentUri, fallbackAuthority);

        if (trim.StartsWith("openapi:", StringComparison.OrdinalIgnoreCase)
            || trim.StartsWith("swagger:", StringComparison.OrdinalIgnoreCase))
            return ParseYamlDocument(body, specUrl, documentUri, fallbackAuthority);

        return [];
    }

    private static List<OpenApiOperation> ParseJsonDocument(string body, string specUrl, Uri documentUri, string fallbackAuthority)
    {
        var ops = new List<OpenApiOperation>();
        using var jd = JsonDocument.Parse(body);
        var root = jd.RootElement;
        if (!root.TryGetProperty("paths", out var pathsEl) || pathsEl.ValueKind != JsonValueKind.Object)
            return ops;

        var isSwagger2 = root.TryGetProperty("swagger", out var sw)
                         && sw.ValueKind == JsonValueKind.String
                         && sw.GetString()!.StartsWith('2');

        foreach (var baseUrl in ResolveServerBases(documentUri, root, isSwagger2, fallbackAuthority))
        {
            foreach (var pathProp in pathsEl.EnumerateObject())
            {
                if (pathProp.Value.ValueKind != JsonValueKind.Object) continue;
                foreach (var opProp in pathProp.Value.EnumerateObject())
                {
                    if (!HttpVerbs.Contains(opProp.Name)) continue;
                    var method = opProp.Name.ToUpperInvariant();
                    var opEl = opProp.Value;
                    if (opEl.TryGetProperty("deprecated", out var dep) && dep.ValueKind == JsonValueKind.True)
                        continue;

                    var requiresSecurity = opEl.TryGetProperty("security", out var secEl)
                                           && secEl.ValueKind == JsonValueKind.Array
                                           && secEl.GetArrayLength() > 0;
                    if (!requiresSecurity && root.TryGetProperty("security", out var globalSec)
                        && globalSec.ValueKind == JsonValueKind.Array
                        && globalSec.GetArrayLength() > 0)
                        requiresSecurity = true;

                    var parameters = ParseParameters(opEl, pathProp.Name);
                    var requestBody = ParseRequestBody(opEl);

                    ops.Add(new OpenApiOperation
                    {
                        SpecUrl = specUrl,
                        BaseUrl = baseUrl,
                        PathTemplate = pathProp.Name,
                        Method = method,
                        OperationId = opEl.TryGetProperty("operationId", out var oid) ? oid.GetString() : null,
                        RequiresSecurity = requiresSecurity,
                        Parameters = parameters,
                        RequestBody = requestBody
                    });
                }
            }
        }

        return ops;
    }

    private static List<OpenApiOperation> ParseYamlDocument(string yaml, string specUrl, Uri documentUri, string fallbackAuthority)
    {
        var ops = new List<OpenApiOperation>();
        using var reader = new StringReader(yaml);
        var ys = new YamlStream();
        ys.Load(reader);
        var root = ys.Documents.FirstOrDefault()?.RootNode as YamlMappingNode;
        if (root?.Children.TryGetValue(new YamlScalarNode("paths"), out var pn) != true
            || pn is not YamlMappingNode pathsMap)
            return ops;

        var globalSecurity = root.Children.ContainsKey(new YamlScalarNode("security"));
        var serverBases = ResolveYamlServerBases(root, documentUri, fallbackAuthority);

        foreach (var (pathScalar, node) in pathsMap.Children)
        {
            if (pathScalar is not YamlScalarNode pk || node is not YamlMappingNode opMap)
                continue;
            var apiPath = pk.Value ?? "";
            if (string.IsNullOrEmpty(apiPath)) continue;

            foreach (var (methScalar, opNode) in opMap.Children)
            {
                if (methScalar is not YamlScalarNode mk || opNode is not YamlMappingNode opMapNode)
                    continue;
                if (!HttpVerbs.Contains(mk.Value ?? "")) continue;

                if (opMapNode.Children.ContainsKey(new YamlScalarNode("deprecated")))
                    continue;

                var requiresSecurity = opMapNode.Children.ContainsKey(new YamlScalarNode("security")) || globalSecurity;
                var parameters = ParseYamlParameters(opMapNode, apiPath);
                var requestBody = ParseYamlRequestBody(opMapNode);

                foreach (var baseUrl in serverBases)
                {
                    ops.Add(new OpenApiOperation
                    {
                        SpecUrl = specUrl,
                        BaseUrl = baseUrl,
                        PathTemplate = apiPath,
                        Method = mk.Value!.Trim().ToUpperInvariant(),
                        OperationId = YamlString(opMapNode, "operationId"),
                        RequiresSecurity = requiresSecurity,
                        Parameters = parameters,
                        RequestBody = requestBody
                    });
                }
            }
        }

        return ops;
    }

    private static List<OpenApiParameter> ParseYamlParameters(YamlMappingNode opMap, string pathTemplate)
    {
        var list = new List<OpenApiParameter>();
        foreach (Match m in PathBraceParams.Matches(pathTemplate))
        {
            list.Add(new OpenApiParameter { Name = m.Groups[1].Value, In = "path", Required = true });
        }

        if (!opMap.Children.TryGetValue(new YamlScalarNode("parameters"), out var pn)
            || pn is not YamlSequenceNode seq)
            return list;

        foreach (var item in seq.Children.OfType<YamlMappingNode>())
        {
            var name = YamlString(item, "name");
            if (string.IsNullOrEmpty(name)) continue;
            var loc = YamlString(item, "in") ?? "query";
            var required = item.Children.ContainsKey(new YamlScalarNode("required"));
            var isLimit = LimitParamNames.Any(p => name.Equals(p, StringComparison.OrdinalIgnoreCase));
            list.Add(new OpenApiParameter
            {
                Name = name,
                In = loc,
                Required = required,
                IsLimitLike = isLimit
            });
        }

        return list;
    }

    private static OpenApiRequestBody? ParseYamlRequestBody(YamlMappingNode opMap)
    {
        if (!opMap.Children.TryGetValue(new YamlScalarNode("requestBody"), out var rb)
            || rb is not YamlMappingNode rbMap)
            return null;
        if (!rbMap.Children.TryGetValue(new YamlScalarNode("content"), out var content)
            || content is not YamlMappingNode contentMap)
            return null;

        foreach (var (mediaKey, mediaVal) in contentMap.Children)
        {
            if (mediaKey is not YamlScalarNode mk) continue;
            var media = mk.Value ?? "";
            if (!media.Contains("json", StringComparison.OrdinalIgnoreCase)
                && !media.Contains("fhir", StringComparison.OrdinalIgnoreCase))
                continue;

            string? example = null;
            if (mediaVal is YamlMappingNode mm)
            {
                if (mm.Children.TryGetValue(new YamlScalarNode("example"), out var exNode) && exNode is YamlScalarNode exs)
                    example = exs.Value;
            }

            return new OpenApiRequestBody
            {
                ContentType = media.Contains("fhir", StringComparison.OrdinalIgnoreCase)
                    ? "application/fhir+json"
                    : "application/json",
                ExampleJson = example
            };
        }

        return new OpenApiRequestBody { ContentType = "application/json" };
    }

    private static List<string> ResolveYamlServerBases(YamlMappingNode root, Uri docUri, string fallbackAuthority)
    {
        if (root.Children.TryGetValue(new YamlScalarNode("servers"), out var sn) && sn is YamlSequenceNode seq)
        {
            var bases = seq.Children.OfType<YamlMappingNode>()
                .Select(m => YamlString(m, "url"))
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u => ResolveServerUrl(docUri, u!).TrimEnd('/'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (bases.Count > 0) return bases;
        }

        if (Uri.TryCreate(fallbackAuthority, UriKind.Absolute, out var fb))
            return [fb.GetLeftPart(UriPartial.Authority).TrimEnd('/')];

        return [docUri.GetLeftPart(UriPartial.Authority).TrimEnd('/')];
    }

    private static string? YamlString(YamlMappingNode map, string key) =>
        map.Children.TryGetValue(new YamlScalarNode(key), out var v) && v is YamlScalarNode s ? s.Value : null;

    public static BuiltRequest? BuildRequest(OpenApiOperation op, RequestVariant variant, string? omitField = null)
    {
        var path = op.PathTemplate;
        foreach (Match m in PathBraceParams.Matches(path))
        {
            var name = m.Groups[1].Value;
            var val = variant == RequestVariant.Edge && name.Contains("id", StringComparison.OrdinalIgnoreCase)
                ? "999999999"
                : "1";
            path = path.Replace("{" + name + "}", Uri.EscapeDataString(val), StringComparison.Ordinal);
        }

        var queryParts = new List<string>();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in op.Parameters)
        {
            if (string.Equals(p.In, "path", StringComparison.OrdinalIgnoreCase))
                continue;

            if (string.Equals(p.In, "header", StringComparison.OrdinalIgnoreCase))
            {
                if (p.Required || variant is RequestVariant.Minimal or RequestVariant.Example)
                    headers[p.Name] = SampleScalar(p, variant);
                continue;
            }

            if (!string.Equals(p.In, "query", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!p.Required && variant is RequestVariant.Minimal)
                continue;

            if (variant == RequestVariant.Edge && p.IsLimitLike)
                queryParts.Add($"{Uri.EscapeDataString(p.Name)}=9999");
            else if (p.Required || variant != RequestVariant.Minimal)
                queryParts.Add($"{Uri.EscapeDataString(p.Name)}={Uri.EscapeDataString(SampleScalar(p, variant))}");
        }

        var url = op.BaseUrl.TrimEnd('/') + path;
        if (queryParts.Count > 0)
            url += "?" + string.Join("&", queryParts);

        string? body = null;
        if (op.RequestBody != null && op.Method is "POST" or "PUT" or "PATCH")
        {
            if (variant == RequestVariant.Malformed)
                body = "{\"email\":";
            else if (variant == RequestVariant.OmitField && !string.IsNullOrEmpty(omitField))
                body = BuildBodyOmitField(op.RequestBody, omitField);
            else if (variant == RequestVariant.Example && !string.IsNullOrEmpty(op.RequestBody.ExampleJson))
                body = op.RequestBody.ExampleJson;
            else
                body = BuildBodyFromSchema(op.RequestBody, variant, omitField);

            headers.TryAdd("Content-Type", op.RequestBody.ContentType);
        }

        if (body == null && op.Method is "POST" or "PUT" or "PATCH" && variant != RequestVariant.Minimal)
            body = "{}";

        return new BuiltRequest
        {
            Url = url,
            Method = op.Method,
            Headers = headers,
            Body = body,
            Variant = variant.ToString().ToLowerInvariant(),
            OmittedField = omitField,
            Operation = op
        };
    }

    public static AttackSurfaceEndpoint ToAttackSurfaceEndpoint(OpenApiOperation op)
    {
        var rel = op.PathTemplate.StartsWith('/') ? op.PathTemplate : "/" + op.PathTemplate;
        var displayUrl = op.BaseUrl.TrimEnd('/') + rel;

        var pathParams = PathBraceParams.Matches(rel).Select(m => m.Groups[1].Value).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var query = op.Parameters.Where(p => string.Equals(p.In, "query", StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n).ToList();
        var bodyFields = op.RequestBody != null ? ExtractBodyFieldNames(op.RequestBody.SchemaJson) : [];

        var ep = new AttackSurfaceEndpoint
        {
            Url = displayUrl,
            UrlTemplate = AttackSurfaceMapper.TemplatizePath(rel),
            Methods = [op.Method],
            Parameters = new AttackSurfaceParameters
            {
                Path = pathParams,
                Query = query,
                Body = bodyFields,
                RequestContentType = op.RequestBody?.ContentType
            },
            Auth = new AttackSurfaceAuth
            {
                Required = op.RequiresSecurity,
                Type = op.RequiresSecurity ? "openapi-security" : "none (openapi)"
            },
            DiscoveredVia = { "swaggering-catalog" },
            RequestCount = 0,
            TestPriority = AttackSurfaceMapper.EstimatePriorityWithoutTraffic(new AttackSurfaceEndpoint
            {
                Url = displayUrl,
                Parameters = new AttackSurfaceParameters { Path = pathParams, Query = query, Body = bodyFields }
            })
        };
        return ep;
    }

    public static AttackSurfaceResult BuildSurfaceFromOperations(IEnumerable<OpenApiOperation> operations)
    {
        var mergeMap = new Dictionary<string, AttackSurfaceEndpoint>(StringComparer.OrdinalIgnoreCase);
        foreach (var op in operations)
        {
            var ep = ToAttackSurfaceEndpoint(op);
            var key = AttackSurfaceMapper.EndpointMergeKeyFromUrl(ep.Url);
            if (mergeMap.TryGetValue(key, out var existing))
            {
                existing.Methods.Add(op.Method);
                foreach (var q in ep.Parameters.Query)
                    if (!existing.Parameters.Query.Contains(q, StringComparer.OrdinalIgnoreCase))
                        existing.Parameters.Query.Add(q);
                foreach (var b in ep.Parameters.Body)
                    if (!existing.Parameters.Body.Contains(b, StringComparer.OrdinalIgnoreCase))
                        existing.Parameters.Body.Add(b);
            }
            else
                mergeMap[key] = ep;
        }

        var surface = new AttackSurfaceResult
        {
            Endpoints = mergeMap.Values.ToList(),
            Source = "swaggering-catalog"
        };
        var mapper = new AttackSurfaceMapper();
        mapper.AttachRefreshedSummary(surface, []);
        return surface;
    }

    private static int ScoreOperation(OpenApiOperation op)
    {
        var score = 0;
        if (op.RequiresSecurity) score += 40;
        if (op.Parameters.Any(p => p.IsLimitLike)) score += 25;
        if (op.PathTemplate.Contains('{')) score += 20;
        if (op.Method is "POST" or "PUT" or "PATCH") score += 15;
        if (op.RequestBody != null) score += 10;
        return score;
    }

    private static List<OpenApiParameter> ParseParameters(JsonElement opEl, string pathTemplate)
    {
        var list = new List<OpenApiParameter>();
        foreach (Match m in PathBraceParams.Matches(pathTemplate))
        {
            list.Add(new OpenApiParameter
            {
                Name = m.Groups[1].Value,
                In = "path",
                Required = true
            });
        }

        if (!opEl.TryGetProperty("parameters", out var parameters) || parameters.ValueKind != JsonValueKind.Array)
            return list;

        foreach (var param in parameters.EnumerateArray())
        {
            var name = param.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(name)) continue;
            var loc = param.TryGetProperty("in", out var locEl) ? locEl.GetString() ?? "query" : "query";
            var required = param.TryGetProperty("required", out var req) && req.ValueKind == JsonValueKind.True;
            JsonElement schema = default;
            if (param.TryGetProperty("schema", out var sch))
                schema = sch;
            else if (param.TryGetProperty("type", out _))
                schema = param;

            var schemaJson = CaptureSchemaJson(schema);
            list.Add(new OpenApiParameter
            {
                Name = name,
                In = loc,
                Required = required,
                SchemaJson = schemaJson,
                SchemaType = ReadSchemaType(schemaJson),
                IsLimitLike = LimitParamNames.Any(p => name.Equals(p, StringComparison.OrdinalIgnoreCase)
                                                        || name.Equals("$" + p, StringComparison.OrdinalIgnoreCase))
            });
        }

        return list;
    }

    private static OpenApiRequestBody? ParseRequestBody(JsonElement opEl)
    {
        if (!opEl.TryGetProperty("requestBody", out var rb) || rb.ValueKind != JsonValueKind.Object)
            return null;
        if (!rb.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object)
            return null;

        foreach (var media in content.EnumerateObject())
        {
            if (!media.Name.Contains("json", StringComparison.OrdinalIgnoreCase)
                && !media.Name.Contains("fhir", StringComparison.OrdinalIgnoreCase))
                continue;
            JsonElement schema = default;
            if (media.Value.TryGetProperty("schema", out var sch))
                schema = sch;

            string? example = null;
            if (media.Value.TryGetProperty("example", out var ex) && ex.ValueKind != JsonValueKind.Undefined)
                example = ex.GetRawText();
            else if (schema.ValueKind != JsonValueKind.Undefined
                     && schema.TryGetProperty("example", out var schEx))
                example = schEx.GetRawText();

            return new OpenApiRequestBody
            {
                ContentType = media.Name.Contains("fhir", StringComparison.OrdinalIgnoreCase)
                    ? media.Name
                    : media.Name,
                SchemaJson = CaptureSchemaJson(schema),
                ExampleJson = example
            };
        }

        return null;
    }

    private static List<string> ResolveServerBases(Uri documentUri, JsonElement root, bool isSwagger2, string fallbackAuthority)
    {
        if (isSwagger2)
        {
            var hostPart = root.TryGetProperty("host", out var hEl) && hEl.ValueKind == JsonValueKind.String
                ? hEl.GetString()!.Trim()
                : documentUri.Host;
            var basePath = root.TryGetProperty("basePath", out var bp) && bp.ValueKind == JsonValueKind.String
                ? bp.GetString() ?? "/"
                : "/";
            var scheme = root.TryGetProperty("schemes", out var schemes) && schemes.ValueKind == JsonValueKind.Array
                && schemes.GetArrayLength() > 0
                ? schemes[0].GetString() ?? documentUri.Scheme
                : documentUri.Scheme;
            var authority = $"{scheme}://{hostPart}".TrimEnd('/');
            return [$"{authority}{NormalizeBasePath(basePath)}"];
        }

        if (root.TryGetProperty("servers", out var srvEl) && srvEl.ValueKind == JsonValueKind.Array)
        {
            var bases = srvEl.EnumerateArray()
                .Where(s => s.ValueKind == JsonValueKind.Object && s.TryGetProperty("url", out _))
                .Select(s => ResolveServerUrl(documentUri, s.GetProperty("url").GetString()!))
                .Where(u => !string.IsNullOrEmpty(u))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (bases.Count > 0) return bases;
        }

        if (Uri.TryCreate(fallbackAuthority, UriKind.Absolute, out var fb))
            return [fb.GetLeftPart(UriPartial.Authority).TrimEnd('/')];

        return [documentUri.GetLeftPart(UriPartial.Authority).TrimEnd('/')];
    }

    private static string ResolveServerUrl(Uri documentUri, string serverUrl)
    {
        var s = serverUrl.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var abs))
            return abs.ToString().TrimEnd('/');
        var authority = documentUri.GetLeftPart(UriPartial.Authority);
        return new Uri(authority.TrimEnd('/') + (s.StartsWith('/') ? "" : "/") + s).ToString().TrimEnd('/');
    }

    private static string NormalizeBasePath(string basePath)
    {
        if (string.IsNullOrEmpty(basePath) || basePath == "/") return "";
        return basePath.StartsWith('/') ? basePath.TrimEnd('/') : "/" + basePath.TrimEnd('/');
    }

    private static string? CaptureSchemaJson(JsonElement schema) =>
        schema.ValueKind == JsonValueKind.Undefined ? null : schema.GetRawText();

    private static string? ReadSchemaType(string? schemaJson)
    {
        if (string.IsNullOrEmpty(schemaJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(schemaJson);
            return doc.RootElement.TryGetProperty("type", out var t) ? t.GetString() : null;
        }
        catch
        {
            return null;
        }
    }

    private static string SampleScalar(OpenApiParameter param, RequestVariant variant)
    {
        if (variant == RequestVariant.Edge && param.IsLimitLike) return "9999";
        if (string.IsNullOrEmpty(param.SchemaJson))
            return param.SchemaType switch
            {
                "integer" or "number" => "1",
                "boolean" => "true",
                _ => "test"
            };

        try
        {
            using var doc = JsonDocument.Parse(param.SchemaJson);
            return SampleScalarElement(doc.RootElement, variant, param.IsLimitLike);
        }
        catch
        {
            return "test";
        }
    }

    private static string SampleScalarElement(JsonElement schema, RequestVariant variant, bool isLimitLike)
    {
        if (variant == RequestVariant.Edge && isLimitLike) return "9999";
        if (schema.ValueKind == JsonValueKind.Undefined) return "test";
        if (schema.TryGetProperty("enum", out var en) && en.ValueKind == JsonValueKind.Array && en.GetArrayLength() > 0)
            return en[0].ToString();
        var type = schema.TryGetProperty("type", out var t) ? t.GetString() : "string";
        return type switch
        {
            "integer" or "number" => "1",
            "boolean" => "true",
            _ => "test"
        };
    }

    private static string BuildBodyFromSchema(OpenApiRequestBody body, RequestVariant variant, string? omitField)
    {
        if (string.IsNullOrEmpty(body.SchemaJson))
            return "{}";

        try
        {
            using var doc = JsonDocument.Parse(body.SchemaJson);
            return BuildBodyFromSchemaElement(doc.RootElement, variant, omitField);
        }
        catch
        {
            return "{}";
        }
    }

    private static string BuildBodyFromSchemaElement(JsonElement schema, RequestVariant variant, string? omitField)
    {
        if (schema.ValueKind == JsonValueKind.Undefined)
            return "{}";

        if (schema.TryGetProperty("properties", out var props) && props.ValueKind == JsonValueKind.Object)
        {
            var obj = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            var required = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (schema.TryGetProperty("required", out var reqArr) && reqArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var r in reqArr.EnumerateArray())
                {
                    if (r.ValueKind == JsonValueKind.String)
                        required.Add(r.GetString()!);
                }
            }

            foreach (var p in props.EnumerateObject())
            {
                if (omitField != null && string.Equals(p.Name, omitField, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (variant == RequestVariant.Minimal && !required.Contains(p.Name))
                    continue;
                obj[p.Name] = SampleJsonValue(p.Value, variant);
            }

            return JsonSerializer.Serialize(obj);
        }

        return "{}";
    }

    private static string BuildBodyOmitField(OpenApiRequestBody body, string field)
    {
        var baseJson = !string.IsNullOrEmpty(body.ExampleJson)
            ? body.ExampleJson
            : BuildBodyFromSchema(body, RequestVariant.Example, null);
        try
        {
            using var doc = JsonDocument.Parse(baseJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return baseJson;
            var dict = new Dictionary<string, JsonElement>();
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (!string.Equals(p.Name, field, StringComparison.OrdinalIgnoreCase))
                    dict[p.Name] = p.Value.Clone();
            }

            return JsonSerializer.Serialize(dict);
        }
        catch
        {
            return BuildBodyFromSchema(body, RequestVariant.Example, field);
        }
    }

    private static object? SampleJsonValue(JsonElement schema, RequestVariant variant)
    {
        var type = schema.TryGetProperty("type", out var t) ? t.GetString() : null;
        return type switch
        {
            "integer" or "number" => 1,
            "boolean" => true,
            "array" => Array.Empty<object>(),
            "object" => new Dictionary<string, object>(),
            _ => "test"
        };
    }

    private static List<string> ExtractBodyFieldNames(string? schemaJson)
    {
        var names = new List<string>();
        if (string.IsNullOrEmpty(schemaJson)) return names;
        try
        {
            using var doc = JsonDocument.Parse(schemaJson);
            var schema = doc.RootElement;
            if (schema.TryGetProperty("properties", out var props) && props.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in props.EnumerateObject())
                    names.Add(p.Name);
            }
        }
        catch
        {
            // ignore
        }

        return names.OrderBy(n => n).ToList();
    }
}
