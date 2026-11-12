using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Automated GraphQL security analysis. Performs introspection, mutation/subscription discovery,
/// query batching, alias amplification, depth limit probing, max limit testing, draft/preview
/// access, field suggestion exploitation, and rate limit extraction against a GraphQL endpoint.
/// </summary>
public static class GraphqlAnalyzer
{
    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        AllowAutoRedirect = true,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private static readonly string[] SensitivePatterns =
    [
        "user", "admin", "password", "token", "secret", "payment", "credential",
        "auth", "session", "key", "private", "internal", "role", "permission",
        "audit", "auditlog", "securityevent", "logentry", "eventlog"
    ];

    public sealed class GraphqlOptions
    {
        public string? Url { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public bool AutoDetect { get; set; } = true;
        public int TimeoutMs { get; set; } = 30000;
        public bool SkipIntrospection { get; set; }
        public bool SkipBatching { get; set; }
        public bool SkipAmplification { get; set; }
        public bool SkipDepthProbe { get; set; }
        public bool SkipLimitProbe { get; set; }
        public bool SkipFieldSuggestion { get; set; }
        public bool SkipDraftAccess { get; set; }
        public bool IncludeCostAnalysis { get; set; }
    }

    public sealed class GraphqlFinding
    {
        public string Category { get; set; } = "";
        public string Severity { get; set; } = "info";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public object? Details { get; set; }
    }

    public sealed class GraphqlSchemaSummary
    {
        public int TotalTypes { get; set; }
        public int QueryTypes { get; set; }
        public int MutationTypes { get; set; }
        public int SubscriptionTypes { get; set; }
        public bool HasMutations { get; set; }
        public bool HasSubscriptions { get; set; }
        public List<string> SensitiveTypes { get; set; } = [];
        public string? RateLimit { get; set; }
    }

    public sealed class CostFinding
    {
        public string Query { get; set; } = "";
        public int Depth { get; set; }
        public int ResponseTimeMs { get; set; }
        public string Status { get; set; } = "";
        public string Description { get; set; } = "";
    }

    public sealed class CostAnalysisResult
    {
        public int QueriesBuilt { get; set; }
        public int QueriesSent { get; set; }
        public int MaxDepthAccepted { get; set; }
        public int MaxResponseTimeMs { get; set; }
        public List<CostFinding> Findings { get; set; } = [];
    }

    public sealed class GraphqlResult
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string Url { get; set; } = "";
        public List<GraphqlFinding> Findings { get; set; } = [];
        public GraphqlSchemaSummary Schema { get; set; } = new();
        public CostAnalysisResult? CostAnalysis { get; set; }
        public List<string> Errors { get; set; } = [];
        public int ElapsedMs { get; set; }
    }

    public static async Task<GraphqlResult> RunAsync(
        AutomationContext? ctx, GraphqlOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new GraphqlResult();

        var url = options.Url?.TrimEnd('/');

        if (string.IsNullOrEmpty(url) && options.AutoDetect && ctx != null)
            url = TryAutoDetectEndpoint(ctx);

        if (string.IsNullOrEmpty(url))
        {
            result.Errors.Add("No GraphQL URL provided and auto-detection from network log found nothing. " +
                              "Provide a url parameter (e.g. https://api.example.com/graphql).");
            result.ElapsedMs = (int)sw.ElapsedMilliseconds;
            return result;
        }

        result.Url = url;
        var headers = options.Headers ?? new Dictionary<string, string>();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(options.TimeoutMs);
        var token = linkedCts.Token;

        // 1. Introspection test
        JsonElement? schema = null;
        if (!options.SkipIntrospection)
        {
            try
            {
                schema = await TestIntrospection(url, headers, result, token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                result.Errors.Add($"Introspection test failed: {ex.Message}");
            }
        }

        // 2. Mutation/subscription check (uses introspection result)
        if (schema != null)
        {
            try { AnalyzeMutationsAndSubscriptions(schema.Value, result); }
            catch (Exception ex) { result.Errors.Add($"Mutation/subscription analysis failed: {ex.Message}"); }
        }

        var parallelTasks = new List<Task>();

        // 3. Query batching test
        if (!options.SkipBatching)
            parallelTasks.Add(SafeRun(() => TestBatching(url, headers, result, token), "batching", result));

        // 4. Alias amplification test
        if (!options.SkipAmplification)
            parallelTasks.Add(SafeRun(() => TestAliasAmplification(url, headers, schema, result, token), "amplification", result));

        // 5. Depth limit test
        if (!options.SkipDepthProbe)
            parallelTasks.Add(SafeRun(() => TestDepthLimit(url, headers, schema, result, token), "depth-limit", result));

        // 6. Max limit test
        if (!options.SkipLimitProbe)
            parallelTasks.Add(SafeRun(() => TestMaxLimit(url, headers, schema, result, token), "max-limit", result));

        // 7. Draft/preview access
        if (!options.SkipDraftAccess)
            parallelTasks.Add(SafeRun(() => TestDraftAccess(url, headers, schema, result, token), "draft-access", result));

        // 8. Field suggestion exploitation
        if (!options.SkipFieldSuggestion)
            parallelTasks.Add(SafeRun(() => TestFieldSuggestion(url, headers, result, token), "field-suggestion", result));

        await Task.WhenAll(parallelTasks);

        // 9. Rate limit extraction (already collected from response headers during other tests)

        // 10. Cost analysis (active mode only, requires successful introspection)
        if (options.IncludeCostAnalysis && schema != null)
        {
            try
            {
                await RunCostAnalysisAsync(url, headers, schema.Value, result, token);
            }
            catch (OperationCanceledException)
            {
                result.Errors.Add("cost-analysis test timed out.");
            }
            catch (Exception ex)
            {
                result.Errors.Add($"cost-analysis test failed: {ex.Message}");
            }
        }

        result.ElapsedMs = (int)sw.ElapsedMilliseconds;
        return result;
    }

    private static async Task SafeRun(Func<Task> action, string label, GraphqlResult result)
    {
        try
        {
            await action();
        }
        catch (OperationCanceledException)
        {
            result.Errors.Add($"{label} test timed out.");
        }
        catch (Exception ex)
        {
            result.Errors.Add($"{label} test failed: {ex.Message}");
        }
    }

    #region 1. Introspection

    private static async Task<JsonElement?> TestIntrospection(
        string url, Dictionary<string, string> headers, GraphqlResult result, CancellationToken ct)
    {
        const string introspectionQuery = @"
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types { name kind fields { name type { name kind ofType { name kind ofType { name kind } } } } }
                }
            }";

        var (json, responseHeaders) = await PostGraphql(url, headers, introspectionQuery, ct: ct);
        ExtractRateLimit(responseHeaders, result);

        if (json == null)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "introspection",
                Severity = "info",
                Title = "Introspection disabled or endpoint unreachable",
                Description = "The GraphQL endpoint did not respond to an introspection query. " +
                              "This is a good security practice for production APIs."
            });
            return null;
        }

        if (!json.Value.TryGetProperty("data", out var data) ||
            !data.TryGetProperty("__schema", out var schemaEl))
        {
            if (json.Value.TryGetProperty("errors", out var errs))
            {
                var errMsg = errs.EnumerateArray().FirstOrDefault().TryGetProperty("message", out var m)
                    ? m.GetString() : "unknown error";
                result.Findings.Add(new GraphqlFinding
                {
                    Category = "introspection",
                    Severity = "info",
                    Title = "Introspection blocked",
                    Description = $"Introspection returned an error: {errMsg}"
                });
            }
            return null;
        }

        var types = new List<SchemaType>();
        if (schemaEl.TryGetProperty("types", out var typesEl))
        {
            foreach (var t in typesEl.EnumerateArray())
            {
                var typeName = t.GetProperty("name").GetString() ?? "";
                var kind = t.GetProperty("kind").GetString() ?? "";
                var fieldCount = 0;
                var fieldNames = new List<string>();
                if (t.TryGetProperty("fields", out var fieldsEl) && fieldsEl.ValueKind == JsonValueKind.Array)
                {
                    fieldCount = fieldsEl.GetArrayLength();
                    foreach (var f in fieldsEl.EnumerateArray())
                    {
                        var fn = f.GetProperty("name").GetString();
                        if (fn != null) fieldNames.Add(fn);
                    }
                }
                types.Add(new SchemaType { Name = typeName, Kind = kind, FieldCount = fieldCount, FieldNames = fieldNames });
            }
        }

        var userTypes = types.Where(t => !t.Name.StartsWith("__")).ToList();
        var objectTypes = userTypes.Where(t => t.Kind == "OBJECT").ToList();
        var sensitiveTypes = userTypes
            .Where(t => SensitivePatterns.Any(p => t.Name.Contains(p, StringComparison.OrdinalIgnoreCase)))
            .Select(t => t.Name)
            .Distinct()
            .ToList();

        var queryTypeName = schemaEl.TryGetProperty("queryType", out var qt) && qt.ValueKind == JsonValueKind.Object
            ? qt.GetProperty("name").GetString() : null;
        var queryType = objectTypes.FirstOrDefault(t => t.Name == queryTypeName);

        result.Schema.TotalTypes = userTypes.Count;
        result.Schema.QueryTypes = queryType?.FieldCount ?? 0;
        result.Schema.SensitiveTypes = sensitiveTypes;

        var severity = sensitiveTypes.Count > 0 ? "high" : "medium";
        var sensitiveNote = sensitiveTypes.Count > 0
            ? $" Including {sensitiveTypes.Count} sensitive-looking types: {string.Join(", ", sensitiveTypes.Take(10))}."
            : "";

        result.Findings.Add(new GraphqlFinding
        {
            Category = "introspection",
            Severity = severity,
            Title = "Full schema introspection enabled",
            Description = $"Schema exposes {userTypes.Count} types including {objectTypes.Count} object types " +
                          $"with {queryType?.FieldCount ?? 0} query root fields.{sensitiveNote}",
            Details = new
            {
                typeCount = userTypes.Count,
                objectTypes = objectTypes.Count,
                queryFields = queryType?.FieldCount ?? 0,
                sensitiveTypes,
                allTypeNames = userTypes.Select(t => t.Name).OrderBy(n => n).ToList()
            }
        });

        return json;
    }

    private sealed class SchemaType
    {
        public string Name { get; set; } = "";
        public string Kind { get; set; } = "";
        public int FieldCount { get; set; }
        public List<string> FieldNames { get; set; } = [];
    }

    #endregion

    #region 2. Mutations & Subscriptions

    private static void AnalyzeMutationsAndSubscriptions(JsonElement json, GraphqlResult result)
    {
        if (!json.TryGetProperty("data", out var data) || !data.TryGetProperty("__schema", out var schema))
            return;

        var hasMutationType = schema.TryGetProperty("mutationType", out var mt) &&
                              mt.ValueKind == JsonValueKind.Object;
        var hasSubscriptionType = schema.TryGetProperty("subscriptionType", out var st) &&
                                  st.ValueKind == JsonValueKind.Object;

        var mutationTypeName = hasMutationType ? mt.GetProperty("name").GetString() : null;
        var subscriptionTypeName = hasSubscriptionType ? st.GetProperty("name").GetString() : null;

        int mutationCount = 0, subscriptionCount = 0;

        if (schema.TryGetProperty("types", out var types))
        {
            foreach (var t in types.EnumerateArray())
            {
                var name = t.GetProperty("name").GetString();
                if (name == mutationTypeName && t.TryGetProperty("fields", out var mf) &&
                    mf.ValueKind == JsonValueKind.Array)
                    mutationCount = mf.GetArrayLength();
                if (name == subscriptionTypeName && t.TryGetProperty("fields", out var sf) &&
                    sf.ValueKind == JsonValueKind.Array)
                    subscriptionCount = sf.GetArrayLength();
            }
        }

        result.Schema.HasMutations = hasMutationType;
        result.Schema.HasSubscriptions = hasSubscriptionType;
        result.Schema.MutationTypes = mutationCount;
        result.Schema.SubscriptionTypes = subscriptionCount;

        if (hasMutationType)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "mutations",
                Severity = "high",
                Title = "GraphQL mutations available",
                Description = $"Schema exposes {mutationCount} mutations (write operations). " +
                              "This means the API accepts data modifications. Review access controls on all mutations.",
                Details = new { mutationCount }
            });
        }

        if (hasSubscriptionType)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "subscriptions",
                Severity = "medium",
                Title = "GraphQL subscriptions available",
                Description = $"Schema exposes {subscriptionCount} subscription(s). " +
                              "Subscriptions maintain persistent connections and may expose real-time data streams.",
                Details = new { subscriptionCount }
            });
        }

        if (!hasMutationType && !hasSubscriptionType)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "mutations",
                Severity = "info",
                Title = "Read-only API (no mutations or subscriptions)",
                Description = "The schema defines no mutation or subscription type. This is a query-only API."
            });
        }
    }

    #endregion

    #region 3. Query Batching

    private static async Task TestBatching(
        string url, Dictionary<string, string> headers, GraphqlResult result, CancellationToken ct)
    {
        var batchPayload = JsonSerializer.Serialize(new[]
        {
            new { query = "{ __typename }" },
            new { query = "{ __typename }" },
            new { query = "{ __typename }" }
        });

        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        req.Content = new StringContent(batchPayload, Encoding.UTF8, "application/json");
        ApplyHeaders(req, headers);

        using var resp = await Http.SendAsync(req, ct);
        ExtractRateLimit(resp.Headers, result);
        var body = await resp.Content.ReadAsStringAsync(ct);

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
        {
            var count = doc.RootElement.GetArrayLength();
            result.Findings.Add(new GraphqlFinding
            {
                Category = "batching",
                Severity = "medium",
                Title = "Query batching supported",
                Description = $"The endpoint accepts batched queries (array of {count} queries returned {count} results). " +
                              "An attacker can send hundreds of operations in a single request to bypass per-request rate limiting.",
                Details = new { batchSize = 3, responsesReturned = count }
            });
        }
        else
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "batching",
                Severity = "info",
                Title = "Query batching not supported or limited",
                Description = "The endpoint returned a single response object for a batched request. " +
                              "Batching may be disabled or the endpoint only processes the first query."
            });
        }
    }

    #endregion

    #region 4. Alias Amplification

    private static async Task TestAliasAmplification(
        string url, Dictionary<string, string> headers, JsonElement? introspection,
        GraphqlResult result, CancellationToken ct)
    {
        var queryField = FindFirstQueryField(introspection);
        if (queryField == null)
        {
            // Fall back to __typename which always works
            queryField = "__typename";
        }

        const int aliasCount = 10;
        var aliases = string.Join("\n",
            Enumerable.Range(0, aliasCount).Select(i => $"a{i}: {queryField}"));
        var query = $"{{ {aliases} }}";

        var (json, responseHeaders) = await PostGraphql(url, headers, query, ct: ct);
        ExtractRateLimit(responseHeaders, result);

        if (json == null)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "amplification",
                Severity = "info",
                Title = "Alias amplification test inconclusive",
                Description = "Could not get a valid response for the amplification test query."
            });
            return;
        }

        var responseText = json.Value.GetRawText();
        var responseSize = Encoding.UTF8.GetByteCount(responseText);

        if (json.Value.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object)
        {
            var returnedAliases = 0;
            foreach (var _ in data.EnumerateObject()) returnedAliases++;

            if (returnedAliases >= aliasCount)
            {
                result.Findings.Add(new GraphqlFinding
                {
                    Category = "amplification",
                    Severity = "medium",
                    Title = "Alias amplification unrestricted",
                    Description = $"{aliasCount} aliases all returned data ({FormatBytes(responseSize)} response). " +
                                  "No query complexity limit detected. Attackers can amplify a single request " +
                                  "by duplicating expensive fields via aliases.",
                    Details = new { aliasCount, returnedAliases, responseSize }
                });
            }
            else
            {
                result.Findings.Add(new GraphqlFinding
                {
                    Category = "amplification",
                    Severity = "info",
                    Title = "Alias amplification partially restricted",
                    Description = $"Sent {aliasCount} aliases but only {returnedAliases} returned data. " +
                                  "A complexity limit may be in effect."
                });
            }
        }
    }

    private static string? FindFirstQueryField(JsonElement? introspection)
    {
        if (introspection == null) return null;

        try
        {
            if (!introspection.Value.TryGetProperty("data", out var data)) return null;
            if (!data.TryGetProperty("__schema", out var schema)) return null;
            if (!schema.TryGetProperty("queryType", out var qt)) return null;
            var queryTypeName = qt.GetProperty("name").GetString();
            if (queryTypeName == null || !schema.TryGetProperty("types", out var types)) return null;

            foreach (var t in types.EnumerateArray())
            {
                if (t.GetProperty("name").GetString() != queryTypeName) continue;
                if (!t.TryGetProperty("fields", out var fields)) return null;

                foreach (var f in fields.EnumerateArray())
                {
                    var fieldName = f.GetProperty("name").GetString();
                    if (fieldName != null && !fieldName.StartsWith("_"))
                        return fieldName;
                }
            }
        }
        catch { /* graceful fallback */ }
        return null;
    }

    #endregion

    #region 5. Depth Limit

    private static async Task TestDepthLimit(
        string url, Dictionary<string, string> headers, JsonElement? introspection,
        GraphqlResult result, CancellationToken ct)
    {
        // Use __typename at each level to test pure depth without needing real field names
        var depths = new[] { 3, 5, 8, 10, 15 };
        int maxSuccessfulDepth = 0;
        int? failedAtDepth = null;

        // Try to find a type with a self-referencing field from introspection
        var (fieldChain, typeName) = FindNestedFieldChain(introspection);

        foreach (var depth in depths)
        {
            ct.ThrowIfCancellationRequested();

            string query;
            if (fieldChain != null)
            {
                query = BuildDepthQuery(fieldChain, depth);
            }
            else
            {
                // Without schema knowledge, use __type introspection which has natural depth
                query = BuildIntrospectionDepthQuery(depth);
            }

            var (json, responseHeaders) = await PostGraphql(url, headers, query, ct: ct);
            ExtractRateLimit(responseHeaders, result);

            if (json != null && json.Value.TryGetProperty("data", out var data) &&
                data.ValueKind == JsonValueKind.Object)
            {
                var hasErrors = json.Value.TryGetProperty("errors", out var errs) &&
                                errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0;

                if (!hasErrors)
                {
                    maxSuccessfulDepth = depth;
                }
                else
                {
                    failedAtDepth ??= depth;
                    break;
                }
            }
            else if (json != null && json.Value.TryGetProperty("errors", out _))
            {
                failedAtDepth ??= depth;
                break;
            }
            else
            {
                failedAtDepth ??= depth;
                break;
            }
        }

        if (maxSuccessfulDepth >= 10)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "depth-limit",
                Severity = "high",
                Title = "No effective query depth limit detected",
                Description = $"Queries at depth {maxSuccessfulDepth} succeed without restriction. " +
                              "Deep queries can cause exponential resolver execution and server-side DoS.",
                Details = new { maxSuccessfulDepth, failedAtDepth }
            });
        }
        else if (failedAtDepth != null)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "depth-limit",
                Severity = "info",
                Title = $"Query depth limit detected at depth ~{failedAtDepth}",
                Description = $"Queries succeeded at depth {maxSuccessfulDepth} but failed at depth {failedAtDepth}. " +
                              "A depth limit appears to be configured.",
                Details = new { maxSuccessfulDepth, failedAtDepth }
            });
        }
        else if (maxSuccessfulDepth > 0)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "depth-limit",
                Severity = "medium",
                Title = $"Queries succeed up to depth {maxSuccessfulDepth}",
                Description = $"Tested up to depth {maxSuccessfulDepth} successfully. " +
                              "Could not determine exact depth ceiling.",
                Details = new { maxSuccessfulDepth }
            });
        }
    }

    private static (string? field, string? typeName) FindNestedFieldChain(JsonElement? introspection)
    {
        if (introspection == null) return (null, null);
        try
        {
            if (!introspection.Value.TryGetProperty("data", out var data)) return (null, null);
            if (!data.TryGetProperty("__schema", out var schema)) return (null, null);
            if (!schema.TryGetProperty("types", out var types)) return (null, null);

            foreach (var t in types.EnumerateArray())
            {
                if (t.GetProperty("kind").GetString() != "OBJECT") continue;
                var tName = t.GetProperty("name").GetString();
                if (tName == null || tName.StartsWith("__")) continue;
                if (!t.TryGetProperty("fields", out var fields)) continue;

                foreach (var f in fields.EnumerateArray())
                {
                    var returnType = ResolveTypeName(f.GetProperty("type"));
                    if (returnType == tName)
                        return (f.GetProperty("name").GetString(), tName);
                }
            }
        }
        catch { /* best effort */ }
        return (null, null);
    }

    private static string? ResolveTypeName(JsonElement typeEl)
    {
        if (typeEl.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String)
            return name.GetString();
        if (typeEl.TryGetProperty("ofType", out var ofType) && ofType.ValueKind == JsonValueKind.Object)
            return ResolveTypeName(ofType);
        return null;
    }

    private static string BuildDepthQuery(string field, int depth)
    {
        var sb = new StringBuilder("{ ");
        for (var i = 0; i < depth; i++)
            sb.Append($"{field} {{ ");
        sb.Append("__typename ");
        for (var i = 0; i < depth; i++)
            sb.Append("} ");
        sb.Append('}');
        return sb.ToString();
    }

    private static string BuildIntrospectionDepthQuery(int depth)
    {
        // Use __type(name: "Query") with nested ofType chains
        var sb = new StringBuilder("{ __schema { types { ");
        var levels = Math.Min(depth, 15);
        for (var i = 0; i < levels; i++)
            sb.Append("fields { type { ofType { ");
        sb.Append("name ");
        for (var i = 0; i < levels; i++)
            sb.Append("} } } ");
        sb.Append("} } }");
        return sb.ToString();
    }

    #endregion

    #region 6. Max Limit Test

    private static async Task TestMaxLimit(
        string url, Dictionary<string, string> headers, JsonElement? introspection,
        GraphqlResult result, CancellationToken ct)
    {
        // Try to find a collection field from the schema
        var collectionField = FindCollectionField(introspection);
        if (collectionField == null)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "max-limit",
                Severity = "info",
                Title = "Max limit test skipped",
                Description = "Could not identify a collection/list field to test pagination limits. " +
                              "Requires introspection to find testable fields."
            });
            return;
        }

        var limits = new[] { 100, 1000, 10000 };
        int? maxWorked = null;
        int? maxReturnedCount = null;

        foreach (var limit in limits)
        {
            ct.ThrowIfCancellationRequested();

            var query = $"{{ {collectionField.Name}(limit: {limit}) {{ __typename }} }}";
            // Also try `first` parameter which is common in Relay-style APIs
            var altQuery = $"{{ {collectionField.Name}(first: {limit}) {{ __typename }} }}";

            var (json, responseHeaders) = await PostGraphql(url, headers, query, ct: ct);
            ExtractRateLimit(responseHeaders, result);

            if (json == null || !json.Value.TryGetProperty("data", out var data))
            {
                // Try with `first` instead
                (json, responseHeaders) = await PostGraphql(url, headers, altQuery, ct: ct);
                ExtractRateLimit(responseHeaders, result);
            }

            if (json != null && json.Value.TryGetProperty("data", out data) &&
                data.ValueKind == JsonValueKind.Object)
            {
                // Count items in the first field that is an array
                foreach (var prop in data.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.Array)
                    {
                        var count = prop.Value.GetArrayLength();
                        if (count > 0)
                        {
                            maxWorked = limit;
                            maxReturnedCount = count;
                        }
                        break;
                    }
                    if (prop.Value.ValueKind == JsonValueKind.Object &&
                        prop.Value.TryGetProperty("items", out var items) &&
                        items.ValueKind == JsonValueKind.Array)
                    {
                        var count = items.GetArrayLength();
                        if (count > 0)
                        {
                            maxWorked = limit;
                            maxReturnedCount = count;
                        }
                        break;
                    }
                }
            }
        }

        if (maxWorked >= 10000)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "max-limit",
                Severity = "high",
                Title = "Very high collection limits accepted",
                Description = $"The API accepts limit={maxWorked} and returned {maxReturnedCount} items. " +
                              "Large unbounded queries can cause excessive memory usage and slow responses.",
                Details = new { maxLimitTested = maxWorked, itemsReturned = maxReturnedCount }
            });
        }
        else if (maxWorked >= 1000)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "max-limit",
                Severity = "medium",
                Title = $"High collection limit accepted (limit={maxWorked})",
                Description = $"The API accepted limit={maxWorked} returning {maxReturnedCount} items. " +
                              "Consider enforcing a lower maximum.",
                Details = new { maxLimitTested = maxWorked, itemsReturned = maxReturnedCount }
            });
        }
        else if (maxWorked > 0)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "max-limit",
                Severity = "info",
                Title = $"Collection limit capped",
                Description = $"The API capped results at {maxReturnedCount} items when requesting {maxWorked}. " +
                              "A server-side limit appears to be in effect.",
                Details = new { maxLimitTested = maxWorked, itemsReturned = maxReturnedCount }
            });
        }
    }

    private sealed class CollectionFieldInfo
    {
        public string Name { get; set; } = "";
        public string ReturnType { get; set; } = "";
    }

    private static CollectionFieldInfo? FindCollectionField(JsonElement? introspection)
    {
        if (introspection == null) return null;
        try
        {
            if (!introspection.Value.TryGetProperty("data", out var data)) return null;
            if (!data.TryGetProperty("__schema", out var schema)) return null;
            if (!schema.TryGetProperty("queryType", out var qt)) return null;
            var queryTypeName = qt.GetProperty("name").GetString();
            if (!schema.TryGetProperty("types", out var types)) return null;

            foreach (var t in types.EnumerateArray())
            {
                if (t.GetProperty("name").GetString() != queryTypeName) continue;
                if (!t.TryGetProperty("fields", out var fields)) return null;

                foreach (var f in fields.EnumerateArray())
                {
                    var typeEl = f.GetProperty("type");
                    if (IsListType(typeEl))
                    {
                        var fieldName = f.GetProperty("name").GetString();
                        if (fieldName != null)
                            return new CollectionFieldInfo
                            {
                                Name = fieldName,
                                ReturnType = ResolveTypeName(typeEl) ?? "unknown"
                            };
                    }
                }
            }
        }
        catch { /* best effort */ }
        return null;
    }

    private static bool IsListType(JsonElement typeEl)
    {
        if (typeEl.TryGetProperty("kind", out var kind) && kind.GetString() == "LIST") return true;
        if (typeEl.TryGetProperty("ofType", out var ofType) && ofType.ValueKind == JsonValueKind.Object)
            return IsListType(ofType);
        return false;
    }

    #endregion

    #region 7. Draft/Preview Access

    private static async Task TestDraftAccess(
        string url, Dictionary<string, string> headers, JsonElement? introspection,
        GraphqlResult result, CancellationToken ct)
    {
        // Test Contentful-style preview parameter
        var queryField = FindFirstQueryField(introspection) ?? "__typename";
        var previewQuery = $"{{ {queryField}(preview: true) }}";

        var (json, responseHeaders) = await PostGraphql(url, headers, previewQuery, ct: ct);
        ExtractRateLimit(responseHeaders, result);

        if (json != null && json.Value.TryGetProperty("data", out var data) &&
            data.ValueKind == JsonValueKind.Object)
        {
            var hasErrors = json.Value.TryGetProperty("errors", out var errs) &&
                            errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0;

            if (!hasErrors)
            {
                result.Findings.Add(new GraphqlFinding
                {
                    Category = "draft-access",
                    Severity = "medium",
                    Title = "Draft/preview content accessible",
                    Description = "Queries with preview: true returned data successfully. " +
                                  "Unpublished/draft content may be exposed through this parameter.",
                    Details = new { parameter = "preview: true" }
                });
                return;
            }
        }

        // Also check for a draft=true style parameter
        var draftUrl = url + (url.Contains('?') ? "&" : "?") + "preview=true";
        var (json2, responseHeaders2) = await PostGraphql(draftUrl, headers, $"{{ {queryField} }}", ct: ct);
        ExtractRateLimit(responseHeaders2, result);

        if (json2 != null && json2.Value.TryGetProperty("data", out var data2) &&
            data2.ValueKind == JsonValueKind.Object)
        {
            var hasErrors = json2.Value.TryGetProperty("errors", out var errs2) &&
                            errs2.ValueKind == JsonValueKind.Array && errs2.GetArrayLength() > 0;
            if (!hasErrors)
            {
                result.Findings.Add(new GraphqlFinding
                {
                    Category = "draft-access",
                    Severity = "low",
                    Title = "Preview URL parameter accepted",
                    Description = "The endpoint accepted a ?preview=true query parameter. " +
                                  "This may or may not expose draft content depending on authorization.",
                    Details = new { parameter = "?preview=true" }
                });
                return;
            }
        }

        result.Findings.Add(new GraphqlFinding
        {
            Category = "draft-access",
            Severity = "info",
            Title = "No draft/preview access detected",
            Description = "Neither preview: true in query nor ?preview=true URL parameter yielded draft content."
        });
    }

    #endregion

    #region 8. Field Suggestion Exploitation

    private static async Task TestFieldSuggestion(
        string url, Dictionary<string, string> headers, GraphqlResult result, CancellationToken ct)
    {
        var query = "{ __typename xyzNonExistentField12345 }";

        var (json, responseHeaders) = await PostGraphql(url, headers, query, ct: ct);
        ExtractRateLimit(responseHeaders, result);

        if (json == null) return;

        if (json.Value.TryGetProperty("errors", out var errors) &&
            errors.ValueKind == JsonValueKind.Array)
        {
            var suggestions = new List<string>();
            foreach (var err in errors.EnumerateArray())
            {
                var msg = err.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
                // Common patterns: "Did you mean X?" or "Cannot query field ... Did you mean ..."
                if (msg.Contains("Did you mean", StringComparison.OrdinalIgnoreCase) ||
                    msg.Contains("did you mean", StringComparison.OrdinalIgnoreCase))
                {
                    suggestions.Add(msg);
                }
            }

            if (suggestions.Count > 0)
            {
                result.Findings.Add(new GraphqlFinding
                {
                    Category = "field-suggestion",
                    Severity = "low",
                    Title = "Field suggestions in error messages (information disclosure)",
                    Description = "The server suggests valid field names in error responses for invalid queries. " +
                                  "An attacker can enumerate the schema even when introspection is disabled.",
                    Details = new { suggestionsFound = suggestions.Count, examples = suggestions.Take(3).ToList() }
                });
            }
            else
            {
                result.Findings.Add(new GraphqlFinding
                {
                    Category = "field-suggestion",
                    Severity = "info",
                    Title = "No field suggestions in error messages",
                    Description = "Error messages for invalid fields do not suggest valid field names."
                });
            }
        }
    }

    #endregion

    #region 9. Rate Limit Extraction

    private static void ExtractRateLimit(HttpResponseHeaders? headers, GraphqlResult result)
    {
        if (headers == null || result.Schema.RateLimit != null) return;

        string? rateLimit = null;
        string? remaining = null;
        string? reset = null;

        foreach (var h in headers)
        {
            var key = h.Key.ToLowerInvariant();
            var value = h.Value.FirstOrDefault() ?? "";

            if (key.Contains("ratelimit-limit") || key == "x-ratelimit-limit" || key == "ratelimit")
                rateLimit = value;
            else if (key.Contains("ratelimit-remaining") || key == "x-ratelimit-remaining")
                remaining = value;
            else if (key.Contains("ratelimit-reset") || key == "x-ratelimit-reset")
                reset = value;
            else if (key == "retry-after")
                reset ??= value;
        }

        if (rateLimit != null)
        {
            var desc = rateLimit;
            if (remaining != null) desc += $" (remaining: {remaining})";
            if (reset != null) desc += $" (resets: {reset})";
            result.Schema.RateLimit = desc;

            result.Findings.Add(new GraphqlFinding
            {
                Category = "rate-limit",
                Severity = "info",
                Title = "Rate limit headers present",
                Description = $"Rate limit: {desc}",
                Details = new { limit = rateLimit, remaining, reset }
            });
        }
    }

    #endregion

    #region HTTP Helpers

    private static async Task<(JsonElement? json, HttpResponseHeaders? headers)> PostGraphql(
        string url, Dictionary<string, string> headers, string query,
        object? variables = null, CancellationToken ct = default)
    {
        var payload = new Dictionary<string, object> { ["query"] = query };
        if (variables != null) payload["variables"] = variables;

        var json = JsonSerializer.Serialize(payload);

        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        req.Content = new StringContent(json, Encoding.UTF8, "application/json");
        ApplyHeaders(req, headers);

        try
        {
            using var resp = await Http.SendAsync(req, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);

            if (string.IsNullOrWhiteSpace(body))
                return (null, resp.Headers);

            using var doc = JsonDocument.Parse(body);
            // Clone so we can dispose the document
            return (doc.RootElement.Clone(), resp.Headers);
        }
        catch (HttpRequestException)
        {
            return (null, null);
        }
        catch (TaskCanceledException)
        {
            return (null, null);
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }

    private static void ApplyHeaders(HttpRequestMessage req, Dictionary<string, string> headers)
    {
        foreach (var (key, value) in headers)
        {
            if (key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                continue; // already set
            if (key.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                req.Headers.TryAddWithoutValidation("Authorization", value);
            else
                req.Headers.TryAddWithoutValidation(key, value);
        }
    }

    private static string? TryAutoDetectEndpoint(AutomationContext ctx)
    {
        var entries = ctx.Network?.Entries;
        if (entries == null || entries.Count == 0) return null;

        // Prefer most-recent POST to a URL containing "graphql"
        for (var i = entries.Count - 1; i >= 0; i--)
        {
            var entry = entries[i];
            if (string.IsNullOrEmpty(entry.Url)) continue;

            if (entry.Url.Contains("graphql", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(entry.Method, "POST", StringComparison.OrdinalIgnoreCase))
                return entry.Url.Split('?')[0];
        }

        // Fall back: POST requests with content-type containing "graphql"
        for (var i = entries.Count - 1; i >= 0; i--)
        {
            var entry = entries[i];
            if (!string.Equals(entry.Method, "POST", StringComparison.OrdinalIgnoreCase)) continue;
            if (entry.RequestHeaders.TryGetValue("content-type", out var ct) &&
                ct.Contains("graphql", StringComparison.OrdinalIgnoreCase))
                return entry.Url?.Split('?')[0];
        }

        return null;
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1_048_576 => $"{bytes / 1_048_576.0:F1} MB",
        >= 1_024 => $"{bytes / 1_024.0:F1} KB",
        _ => $"{bytes} B"
    };

    #endregion

    #region 10. Cost Analysis

    private static async Task RunCostAnalysisAsync(
        string url, Dictionary<string, string> headers, JsonElement introspection,
        GraphqlResult result, CancellationToken ct)
    {
        var costResult = new CostAnalysisResult();
        result.CostAnalysis = costResult;

        var recursiveFields = FindRecursiveFields(introspection);
        if (recursiveFields.Count == 0)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "cost-analysis",
                Severity = "info",
                Title = "Cost analysis skipped — no recursive types found",
                Description = "The schema has no self-referencing fields to build worst-case nested queries."
            });
            return;
        }

        var worstCaseQueries = BuildWorstCaseQueries(recursiveFields, introspection);
        costResult.QueriesBuilt = worstCaseQueries.Count;

        var depths = new[] { 3, 5, 8 };

        foreach (var (queryTemplate, label) in worstCaseQueries)
        {
            var timings = new List<(int depth, int ms, string status)>();

            foreach (var depth in depths)
            {
                ct.ThrowIfCancellationRequested();

                var query = ExpandQueryToDepth(queryTemplate, depth);
                costResult.QueriesSent++;

                var sw = Stopwatch.StartNew();
                var (json, responseHeaders) = await PostGraphql(url, headers, query, ct: ct);
                var elapsed = (int)sw.ElapsedMilliseconds;

                ExtractRateLimit(responseHeaders, result);

                string status;
                if (json == null)
                {
                    status = "no-response";
                }
                else if (json.Value.TryGetProperty("errors", out var errs) &&
                         errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0)
                {
                    var hasData = json.Value.TryGetProperty("data", out var d) &&
                                  d.ValueKind == JsonValueKind.Object;
                    status = hasData ? "partial-error" : "rejected";
                }
                else if (json.Value.TryGetProperty("data", out _))
                {
                    status = "success";
                }
                else
                {
                    status = "unknown";
                }

                timings.Add((depth, elapsed, status));

                if (elapsed > costResult.MaxResponseTimeMs)
                    costResult.MaxResponseTimeMs = elapsed;

                if (status == "success" || status == "partial-error")
                {
                    if (depth > costResult.MaxDepthAccepted)
                        costResult.MaxDepthAccepted = depth;
                }

                var truncatedQuery = query.Length > 120 ? query[..120] + "..." : query;
                costResult.Findings.Add(new CostFinding
                {
                    Query = truncatedQuery,
                    Depth = depth,
                    ResponseTimeMs = elapsed,
                    Status = status,
                    Description = $"{label} at depth {depth}: {status} in {elapsed}ms"
                });

                if (status == "rejected" || status == "no-response")
                    break;
            }

            AnalyzeCostTimings(timings, label, result);
        }

        if (costResult.MaxDepthAccepted >= 8)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "cost-analysis",
                Severity = "high",
                Title = "No query cost/complexity limit enforced",
                Description = $"Recursive nested queries succeeded at depth {costResult.MaxDepthAccepted} " +
                              $"(max response: {costResult.MaxResponseTimeMs}ms). " +
                              "An attacker can craft exponentially expensive queries to exhaust server resources.",
                Details = new
                {
                    costResult.QueriesBuilt,
                    costResult.QueriesSent,
                    costResult.MaxDepthAccepted,
                    costResult.MaxResponseTimeMs
                }
            });
        }
        else if (costResult.MaxDepthAccepted >= 5)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "cost-analysis",
                Severity = "medium",
                Title = "Moderate query depth accepted without cost limit",
                Description = $"Recursive queries accepted at depth {costResult.MaxDepthAccepted}. " +
                              "A cost/complexity analyzer may be partially configured.",
                Details = new
                {
                    costResult.QueriesBuilt,
                    costResult.QueriesSent,
                    costResult.MaxDepthAccepted,
                    costResult.MaxResponseTimeMs
                }
            });
        }
        else if (costResult.MaxDepthAccepted > 0)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "cost-analysis",
                Severity = "info",
                Title = "Query cost/complexity limits appear active",
                Description = $"Recursive queries were limited at depth >{costResult.MaxDepthAccepted}. " +
                              "The server enforces query complexity restrictions.",
                Details = new
                {
                    costResult.QueriesBuilt,
                    costResult.QueriesSent,
                    costResult.MaxDepthAccepted,
                    costResult.MaxResponseTimeMs
                }
            });
        }
    }

    private static void AnalyzeCostTimings(
        List<(int depth, int ms, string status)> timings, string label, GraphqlResult result)
    {
        var successTimings = timings.Where(t => t.status == "success" || t.status == "partial-error").ToList();
        if (successTimings.Count < 2) return;

        var first = successTimings[0];
        var last = successTimings[^1];

        if (first.ms > 0 && last.ms > first.ms * 4 && last.ms > 1000)
        {
            result.Findings.Add(new GraphqlFinding
            {
                Category = "cost-analysis",
                Severity = "high",
                Title = $"Exponential response time growth: {label}",
                Description = $"Response time grew from {first.ms}ms (depth {first.depth}) to {last.ms}ms " +
                              $"(depth {last.depth}) — a {last.ms / Math.Max(first.ms, 1)}x increase. " +
                              "This indicates no query cost limit is preventing expensive nested resolution.",
                Details = new { timings = successTimings.Select(t => new { t.depth, t.ms }).ToList() }
            });
        }
    }

    private sealed class RecursiveFieldInfo
    {
        public string TypeName { get; set; } = "";
        public string FieldName { get; set; } = "";
        public string? QueryRootField { get; set; }
    }

    private static List<RecursiveFieldInfo> FindRecursiveFields(JsonElement introspection)
    {
        var results = new List<RecursiveFieldInfo>();

        if (!introspection.TryGetProperty("data", out var data)) return results;
        if (!data.TryGetProperty("__schema", out var schema)) return results;
        if (!schema.TryGetProperty("types", out var types)) return results;

        var queryTypeName = schema.TryGetProperty("queryType", out var qt) && qt.ValueKind == JsonValueKind.Object
            ? qt.GetProperty("name").GetString()
            : null;

        var queryRootFields = new Dictionary<string, string>();
        if (queryTypeName != null)
        {
            foreach (var t in types.EnumerateArray())
            {
                if (t.GetProperty("name").GetString() != queryTypeName) continue;
                if (!t.TryGetProperty("fields", out var qFields)) break;
                foreach (var f in qFields.EnumerateArray())
                {
                    var returnType = ResolveTypeName(f.GetProperty("type"));
                    var fieldName = f.GetProperty("name").GetString();
                    if (returnType != null && fieldName != null)
                        queryRootFields[returnType] = fieldName;
                }
                break;
            }
        }

        foreach (var t in types.EnumerateArray())
        {
            if (t.GetProperty("kind").GetString() != "OBJECT") continue;
            var tName = t.GetProperty("name").GetString();
            if (tName == null || tName.StartsWith("__")) continue;
            if (!t.TryGetProperty("fields", out var fields)) continue;

            foreach (var f in fields.EnumerateArray())
            {
                var returnType = ResolveTypeName(f.GetProperty("type"));
                if (returnType != tName) continue;

                var fieldName = f.GetProperty("name").GetString();
                if (fieldName == null) continue;

                results.Add(new RecursiveFieldInfo
                {
                    TypeName = tName,
                    FieldName = fieldName,
                    QueryRootField = queryRootFields.GetValueOrDefault(tName)
                });
            }
        }

        return results;
    }

    private static List<(string template, string label)> BuildWorstCaseQueries(
        List<RecursiveFieldInfo> recursiveFields, JsonElement introspection)
    {
        var queries = new List<(string template, string label)>();
        var seen = new HashSet<string>();

        foreach (var rf in recursiveFields)
        {
            if (!seen.Add($"{rf.TypeName}.{rf.FieldName}")) continue;
            if (queries.Count >= 3) break;

            var rootField = rf.QueryRootField ?? rf.FieldName;
            var template = $"{rootField}/{rf.FieldName}";
            queries.Add((template, $"{rf.TypeName}.{rf.FieldName}"));
        }

        return queries;
    }

    private static string ExpandQueryToDepth(string template, int depth)
    {
        var parts = template.Split('/');
        var rootField = parts[0];
        var nestedField = parts.Length > 1 ? parts[1] : rootField;

        var sb = new StringBuilder();
        sb.Append($"{{ {rootField} {{ ");
        for (var i = 0; i < depth; i++)
            sb.Append($"{nestedField} {{ ");
        sb.Append("__typename ");
        for (var i = 0; i < depth; i++)
            sb.Append("} ");
        sb.Append("} }");
        return sb.ToString();
    }

    #endregion

    #region Formatting

    public static string Format(GraphqlResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== GraphQL Security Analysis ===");
        sb.AppendLine($"URL: {result.Url}");
        sb.AppendLine($"Elapsed: {result.ElapsedMs}ms");
        sb.AppendLine();

        if (result.Findings.Count > 0)
        {
            var bySeverity = result.Findings.GroupBy(f => f.Severity)
                .ToDictionary(g => g.Key, g => g.Count());
            sb.AppendLine($"FINDINGS: {result.Findings.Count}");
            var parts = new List<string>();
            foreach (var s in new[] { "critical", "high", "medium", "low", "info" })
                if (bySeverity.TryGetValue(s, out var c))
                    parts.Add($"{s}: {c}");
            sb.AppendLine($"  {string.Join(", ", parts)}");
            sb.AppendLine();

            foreach (var f in result.Findings.OrderByDescending(f => SeverityRank(f.Severity)))
            {
                sb.AppendLine($"[{f.Severity.ToUpper()}] [{f.Category}] {f.Title}");
                sb.AppendLine($"  {f.Description}");
                sb.AppendLine();
            }
        }
        else
        {
            sb.AppendLine("No findings.");
        }

        sb.AppendLine("SCHEMA SUMMARY:");
        sb.AppendLine($"  Total types: {result.Schema.TotalTypes}");
        sb.AppendLine($"  Query fields: {result.Schema.QueryTypes}");
        sb.AppendLine($"  Has mutations: {result.Schema.HasMutations}");
        sb.AppendLine($"  Has subscriptions: {result.Schema.HasSubscriptions}");
        if (result.Schema.MutationTypes > 0)
            sb.AppendLine($"  Mutation fields: {result.Schema.MutationTypes}");
        if (result.Schema.SubscriptionTypes > 0)
            sb.AppendLine($"  Subscription fields: {result.Schema.SubscriptionTypes}");
        if (result.Schema.SensitiveTypes.Count > 0)
            sb.AppendLine($"  Sensitive types: {string.Join(", ", result.Schema.SensitiveTypes)}");
        if (result.Schema.RateLimit != null)
            sb.AppendLine($"  Rate limit: {result.Schema.RateLimit}");

        if (result.Errors.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("ERRORS:");
            foreach (var err in result.Errors)
                sb.AppendLine($"  ! {err}");
        }

        return sb.ToString().TrimEnd();
    }

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };

    #endregion
}
