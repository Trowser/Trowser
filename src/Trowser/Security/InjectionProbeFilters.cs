namespace Trowser.Security;

/// <summary>Shared exclusions and tech-stack gates for injection scanners.</summary>
public static class InjectionProbeFilters
{
    private static readonly string[] TransportPathFragments =
    [
        "/socket.io/", "/sockjs/", "/sockjs-node/", "/webpack-hmr", "/__webpack", "/hot-update"
    ];

    private static readonly HashSet<string> TransportQueryParams = new(StringComparer.OrdinalIgnoreCase)
    {
        "EIO", "transport", "sid", "t", "polling", "b64"
    };

    private static readonly string[] MongoEvidencePatterns =
    [
        "MongoError", "MongoServerError", "BSON", "unknown operator", "$where",
        "cannot use $", "bad query", "Cast to ObjectId",
        "cannot be applied to a field", "expression is invalid", "has to be a string",
        "must be a boolean", "use $a with", "use &a with", "JSInterpreterFailure", "BadValue"
    ];

    private static readonly string[] RedisEvidencePatterns =
    [
        "ERR wrong number of arguments", "ERR unknown command", "WRONGTYPE",
        "NOPERM", "NOAUTH", "MOVED ", "ASK ", "CROSSSLOT", "EXECABORT",
        "LOADING Redis is loading", "BUSY Redis is busy", "OOM command not allowed"
    ];

    private static readonly string[] CouchEvidencePatterns =
    [
        "invalid UTF-8 JSON", "bad_request", "not_found", "doc_id", "_rev"
    ];

    public static bool ShouldExcludeTransportEndpoint(string? url, string? paramName = null, bool enabled = true)
    {
        if (!enabled || string.IsNullOrEmpty(url)) return false;
        var lower = url.ToLowerInvariant();
        if (TransportPathFragments.Any(f => lower.Contains(f, StringComparison.Ordinal)))
            return true;

        if (!lower.Contains("socket.io", StringComparison.Ordinal)) return false;
        return string.IsNullOrEmpty(paramName)
               || TransportQueryParams.Contains(paramName);
    }

    public static bool LooksRelationalBackend(TechStackResult? stack)
    {
        if (stack == null || stack.Detections.Count == 0) return false;
        if (stack.Detections.Any(d => IsMongoLike(d.Name))) return false;

        return stack.Detections.Any(d =>
            IsRelationalLike(d.Name)
            || (d.Evidence?.Contains("sqlite", StringComparison.OrdinalIgnoreCase) ?? false)
            || (d.Evidence?.Contains("sequelize", StringComparison.OrdinalIgnoreCase) ?? false));
    }

    public static bool PayloadLooksLikeNosqlOperator(string? payload)
    {
        if (string.IsNullOrEmpty(payload)) return false;
        return payload.Contains('$', StringComparison.Ordinal)
               || payload.Contains("[$", StringComparison.Ordinal)
               || payload.Contains("$where", StringComparison.OrdinalIgnoreCase)
               || payload.Contains("$ne", StringComparison.OrdinalIgnoreCase);
    }

    public static bool ResponseHasMongoEvidence(string? text) =>
        !string.IsNullOrEmpty(text)
        && MongoEvidencePatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));

    public static bool ResponseHasRedisEvidence(string? text) =>
        !string.IsNullOrEmpty(text)
        && RedisEvidencePatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));

    public static bool ResponseHasNosqlErrorEvidence(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        // Relational SQL oracles must not be classified as NoSQL (sqlite3/mysql/postgres…).
        if (ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(text).Count > 0)
            return false;
        return ResponseHasMongoEvidence(text)
               || ResponseHasRedisEvidence(text)
               || CouchEvidencePatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    public static bool NosqlSizeHeuristicAllowed(string? payload, TechStackResult? stack)
    {
        if (LooksRelationalBackend(stack))
            return false;

        if (PayloadLooksLikeNosqlOperator(payload))
            return true;

        // Literal true/false/null on search endpoints — not NoSQL operator injection
        if (payload is "true" or "false" or "null")
            return false;

        return true;
    }

    /// <summary>True when the response looks like a relational SQL engine error, not NoSQL.</summary>
    public static bool ResponseHasRelationalSqlErrorEvidence(string? text) =>
        !string.IsNullOrEmpty(text)
        && ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(text).Count > 0;

    private static bool IsMongoLike(string name) =>
        name.Contains("mongo", StringComparison.OrdinalIgnoreCase);

    private static bool IsRelationalLike(string name)
    {
        var n = name.ToLowerInvariant();
        return n.Contains("sqlite") || n.Contains("mysql") || n.Contains("mariadb")
               || n.Contains("postgres") || n.Contains("postgresql") || n.Contains("sql server")
               || n.Contains("mssql") || n.Contains("sequelize") || n.Contains("typeorm")
               || n.Contains("prisma") || n.Contains("knex");
    }
}
