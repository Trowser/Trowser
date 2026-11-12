namespace Trowser.Security;

/// <summary>Semantic category for an injectable parameter — drives scanner routing.</summary>
public enum InjectionParamKind
{
    Generic,
    UrlLike,
    Auth,
    Template,
    Cmd,
    Search,
    NumericId
}

/// <summary>Maps parameter semantics to which injection scanners should run.</summary>
public static class InjectionParamClassifier
{
    private static readonly HashSet<string> CmdParamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "command", "exec", "execute", "shell", "run", "ping", "host", "ip",
        "address", "target", "dest", "destination",
        "file", "path", "dir", "folder", "process", "program", "script", "bin", "binary", "arg", "args",
        // Common compound forms (smart-routing previously missed these exact names)
        "ipaddress", "ip_address", "ip-address", "ipaddr", "hostip", "hostname", "host_name",
        "filename", "file_name", "filepath", "file_path", "dirname", "dir_name", "directory"
    };

    /// <summary>Compound / normalized stems that indicate command / path / host injection sinks.</summary>
    private static readonly string[] CmdParamNormalizedStems =
    [
        "ipaddress", "hostname", "hostip", "filename", "filepath", "dirname", "cmdline", "shellcmd"
    ];

    private static readonly HashSet<string> XssLikelyParamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "q", "query", "search", "term", "keyword", "s", "find", "lookup",
        "value", "name", "text", "html", "content", "message", "comment", "msg",
        "title", "input", "data", "src", "href", "callback", "label", "desc", "description"
    };

    private static readonly HashSet<string> TemplateParamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "template", "render", "preview", "comment", "message", "body", "content",
        "greet", "msg", "text", "html", "markdown", "layout", "view", "tpl"
    };

    private static readonly HashSet<string> AuthParamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "email", "username", "user", "password", "pass", "login", "pwd", "account", "uname"
    };

    private static readonly HashSet<string> SearchParamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "q", "query", "search", "term", "keyword", "s", "find", "lookup"
    };

    public static InjectionParamKind Classify(string paramName, string? endpointPath = null)
    {
        if (string.IsNullOrWhiteSpace(paramName))
            return InjectionParamKind.Generic;

        var name = paramName.Trim();
        if (UrlLikeParamNames.IsUrlLikeParamName(name))
            return InjectionParamKind.UrlLike;

        if (CmdParamNames.Contains(name) || IsCmdLikeCompoundName(name))
            return InjectionParamKind.Cmd;

        if (TemplateParamNames.Contains(name))
            return InjectionParamKind.Template;

        var path = (endpointPath ?? "").ToLowerInvariant();
        // Path-based template sinks (e.g. POST /api/render with raw body) even when the
        // parameter name is generic ("body", "data") or empty.
        if (LooksLikeTemplateEndpoint(path))
            return InjectionParamKind.Template;

        if (AuthParamNames.Contains(name) || LooksLikeAuthEndpoint(path))
            return InjectionParamKind.Auth;

        if (IsNumericIdParam(name))
            return InjectionParamKind.NumericId;

        if (SearchParamNames.Contains(name))
            return InjectionParamKind.Search;

        return InjectionParamKind.Generic;
    }

    /// <summary>True for render/template preview endpoints that commonly accept SSTI bodies.</summary>
    public static bool LooksLikeTemplateEndpoint(string? pathLower)
    {
        if (string.IsNullOrWhiteSpace(pathLower)) return false;
        var p = pathLower.ToLowerInvariant();
        return p.Contains("/render", StringComparison.Ordinal)
               || p.Contains("/template", StringComparison.Ordinal)
               || p.Contains("/preview", StringComparison.Ordinal)
               || p.Contains("/compile", StringComparison.Ordinal)
               || p.Contains("/evaluate", StringComparison.Ordinal)
               || p.Contains("/mustache", StringComparison.Ordinal)
               || p.Contains("/handlebars", StringComparison.Ordinal)
               || p.Contains("/jinja", StringComparison.Ordinal)
               || p.Contains("/twig", StringComparison.Ordinal);
    }

    public static bool IsLoginEndpoint(string? pathTemplate)
    {
        if (string.IsNullOrWhiteSpace(pathTemplate)) return false;
        return LooksLikeAuthEndpoint(pathTemplate.ToLowerInvariant());
    }

    private static bool LooksLikeAuthEndpoint(string pathLower) =>
        pathLower.Contains("login", StringComparison.Ordinal)
        || pathLower.Contains("/auth", StringComparison.Ordinal)
        || pathLower.Contains("signin", StringComparison.Ordinal)
        || pathLower.Contains("sign_in", StringComparison.Ordinal)
        || pathLower.Contains("/session", StringComparison.Ordinal);

    private static bool IsNumericIdParam(string name)
    {
        if (name.Equals("id", StringComparison.OrdinalIgnoreCase))
            return true;
        if (name.EndsWith("id", StringComparison.OrdinalIgnoreCase) && name.Length <= 12)
            return true;
        return false;
    }

    /// <summary>
    /// Match compound names like <c>ipAddress</c> / <c>file_name</c> without treating every
    /// parameter containing <c>path</c> or <c>host</c> as a command sink.
    /// </summary>
    private static bool IsCmdLikeCompoundName(string name)
    {
        var normalized = name.Replace("_", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal)
            .ToLowerInvariant();
        foreach (var stem in CmdParamNormalizedStems)
        {
            if (normalized == stem || normalized.EndsWith(stem, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    /// <summary>Higher score → prefer this parameter when selecting XSS probe budget.</summary>
    public static int XssLikelihoodScore(string? paramName)
    {
        if (string.IsNullOrWhiteSpace(paramName)) return 0;
        var name = paramName.Trim();
        if (XssLikelyParamNames.Contains(name)) return 3;
        var kind = Classify(name);
        return kind switch
        {
            InjectionParamKind.Search or InjectionParamKind.Template => 2,
            InjectionParamKind.UrlLike or InjectionParamKind.Generic or InjectionParamKind.Auth => 1,
            _ => 0
        };
    }

    /// <summary>Higher score → prefer this parameter when selecting SQLi probe budget.</summary>
    public static int SqliLikelihoodScore(string? paramName)
    {
        if (string.IsNullOrWhiteSpace(paramName)) return 0;
        var kind = Classify(paramName.Trim());
        return kind switch
        {
            InjectionParamKind.NumericId or InjectionParamKind.Search => 3,
            InjectionParamKind.Auth or InjectionParamKind.Generic => 2,
            InjectionParamKind.Template or InjectionParamKind.Cmd => 1,
            _ => 0
        };
    }

    /// <summary>Whether a scanner should probe this parameter (before SSTI escalation).</summary>
    public static bool AllowsScanner(InjectionParamKind kind, string scanner, bool isLoginEndpoint)
    {
        return kind switch
        {
            // URL-like params are SSRF/redirect targets, but also common reflected-XSS sinks (src, callback, …).
            InjectionParamKind.UrlLike => scanner is "xss",
            InjectionParamKind.Auth => scanner switch
            {
                "sqli" or "xss" or "nosql" => true,
                "ldap" => isLoginEndpoint,
                _ => false
            },
            InjectionParamKind.Template => scanner is "sqli" or "xss" or "ssti-polyglot" or "ssti",
            // Cmd/exec sinks produce shell differentials that false-positive as SQLi — prefer cmd-canary only.
            InjectionParamKind.Cmd => scanner is "cmd-canary",
            InjectionParamKind.Search => scanner is "sqli" or "xss" or "ssti-polyglot",
            InjectionParamKind.NumericId => scanner is "sqli" or "nosql",
            InjectionParamKind.Generic => scanner is "sqli" or "xss" or "ssti-polyglot",
            _ => true
        };
    }

    /// <summary>Full SSTI only on template params or after polyglot escalation.</summary>
    public static bool AllowsFullSsti(InjectionParamKind kind, bool polyglotEscalated) =>
        kind == InjectionParamKind.Template || polyglotEscalated;
}

/// <summary>Tracks SSTI polyglot hits for funnel escalation to full SSTI scanner.</summary>
public sealed class SstiEscalationTracker
{
    private readonly HashSet<string> _keys = new(StringComparer.OrdinalIgnoreCase);

    public void Record(string endpointKey, string paramName) =>
        _keys.Add($"{endpointKey}|{paramName}");

    public void RecordPolyglot(string url, string paramName)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            Record(uri.GetLeftPart(UriPartial.Path), paramName);
        else
            Record(url.Split('?', '#')[0], paramName);
    }

    public bool IsEscalated(string endpointKey, string paramName) =>
        _keys.Contains($"{endpointKey}|{paramName}");
}
