using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Static hints from inline and same-origin application scripts.
/// Used when a sink is in the source but did not run on this load (empty fragment, click gate, <c>auto=1</c>).
/// </summary>
public static class ClientScriptTextScanner
{
    public static readonly string[] RedirectParamNames =
    [
        "next", "nextUrl", "next_url", "url", "return", "returnUrl", "return_to", "to", "redirect",
        "redirectUrl", "redirect_url", "redirect_uri", "redirectTo", "redirect_to",
        "dest", "destination", "destinationUrl", "destination_url", "continue", "continueUrl", "continue_url",
        "target", "targetUrl", "target_url", "goto", "goTo", "go_to", "back"
    ];

    private static readonly HashSet<string> GadgetBuiltins = new(StringComparer.OrdinalIgnoreCase)
    {
        "location", "document", "navigator", "history", "screen", "performance", "console",
        "localStorage", "sessionStorage", "indexedDB", "crypto", "fetch", "self", "top",
        "parent", "frames", "length", "name", "status", "origin", "chrome", "webkit"
    };

    private static readonly (string Name, Regex Pattern)[] ExecSinkPatterns =
    [
        ("innerHTML", new(@"\binnerHTML\s*=", RegexOptions.Compiled)),
        ("outerHTML", new(@"\bouterHTML\s*=", RegexOptions.Compiled)),
        ("insertAdjacentHTML", new(@"\binsertAdjacentHTML\s*\(", RegexOptions.Compiled)),
        ("document.write", new(@"\bdocument\.write(?:ln)?\s*\(", RegexOptions.Compiled)),
        ("eval", new(@"(?<![\w.])eval\s*\(", RegexOptions.Compiled)),
        ("Function", new(@"(?<![\w.])Function\s*\(", RegexOptions.Compiled)),
        ("DOMParser.parseFromString", new(@"\bparseFromString\s*\(", RegexOptions.Compiled)),
        ("createContextualFragment", new(@"\bcreateContextualFragment\s*\(", RegexOptions.Compiled)),
        ("setHTMLUnsafe", new(@"\bsetHTMLUnsafe\s*\(", RegexOptions.Compiled))
    ];

    private static readonly (string Name, Regex Pattern)[] MarkupSinkPatterns =
    [
        ("innerHTML", new(@"\binnerHTML\s*=", RegexOptions.Compiled)),
        ("outerHTML", new(@"\bouterHTML\s*=", RegexOptions.Compiled)),
        ("insertAdjacentHTML", new(@"\binsertAdjacentHTML\s*\(", RegexOptions.Compiled)),
        ("document.write", new(@"\bdocument\.write(?:ln)?\s*\(", RegexOptions.Compiled)),
        ("createContextualFragment", new(@"\bcreateContextualFragment\s*\(", RegexOptions.Compiled))
    ];

    private static readonly (string Name, Regex Pattern)[] NavSinkPatterns =
    [
        ("location.assign", new(@"\blocation\.assign\s*\(", RegexOptions.Compiled)),
        ("location.replace", new(@"\blocation\.replace\s*\(", RegexOptions.Compiled)),
        ("location.href", new(@"\blocation(?:\.href)?\s*=", RegexOptions.Compiled)),
        ("window.open", new(@"\bwindow\.open\s*\(", RegexOptions.Compiled))
    ];

    private static readonly Regex FetchCall = new(@"\bfetch\s*\(", RegexOptions.Compiled);
    private static readonly Regex XhrOpen = new(@"\.open\s*\(\s*['""](?:GET|POST|PUT|PATCH|DELETE)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex MutatingMethod = new(
        @"method\s*:\s*['""](?:POST|PUT|PATCH|DELETE)['""]|\.open\s*\(\s*['""](?:POST|PUT|PATCH|DELETE)['""]",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex LocationSearch = new(@"\blocation\.search\b|\bURLSearchParams\s*\(", RegexOptions.Compiled);
    private static readonly Regex LocationHash = new(@"\blocation\.hash\b", RegexOptions.Compiled);
    private static readonly Regex PostMessageRead = new(@"\baddEventListener\s*\(\s*['""]message['""]", RegexOptions.Compiled);
    private static readonly Regex ParamGet = new(@"\.get\s*\(\s*['""]([A-Za-z_][\w-]{0,40})['""]", RegexOptions.Compiled);
    private static readonly Regex AutoFlag = new(@"\.get\s*\(\s*['""]auto['""]\s*\)|['""]auto['""]\s*\]", RegexOptions.Compiled);
    private static readonly Regex Mustache = new(@"\{\{[^{}]{1,80}\}\}", RegexOptions.Compiled);
    private static readonly Regex TemplateEval = new(@"(?<![\w.])eval\s*\(\s*`", RegexOptions.Compiled);
    private static readonly Regex NewFunction = new(@"\bnew\s+Function\s*\(", RegexOptions.Compiled);
    private static readonly Regex GadgetRead = new(
        @"\b(?:window|self|globalThis)\s*\.\s*([A-Za-z_$][\w$]{0,63})\s*\.\s*([A-Za-z_$][\w$]{0,63})",
        RegexOptions.Compiled);
    private static readonly Regex StyleSink = new(
        @"\.cssText\s*=|\binsertRule\s*\(|\.style\s*=|setAttribute\s*\(\s*['""]style['""]",
        RegexOptions.Compiled);
    private static readonly Regex ServiceWorkerRegister = new(@"\bserviceWorker\s*\.\s*register\s*\(", RegexOptions.Compiled);
    private static readonly Regex WebSocketCtor = new(@"\bnew\s+WebSocket\s*\(", RegexOptions.Compiled);
    private static readonly Regex WindowOpenCall = new(@"\bwindow\.open\s*\(", RegexOptions.Compiled);
    private static readonly Regex TrustedTypesPolicy = new(@"\btrustedTypes\s*\.\s*createPolicy\s*\(", RegexOptions.Compiled);
    private static readonly Regex AttackerSource = new(
        @"\blocation\.(?:search|hash|href)\b|\bdocument\.referrer\b|\bwindow\.name\b|\bpostMessage\b",
        RegexOptions.Compiled);

    public static ClientScriptTextFacts Scan(IEnumerable<string>? scripts)
    {
        var facts = new ClientScriptTextFacts();
        if (scripts == null) return facts;

        foreach (var raw in scripts)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var text = raw.Length > 48_000 ? raw[..48_000] : raw;
            Absorb(facts, text);
        }

        return facts;
    }

    public static bool IsRedirectParam(string name) =>
        RedirectParamNames.Contains(name, StringComparer.OrdinalIgnoreCase);

    private static void Absorb(ClientScriptTextFacts facts, string text)
    {
        AddMatches(facts.ExecSinks, text, ExecSinkPatterns);
        AddMatches(facts.MarkupSinks, text, MarkupSinkPatterns);
        AddMatches(facts.NavSinks, text, NavSinkPatterns);

        if (FetchCall.IsMatch(text) || XhrOpen.IsMatch(text))
            facts.HasFetch = true;
        if (MutatingMethod.IsMatch(text))
            facts.MutatingFetch = true;
        if (LocationSearch.IsMatch(text))
            facts.ReadsLocationSearch = true;
        if (LocationHash.IsMatch(text))
            facts.ReadsLocationHash = true;
        if (PostMessageRead.IsMatch(text))
            facts.ReadsPostMessage = true;
        if (facts.ReadsLocationSearch || facts.ReadsLocationHash)
        {
            foreach (Match m in ParamGet.Matches(text))
            {
                var name = m.Groups[1].Value;
                if (name.Length > 0 && !facts.LocationParams.Contains(name, StringComparer.OrdinalIgnoreCase))
                    facts.LocationParams.Add(name);
            }
        }

        if (AutoFlag.IsMatch(text))
            facts.ReadsAutoFlag = true;
        if (NewFunction.IsMatch(text) || Mustache.IsMatch(text) || TemplateEval.IsMatch(text)
            || facts.ExecSinks.Contains("Function"))
            facts.CustomTemplate = true;
        if (AttackerSource.IsMatch(text))
            facts.HasAttackerSource = true;
        if (StyleSink.IsMatch(text))
            facts.StyleSink = true;
        if (ServiceWorkerRegister.IsMatch(text))
            facts.RegistersServiceWorker = true;
        if (WebSocketCtor.IsMatch(text))
            facts.UsesWebSocket = true;
        if (TrustedTypesPolicy.IsMatch(text))
            facts.CreatesTrustedTypesPolicy = true;
        if (WindowOpenCall.IsMatch(text) && !text.Contains("noopener", StringComparison.OrdinalIgnoreCase))
            facts.WindowOpenWithoutNoopener = true;

        foreach (Match m in GadgetRead.Matches(text))
        {
            var name = m.Groups[1].Value;
            var prop = m.Groups[2].Value;
            if (GadgetBuiltins.Contains(name) || GadgetBuiltins.Contains(prop))
                continue;
            var label = name + "." + prop;
            if (!facts.GadgetReads.Contains(label, StringComparer.OrdinalIgnoreCase))
                facts.GadgetReads.Add(label);
        }
    }

    private static void AddMatches(List<string> into, string text, (string Name, Regex Pattern)[] patterns)
    {
        foreach (var (name, pattern) in patterns)
        {
            if (into.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            if (pattern.IsMatch(text))
                into.Add(name);
        }
    }
}

public sealed class ClientScriptTextFacts
{
    public List<string> ExecSinks { get; init; } = [];
    public List<string> MarkupSinks { get; init; } = [];
    public List<string> NavSinks { get; init; } = [];
    public bool HasFetch { get; set; }
    public bool MutatingFetch { get; set; }
    public bool ReadsLocationSearch { get; set; }
    public bool ReadsLocationHash { get; set; }
    public bool ReadsPostMessage { get; set; }
    public List<string> LocationParams { get; init; } = [];
    public bool ReadsAutoFlag { get; set; }
    public bool CustomTemplate { get; set; }
    public bool HasAttackerSource { get; set; }
    public List<string> GadgetReads { get; init; } = [];
    public bool StyleSink { get; set; }
    public bool RegistersServiceWorker { get; set; }
    public bool UsesWebSocket { get; set; }
    public bool CreatesTrustedTypesPolicy { get; set; }
    public bool WindowOpenWithoutNoopener { get; set; }

    public bool LocationDrivenRequest =>
        HasFetch && (ReadsLocationSearch || ReadsLocationHash || ReadsPostMessage);
}
