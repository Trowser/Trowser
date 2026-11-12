using Trowser.Security;

namespace Trowser.Laws;

public sealed class LawBuilder
{
    private readonly LawRegistry _registry;
    private readonly string _name;
    private readonly string? _siteFilter;
    private readonly string? _defaultPagePattern;
    private LawTriggerKind _trigger = LawTriggerKind.Page;
    private string? _pattern;
    private bool _hasAssertion;
    private LawCostClass _cost = LawCostClass.Page;
    private Severity _lawSeverity = global::Trowser.Security.Severity.Medium;
    private readonly HashSet<string> _tags = new(StringComparer.OrdinalIgnoreCase);
    private bool _confirm = true;
    private string? _sourceFile;

    private Func<PageFacts, bool>? _pageWhen;
    private Func<PageFacts, bool>? _pageExpect;
    private Func<PageFacts, bool>? _pageForbid;

    private Func<ResponseFacts, bool>? _responseWhen;
    private Func<ResponseFacts, bool>? _responseExpect;
    private Func<ResponseFacts, bool>? _responseForbid;

    private Func<ConsoleFacts, bool>? _consoleWhen;
    private Func<ConsoleFacts, bool>? _consoleExpect;
    private Func<ConsoleFacts, bool>? _consoleForbid;

    private bool _registered;

    internal LawBuilder(LawRegistry registry, string name, string? siteFilter, string? sourceFile = null, string? defaultPagePattern = null)
    {
        _registry = registry;
        _name = name;
        _siteFilter = siteFilter;
        _sourceFile = sourceFile;
        _defaultPagePattern = defaultPagePattern;
    }

    internal LawBuilder WithSourceFile(string path)
    {
        _sourceFile = path;
        return this;
    }

    public LawBuilder OnPage(string pathPattern)
    {
        EnsureTriggerMutable(nameof(OnPage));
        _trigger = LawTriggerKind.Page;
        _pattern = pathPattern;
        _cost = LawCostClass.Page;
        TouchRegister();
        return this;
    }

    public LawBuilder OnResponse(string methodAndPathPattern)
    {
        EnsureTriggerMutable(nameof(OnResponse));
        _trigger = LawTriggerKind.Response;
        _pattern = methodAndPathPattern;
        _cost = LawCostClass.Response;
        TouchRegister();
        return this;
    }

    public LawBuilder OnConsole(string? levelPattern = null)
    {
        EnsureTriggerMutable(nameof(OnConsole));
        _trigger = LawTriggerKind.Console;
        _pattern = levelPattern;
        _cost = LawCostClass.Console;
        TouchRegister();
        return this;
    }

    public LawBuilder OnTimer(string? interval = null)
    {
        EnsureTriggerMutable(nameof(OnTimer));
        _trigger = LawTriggerKind.Timer;
        _pattern = interval;
        _cost = LawCostClass.Heavy;
        TouchRegister();
        return this;
    }

    public LawBuilder OnAction(string? description = null)
    {
        EnsureTriggerMutable(nameof(OnAction));
        _trigger = LawTriggerKind.Action;
        _pattern = description;
        _cost = LawCostClass.Heavy;
        TouchRegister();
        return this;
    }

    public LawBuilder When(Func<PageFacts, bool> guard)
    {
        _pageWhen = guard;
        TouchRegister();
        return this;
    }

    public LawBuilder When(Func<ResponseFacts, bool> guard)
    {
        _responseWhen = guard;
        TouchRegister();
        return this;
    }

    public LawBuilder When(Func<ConsoleFacts, bool> guard)
    {
        _consoleWhen = guard;
        TouchRegister();
        return this;
    }

    public LawBuilder Expect(Func<PageFacts, bool> assertion) => FinishPage(assertion, forbid: null);

    public LawBuilder Forbid(Func<PageFacts, bool> forbiddenPredicate) => FinishPage(expect: null, forbid: forbiddenPredicate);

    public LawBuilder Expect(Func<ResponseFacts, bool> assertion) => FinishResponse(assertion, forbid: null);

    public LawBuilder Forbid(Func<ResponseFacts, bool> forbiddenPredicate) => FinishResponse(expect: null, forbid: forbiddenPredicate);

    public LawBuilder Expect(Func<ConsoleFacts, bool> assertion) => FinishConsole(assertion, forbid: null);

    public LawBuilder Forbid(Func<ConsoleFacts, bool> forbiddenPredicate) => FinishConsole(expect: null, forbid: forbiddenPredicate);

    public LawBuilder Severity(Severity severity)
    {
        _lawSeverity = severity;
        TouchRegister();
        return this;
    }

    public LawBuilder Tags(params string[] tags)
    {
        foreach (var t in tags)
            if (!string.IsNullOrWhiteSpace(t))
                _tags.Add(t.Trim());
        TouchRegister();
        return this;
    }

    public LawBuilder Cost(LawCostClass cost)
    {
        _cost = cost;
        TouchRegister();
        return this;
    }

    public LawBuilder Confirm(bool confirm = true)
    {
        _confirm = confirm;
        TouchRegister();
        return this;
    }

    private LawBuilder FinishPage(Func<PageFacts, bool>? expect, Func<PageFacts, bool>? forbid)
    {
        if (expect != null)
        {
            var prev = _pageExpect;
            _pageExpect = prev == null ? expect : pf => prev(pf) && expect(pf);
        }
        if (forbid != null)
        {
            var prev = _pageForbid;
            _pageForbid = prev == null ? forbid : pf => prev(pf) || forbid(pf);
        }
        _hasAssertion = true;
        Register();
        return this;
    }

    private LawBuilder FinishResponse(Func<ResponseFacts, bool>? expect, Func<ResponseFacts, bool>? forbid)
    {
        if (expect != null)
        {
            var prev = _responseExpect;
            _responseExpect = prev == null ? expect : rf => prev(rf) && expect(rf);
        }
        if (forbid != null)
        {
            var prev = _responseForbid;
            _responseForbid = prev == null ? forbid : rf => prev(rf) || forbid(rf);
        }
        _hasAssertion = true;
        Register();
        return this;
    }

    private LawBuilder FinishConsole(Func<ConsoleFacts, bool>? expect, Func<ConsoleFacts, bool>? forbid)
    {
        if (expect != null)
        {
            var prev = _consoleExpect;
            _consoleExpect = prev == null ? expect : cf => prev(cf) && expect(cf);
        }
        if (forbid != null)
        {
            var prev = _consoleForbid;
            _consoleForbid = prev == null ? forbid : cf => prev(cf) || forbid(cf);
        }
        _hasAssertion = true;
        Register();
        return this;
    }

    private void EnsureTriggerMutable(string method)
    {
        if (!_hasAssertion)
            return;
        throw new InvalidOperationException(
            $"Law \"{_name}\": .{method}() must come before .Expect() / .Forbid(). " +
            "Triggers and OnPage/OnResponse patterns cannot be changed after the assertion.");
    }

    private void TouchRegister()
    {
        if (_registered)
            Register();
    }

    private void Register()
    {
        var id = LawRegistry.MakeId(_sourceFile, _name);
        var pagePattern = _trigger == LawTriggerKind.Page
            ? _pattern ?? _defaultPagePattern
            : _pattern;
        var def = new LawDefinition
        {
            Id = id,
            Name = _name,
            SiteFilter = _siteFilter,
            Trigger = _trigger,
            TriggerPattern = pagePattern,
            Cost = _cost,
            Severity = _lawSeverity,
            Tags = _tags,
            ConfirmOnFail = _confirm,
            SourceFile = _sourceFile,
            PageWhen = _pageWhen,
            PageExpect = _pageExpect,
            PageForbid = _pageForbid,
            ResponseWhen = _responseWhen,
            ResponseExpect = _responseExpect,
            ResponseForbid = _responseForbid,
            ConsoleWhen = _consoleWhen,
            ConsoleExpect = _consoleExpect,
            ConsoleForbid = _consoleForbid
        };
        _registry.Register(def);
        _registered = true;
    }
}
