using System.IO;
using System.Reflection;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Security;

namespace Trowser.Laws;

public enum ShadowLawMode
{
    Light,
    Heavy
}

public sealed class LawService : IPageFactsFetcher
{
    public const string ScriptConsoleSource = "(script-console)";

    public LawRegistry Registry { get; } = new();
    public LawLoader Loader { get; }
    public LawEvaluator Evaluator { get; } = new();
    public LawProposalStore Proposals { get; } = new();
    public LawMiner Miner { get; }

    private readonly List<LawCheckResult> _lastResults = [];
    private FileSystemWatcher? _watcher;
    private AutomationContext? _context;
    private SecurityShadowManager? _shadow;
    private int _reentrancyDepth;
    private CancellationTokenSource? _serendipityCts;

    /// <summary>Optional factory for <see cref="LlmLawAuthor"/> (wired from MainWindow when Chat/API starts).</summary>
    public Func<LlmClient?>? CreateLlmClientForAuthoring { get; set; }

    public LlmLawAuthor CreateAuthor() => new(Loader, CreateLlmClientForAuthoring);

    public LawService()
    {
        Loader = new LawLoader(Registry);
        Miner = new LawMiner(Proposals);
    }

    public void Wire(AutomationContext context, SecurityShadowManager shadow)
    {
        _context = context;
        _shadow = shadow;
    }

    public IReadOnlyList<LawCheckResult> LastResults => _lastResults;

    public IReadOnlyList<string> GetLoadedLawSources() =>
        Registry.All
            .Select(l => l.SourceFile)
            .Where(s => !string.IsNullOrWhiteSpace(s) && !IsEphemeralScriptSource(s))
            .Select(s => ShadowConfig.NormalizeLawSourceKey(s!) ?? s!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private IEnumerable<LawDefinition> QueryForShadow(
        LawTriggerKind? trigger = null,
        LawCostClass? maxCost = null)
    {
        if (_shadow == null)
            return Registry.Query(trigger, maxCost);

        return Registry.Query(trigger, maxCost, _shadow.Config.DisabledLaws)
            .Where(l => _shadow.Config.IsLawSourceActive(l.SourceFile));
    }

    private string? _scriptSiteFilter;
    private string? _scriptSiteDefaultPagePattern;

    public void Site(string hostPattern, string? defaultPagePathPattern = null)
    {
        _scriptSiteFilter = hostPattern;
        _scriptSiteDefaultPagePattern = defaultPagePathPattern;
    }

    public LawBuilder Law(string name) =>
        new LawBuilder(Registry, name, _scriptSiteFilter, sourceFile: ScriptConsoleSource, defaultPagePattern: _scriptSiteDefaultPagePattern);

    public void ResetScriptDeclarationScope()
    {
        _scriptSiteFilter = null;
        _scriptSiteDefaultPagePattern = null;
    }

    /// <summary>Clears Laws from the previous Script Console run before executing a new script.</summary>
    public void BeginScriptLawSession()
    {
        Registry.RemoveSource(ScriptConsoleSource);
        _scriptSiteFilter = null;
        _scriptSiteDefaultPagePattern = null;
        _lastResults.Clear();
    }

    /// <summary>Drop ephemeral script-console Laws so Shadow does not re-run them on navigation.</summary>
    public void EndScriptLawSession()
    {
        Registry.RemoveSource(ScriptConsoleSource);
        _scriptSiteFilter = null;
        _scriptSiteDefaultPagePattern = null;
    }

    public static bool IsEphemeralScriptSource(string? sourceFile) =>
        string.Equals(sourceFile, ScriptConsoleSource, StringComparison.OrdinalIgnoreCase);

    public async Task ReloadAllAsync(CancellationToken ct = default)
    {
        await LoadEmbeddedLawsAsync(ct);
        await LoadUserLawsAsync(ct);
    }

    private static string[]? _embeddedLawResourceNames;

    public async Task LoadEmbeddedLawsAsync(CancellationToken ct = default)
    {
        const string prefix = "Trowser.Resources.Quicktests.Laws.";
        _embeddedLawResourceNames ??= Assembly.GetExecutingAssembly()
            .GetManifestResourceNames()
            .Where(n => n.StartsWith(prefix, StringComparison.Ordinal) && n.EndsWith(".csx"))
            .ToArray();

        var assembly = Assembly.GetExecutingAssembly();
        foreach (var name in _embeddedLawResourceNames)
        {
            await using var stream = assembly.GetManifestResourceStream(name);
            if (stream == null) continue;
            using var reader = new StreamReader(stream);
            var code = await reader.ReadToEndAsync(ct);
            var virtualPath = name[prefix.Length..^4].Replace('.', Path.DirectorySeparatorChar) + ".csx";
            await Loader.LoadSourceAsync("embedded:" + virtualPath, code, ct);
        }
    }

    public static string UserLawsFolder =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Trowser Quicktests", "Laws");

    public static void EnsureUserLawsFolder()
    {
        var dir = UserLawsFolder;
        var fresh = !Directory.Exists(dir);
        Directory.CreateDirectory(dir);
        if (fresh)
            SeedUserLawsFolder(dir);
    }

    private static string SanitizeLawFileHost(string host)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            host = host.Replace(c, '_');
        return string.IsNullOrWhiteSpace(host) ? "custom" : host;
    }

    private static void SeedUserLawsFolder(string dir)
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            var dest = Path.Combine(dir, "ExampleLaw.csx");
            if (File.Exists(dest)) return;
            using var stream = assembly.GetManifestResourceStream("Trowser.Resources.UserQuicktests.Laws.ExampleLaw.csx");
            if (stream == null) return;
            using var reader = new StreamReader(stream);
            File.WriteAllText(dest, reader.ReadToEnd());
        }
        catch
        {
            /* seed best-effort */
        }
    }

    public async Task LoadUserLawsAsync(CancellationToken ct = default)
    {
        EnsureUserLawsFolder();
        foreach (var file in Directory.EnumerateFiles(UserLawsFolder, "*.csx", SearchOption.AllDirectories))
            await Loader.LoadFileAsync(file, ct);
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, CancellationTokenSource> _watchDebounce =
        new(StringComparer.OrdinalIgnoreCase);

    public void StartWatchingUserLaws()
    {
        EnsureUserLawsFolder();
        _watcher?.Dispose();
        _watcher = new FileSystemWatcher(UserLawsFolder, "*.csx")
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
            EnableRaisingEvents = true
        };
        _watcher.Changed += (_, e) => ScheduleReload(e.FullPath);
        _watcher.Created += (_, e) => ScheduleReload(e.FullPath);
        _watcher.Deleted += (_, e) => UnloadUserFile(e.FullPath);
        _watcher.Renamed += (_, e) =>
        {
            UnloadUserFile(e.OldFullPath);
            if (e.FullPath.EndsWith(".csx", StringComparison.OrdinalIgnoreCase))
                ScheduleReload(e.FullPath);
        };
    }

    private void UnloadUserFile(string path)
    {
        if (_watchDebounce.TryRemove(path, out var pending))
            pending.Cancel();
        Registry.RemoveSource(path);
        Loader.ForgetFile(path);
    }

    /// <summary>Editors fire several Changed events per save; reload once after the burst settles.</summary>
    private void ScheduleReload(string path)
    {
        var cts = new CancellationTokenSource();
        CancellationTokenSource? previous = null;
        _watchDebounce.AddOrUpdate(path, cts, (_, existing) => { previous = existing; return cts; });
        previous?.Cancel();

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(250, cts.Token);
                _watchDebounce.TryRemove(new KeyValuePair<string, CancellationTokenSource>(path, cts));
                if (File.Exists(path))
                    await Loader.LoadFileAsync(path, cts.Token);
            }
            catch (OperationCanceledException)
            {
                /* superseded by a newer event */
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Law reload failed for {path}: {ex.Message}");
            }
        });
    }

    public async Task<LawCheckSummary> CheckLawsAsync(
        string? nameFilter = null,
        LawCheckScope scope = LawCheckScope.AllLoaded,
        bool includeTraffic = false,
        CancellationToken ct = default)
    {
        if (_context == null)
            throw new InvalidOperationException("LawService is not wired to a browser context.");

        var url = await _context.GetCurrentUrl();
        var title = await _context.GetTitle();
        var host = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : "";

        IEnumerable<LawDefinition> pageLaws = _shadow != null
            ? QueryForShadow().Where(l => l.UsesPageFacts)
            : Registry.All.Where(l => l.UsesPageFacts);
        if (scope == LawCheckScope.ScriptConsoleDeclared)
            pageLaws = pageLaws.Where(l => IsEphemeralScriptSource(l.SourceFile));
        else
            pageLaws = pageLaws.Where(l => !IsEphemeralScriptSource(l.SourceFile));

        if (!string.IsNullOrWhiteSpace(nameFilter))
            pageLaws = pageLaws.Where(l => l.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase));

        var pageLawList = pageLaws.ToList();
        var prefetched = await Evaluator.PrefetchAsync(
            pageLawList.Where(l => PageLawApplies(l, url, host)), url, title, this, ct);

        var byId = new Dictionary<string, LawCheckResult>(StringComparer.Ordinal);
        foreach (var law in pageLawList)
        {
            var r = await Evaluator.EvaluatePageLawAsync(law, url, host, title, this, ct, prefetched);
            byId[r.LawId] = r;
        }

        var responseEntriesChecked = 0;
        var consoleEntriesChecked = 0;
        if (includeTraffic)
        {
            IEnumerable<LawDefinition> trafficBase = _shadow != null
                ? QueryForShadow()
                : Registry.All;
            if (scope == LawCheckScope.ScriptConsoleDeclared)
                trafficBase = trafficBase.Where(l => IsEphemeralScriptSource(l.SourceFile));
            else
                trafficBase = trafficBase.Where(l => !IsEphemeralScriptSource(l.SourceFile));
            if (!string.IsNullOrWhiteSpace(nameFilter))
                trafficBase = trafficBase.Where(l => l.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase));

            var responseLaws = trafficBase.Where(l => l.Trigger == LawTriggerKind.Response).ToList();
            var consoleLaws = trafficBase.Where(l => l.Trigger == LawTriggerKind.Console).ToList();

            foreach (var entry in _context.Network.Entries)
            {
                responseEntriesChecked++;
                foreach (var law in responseLaws)
                {
                    var r = Evaluator.EvaluateResponseLaw(law, url, host, entry);
                    if (byId.TryGetValue(r.LawId, out var prev))
                        byId[r.LawId] = LawResultDetail.Merge(prev, r);
                    else if (r.Verdict != LawVerdict.NotApplicable)
                        byId[r.LawId] = r;
                }
            }

            foreach (var entry in _context.Console.Entries)
            {
                consoleEntriesChecked++;
                foreach (var law in consoleLaws)
                {
                    var r = Evaluator.EvaluateConsoleLaw(law, url, host, entry);
                    if (byId.TryGetValue(r.LawId, out var prev))
                        byId[r.LawId] = LawResultDetail.Merge(prev, r);
                    else if (r.Verdict != LawVerdict.NotApplicable)
                        byId[r.LawId] = r;
                }
            }
        }

        var results = byId.Values.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToList();

        _lastResults.Clear();
        _lastResults.AddRange(results);
        foreach (var r in results)
            ReportResult(r);
        return new LawCheckSummary
        {
            Results = results,
            ResponseEntriesChecked = responseEntriesChecked,
            ConsoleEntriesChecked = consoleEntriesChecked
        };
    }

    public async Task AssertLawsAsync(string? nameFilter = null, CancellationToken ct = default)
    {
        var summary = await CheckLawsAsync(nameFilter, LawCheckScope.AllLoaded, ct: ct);
        var failures = summary.Results.Where(r => r.Verdict == LawVerdict.Fail).ToList();
        if (failures.Count == 0)
            return;

        var msg = string.Join("; ", failures.Select(f => f.Name));
        throw new InvalidOperationException($"Law assertion failed: {msg}");
    }

    public async Task LoadLaws(string path, CancellationToken ct = default)
    {
        await Loader.LoadFileAsync(path, ct);
    }

    public event Action<ShadowHeavyRunReport>? ShadowHeavyCompleted;

    public async Task<ShadowHeavyRunReport> RunShadowHeavyAsync(CancellationToken ct = default)
    {
        var report = await RunShadowAsync(ShadowLawMode.Heavy, ct);
        ShadowHeavyCompleted?.Invoke(report);
        return report;
    }

    public async Task<string> SaveUserLawSourceAsync(string code, string? fileName = null, CancellationToken ct = default)
    {
        EnsureUserLawsFolder();
        var name = string.IsNullOrWhiteSpace(fileName)
            ? $"Declared-{DateTime.Now:yyyyMMdd-HHmmss}.csx"
            : fileName.Trim();
        if (!name.EndsWith(".csx", StringComparison.OrdinalIgnoreCase))
            name += ".csx";
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');

        var path = Path.Combine(UserLawsFolder, name);
        await File.WriteAllTextAsync(path, code.TrimEnd() + Environment.NewLine, ct);
        await Loader.LoadFileAsync(path, ct);
        _shadow?.Config.EnsureLawSourceActive(path);
        return path;
    }

    private CancellationTokenSource? _navigationCts;

    /// <summary>Shadow Light after a navigation. A newer navigation cancels an older, still-pending run.</summary>
    public async Task RunAfterNavigationAsync(CancellationToken ct = default)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var previous = Interlocked.Exchange(ref _navigationCts, cts);
        try { previous?.Cancel(); }
        catch (ObjectDisposedException) { /* already finished */ }
        try
        {
            if (_context != null)
                await _context.WaitForIdle(quietPeriodMs: 400, timeoutMs: 8000);
            cts.Token.ThrowIfCancellationRequested();
            _ = await RunShadowAsync(ShadowLawMode.Light, cts.Token);
        }
        catch (OperationCanceledException)
        {
            /* navigation cancelled */
        }
        finally
        {
            Interlocked.CompareExchange(ref _navigationCts, null, cts);
            cts.Dispose();
        }
    }

    private async Task<ShadowHeavyRunReport> RunShadowAsync(ShadowLawMode mode, CancellationToken ct = default)
    {
        if (_context == null || _shadow == null)
            return ShadowHeavyRunReport.Skipped("Shadow not initialized.");
        if (!_shadow.Config.LawsEnabled)
            return ShadowHeavyRunReport.Skipped("Laws are off — enable “Laws” in Shadow Settings (Experimental).");

        if (Interlocked.Increment(ref _reentrancyDepth) > 1)
        {
            Interlocked.Decrement(ref _reentrancyDepth);
            return ShadowHeavyRunReport.Skipped("Shadow Law run already in progress.");
        }

        var lawsEvaluated = 0;
        var lawPasses = 0;
        var lawFailures = 0;
        var lawNotApplicable = 0;
        var lawErrors = 0;
        var heavyQuicktests = 0;
        string? pageUrl = null;
        var results = new List<LawCheckResult>();

        try
        {
            pageUrl = await _context.GetCurrentUrl();
            var title = await _context.GetTitle();
            var host = Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri) ? uri.Host : "";

            var budgetMs = mode == ShadowLawMode.Light ? _shadow.Config.LightLawBudgetMs : int.MaxValue;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Evaluator.SetPredicateTimeoutMs(mode == ShadowLawMode.Heavy
                ? LawRuntimeLimits.HeavyPredicateTimeoutMs
                : LawRuntimeLimits.DefaultPredicateTimeoutMs);

            // Light: Page Laws only. Heavy: Page + Action (after quicktest runs) + Timer (serendipity / explicit check).
            var laws = QueryForShadow()
                .Where(l => !IsEphemeralScriptSource(l.SourceFile))
                .Where(l => mode == ShadowLawMode.Heavy ? l.UsesPageFacts : l.Trigger == LawTriggerKind.Page)
                .Where(l => PageLawApplies(l, pageUrl, host))
                .OrderBy(l => l.Cost)
                .ThenBy(l => l.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var prefetched = laws.Count > 0
                ? await Evaluator.PrefetchAsync(laws, pageUrl, title, this, ct)
                : null;

            var skipped = new List<string>();
            foreach (var law in laws)
            {
                if (sw.ElapsedMilliseconds > budgetMs)
                {
                    skipped.Add(law.Name);
                    continue;
                }

                var result = await Evaluator.EvaluatePageLawAsync(law, pageUrl, host, title, this, ct, prefetched);
                results.Add(result);
                lawsEvaluated++;
                if (result.Verdict == LawVerdict.Pass)
                    lawPasses++;
                else if (result.Verdict == LawVerdict.Fail)
                    lawFailures++;
                else if (result.Verdict == LawVerdict.NotApplicable)
                    lawNotApplicable++;
                else if (result.Verdict == LawVerdict.Error)
                    lawErrors++;
                ReportResult(result);
            }

            if (skipped.Count > 0)
                ReportSkipped(skipped, pageUrl);

            if (mode == ShadowLawMode.Light && IsHttpDocumentUrl(pageUrl))
                await RunLightQuicktestsAsync(ct);
            else if (mode == ShadowLawMode.Heavy && IsHttpDocumentUrl(pageUrl))
                heavyQuicktests = await RunHeavyQuicktestsAsync(ct);
        }
        finally
        {
            Interlocked.Decrement(ref _reentrancyDepth);
        }

        _lastResults.Clear();
        _lastResults.AddRange(results);

        if (mode != ShadowLawMode.Heavy)
            return new ShadowHeavyRunReport
            {
                Ran = true,
                PageUrl = pageUrl,
                LawsEvaluated = lawsEvaluated,
                LawPasses = lawPasses,
                LawFailures = lawFailures,
                LawNotApplicable = lawNotApplicable,
                LawErrors = lawErrors
            };

        return new ShadowHeavyRunReport
        {
            Ran = true,
            PageUrl = pageUrl,
            LawsEvaluated = lawsEvaluated,
            LawPasses = lawPasses,
            LawFailures = lawFailures,
            LawNotApplicable = lawNotApplicable,
            LawErrors = lawErrors,
            HeavyQuicktestsRun = heavyQuicktests
        };
    }

    public void OnNetworkEntry(NetworkEntry entry, string pageUrl)
    {
        if (_shadow == null || !_shadow.Enabled || !_shadow.Config.LawsEnabled)
            return;

        var host = Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri) ? uri.Host : "";
        if (_shadow.Config.LawsMiningEnabled)
        {
            Miner.ObserveResponse(entry, host);
            if (entry.Id % 25 == 0)
                Miner.RankAndPropose();
        }

        foreach (var law in QueryForShadow(trigger: LawTriggerKind.Response)
                     .Where(l => !IsEphemeralScriptSource(l.SourceFile)))
        {
            var result = Evaluator.EvaluateResponseLaw(law, pageUrl, host, entry);
            ReportResult(result);
        }
    }

    public void OnConsoleEntry(ConsoleEntry entry, string pageUrl)
    {
        if (_shadow == null || !_shadow.Enabled || !_shadow.Config.LawsEnabled)
            return;

        var host = Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri) ? uri.Host : "";
        if (_shadow.Config.LawsMiningEnabled)
        {
            Miner.ObserveConsole(entry, host);
            if (entry.Id % 25 == 0)
                Miner.RankAndPropose();
        }

        foreach (var law in QueryForShadow(trigger: LawTriggerKind.Console)
                     .Where(l => !IsEphemeralScriptSource(l.SourceFile)))
        {
            var result = Evaluator.EvaluateConsoleLaw(law, pageUrl, host, entry);
            ReportResult(result);
        }
    }

    public void ConfigureSerendipityTimer(bool enabled, int? intervalSeconds, bool randomize)
    {
        _serendipityCts?.Cancel();
        _serendipityCts?.Dispose();
        _serendipityCts = null;
        if (!enabled)
            return;

        _serendipityCts = new CancellationTokenSource();
        var ct = _serendipityCts.Token;
        _ = RunSerendipityLoopAsync(intervalSeconds ?? 300, randomize, ct);
    }

    private async Task RunSerendipityLoopAsync(int baseSeconds, bool randomize, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await RunShadowHeavyAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var delay = randomize
                ? TimeSpan.FromSeconds(Random.Shared.Next(Math.Max(60, baseSeconds / 2), baseSeconds * 2))
                : TimeSpan.FromSeconds(baseSeconds);
            try
            {
                await Task.Delay(delay, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public async Task<string?> AppendProposalToUserLawsAsync(LawProposal proposal, CancellationToken ct = default)
    {
        var fileName = string.Equals(proposal.Source, "mining", StringComparison.OrdinalIgnoreCase)
            ? "host.csx"
            : $"{SanitizeLawFileHost(proposal.Host ?? "custom")}.csx";
        var (ok, error) = await AppendUserLawSourceAsync(fileName, proposal.Code, ct);
        if (!ok)
            throw new InvalidOperationException(error ?? "Could not append mined Law.");
        return ResolveUserLawPath(fileName);
    }

    async Task<Dictionary<string, object?>> IPageFactsFetcher.FetchAsync(IReadOnlyList<string> keys, CancellationToken ct)
    {
        if (_context == null)
            throw new InvalidOperationException("LawService is not wired.");

        return await FetchPageFactsAsync(keys, ct);
    }

    private async Task<Dictionary<string, object?>> FetchPageFactsAsync(IReadOnlyList<string> keys, CancellationToken ct)
    {
        var reqObjects = keys.Select(k =>
        {
            var (key, kind, selector, extra) = ParseKey(k);
            return new Dictionary<string, string?>
            {
                ["key"] = key,
                ["kind"] = kind,
                ["selector"] = selector,
                ["extra"] = extra
            };
        }).ToList();

        var payload = JsonSerializer.Serialize(reqObjects);
        var raw = await _context!.ExecuteJs(
            $$"""
            (function(){
              var reqs = {{payload}};
              var out = {};
              function queryDeepFirst(root, sel) {
                try {
                  var el = root.querySelector(sel);
                  if (el) return el;
                } catch (e) { return null; }
                var nodes = root.querySelectorAll('*');
                for (var i = 0; i < nodes.length; i++) {
                  var sr = nodes[i].shadowRoot;
                  if (!sr) continue;
                  var found = queryDeepFirst(sr, sel);
                  if (found) return found;
                }
                return null;
              }
              function queryDeepAll(root, sel, acc) {
                try {
                  var list = root.querySelectorAll(sel);
                  for (var i = 0; i < list.length; i++) acc.push(list[i]);
                } catch (e) { }
                var nodes = root.querySelectorAll('*');
                for (var j = 0; j < nodes.length; j++) {
                  var sr = nodes[j].shadowRoot;
                  if (sr) queryDeepAll(sr, sel, acc);
                }
              }
              for (var i = 0; i < reqs.length; i++) {
                var r = reqs[i];
                var key = r.key;
                var sel = r.selector;
                try {
                  if (r.kind === 'text') {
                    var el = queryDeepFirst(document, sel);
                    out[key] = el ? (el.innerText || el.textContent || '') : '';
                  } else if (r.kind === 'exists') {
                    out[key] = String(!!queryDeepFirst(document, sel));
                  } else if (r.kind === 'visible') {
                    var el2 = queryDeepFirst(document, sel);
                    if (!el2) { out[key] = 'false'; continue; }
                    var st = getComputedStyle(el2);
                    out[key] = String(st.display !== 'none' && st.visibility !== 'hidden' && el2.offsetParent !== null);
                  } else if (r.kind === 'count') {
                    var acc = [];
                    queryDeepAll(document, sel, acc);
                    out[key] = String(acc.length);
                  } else if (r.kind === 'numbers') {
                    var acc2 = [];
                    queryDeepAll(document, sel, acc2);
                    var nums = [];
                    for (var j = 0; j < acc2.length; j++) {
                      var t = (acc2[j].innerText || acc2[j].textContent || '').trim();
                      if (t) nums.push(t);
                    }
                    out[key] = nums.join('|');
                  } else if (r.kind === 'attr') {
                    var el3 = queryDeepFirst(document, sel);
                    out[key] = el3 ? (el3.getAttribute(r.extra) || '') : '';
                  } else if (r.kind === 'value') {
                    var el4 = queryDeepFirst(document, sel);
                    out[key] = el4 && el4.value != null ? String(el4.value) : '';
                  } else if (r.kind === 'texts') {
                    var acc3 = [];
                    queryDeepAll(document, sel, acc3);
                    var texts = [];
                    for (var k = 0; k < acc3.length; k++) {
                      var tt = (acc3[k].innerText || acc3[k].textContent || '').trim();
                      if (tt) texts.push(tt);
                    }
                    out[key] = texts.join('\u001f');
                  }
                } catch (e) { out[key] = ''; }
              }
              return JSON.stringify(out);
            })()
            """);

        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(raw))
            return result;

        var json = UnwrapJsString(raw);
        using var doc = JsonDocument.Parse(json);
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            result[prop.Name] = prop.Value.ValueKind switch
            {
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Number => prop.Value.GetRawText(),
                _ => prop.Value.GetString()
            };
        }

        return result;
    }

    private static string UnwrapJsString(string raw)
    {
        var t = raw.Trim();
        if (t.Length >= 2 && t.StartsWith('"') && t.EndsWith('"'))
        {
            try { return JsonSerializer.Deserialize<string>(t) ?? t; }
            catch { return t.Trim('"'); }
        }
        return t;
    }

    private static (string key, string kind, string selector, string? extra) ParseKey(string key)
    {
        var parts = key.Split('\0');
        var kind = parts[0];
        var selector = parts.Length > 1 ? parts[1] : "";
        var extra = parts.Length > 2 ? parts[2] : null;
        return (key, kind, selector, extra);
    }

    private void ReportResult(LawCheckResult result)
    {
        if (_shadow == null)
            return;

        switch (result.Verdict)
        {
            case LawVerdict.Fail:
            {
                var desc = result.Message ?? "Violation";
                if (!string.IsNullOrWhiteSpace(result.Evidence))
                    desc += " Evidence: " + result.Evidence;
                _shadow.AddCustomFinding(
                    result.Severity,
                    $"Law: {result.Name}",
                    desc,
                    recommendation: "Fix the invariant or mute the Law in Shadow settings.",
                    audit: "laws",
                    url: result.ContextUrl);
                break;
            }
            case LawVerdict.Error:
                _shadow.AddCustomFinding(
                    Severity.Info,
                    $"Law error: {result.Name}",
                    result.Message ?? "The Law threw or could not complete.",
                    recommendation: "Fix the Law source or mute it in Shadow settings — this is not a site defect.",
                    audit: "law-runtime",
                    url: result.ContextUrl);
                break;
            case LawVerdict.Pass:
                _shadow.ClearLawFailureForUrl(result.Name, result.ContextUrl);
                break;
        }
    }

    private void ReportSkipped(IReadOnlyList<string> lawNames, string url)
    {
        _shadow?.AddCustomFinding(
            Severity.Info,
            "Laws skipped (Shadow Light budget)",
            $"Shadow Light ran out of time ({_shadow.Config.LightLawBudgetMs} ms) before {lawNames.Count} Law(s) could run: "
            + string.Join(", ", lawNames.Take(10)) + (lawNames.Count > 10 ? ", …" : "") + ".",
            recommendation: "Raise the Light budget, move slow Laws to Heavy (.Cost(LawCostClass.Heavy)), or run POST /api/shadow/check.",
            audit: "law-budget",
            url: url);
    }

    internal static bool PageLawApplies(LawDefinition law, string pageUrl, string pageHost)
    {
        if (!law.UsesPageFacts)
            return false;
        if (!LawPathMatch.HostMatches(law.SiteFilter, pageHost))
            return false;
        if (law.Trigger == LawTriggerKind.Page
            && !LawPathMatch.PagePathMatches(law.TriggerPattern, pageUrl))
            return false;
        return true;
    }

    private async Task<int> RunHeavyQuicktestsAsync(CancellationToken ct)
    {
        if (_context?.NestedQuicktestRunner == null)
            return 0;

        var count = 0;
        foreach (var meta in QuicktestCatalog.Embedded.Where(q =>
                     q.IsReadOnlyEffects && _shadow!.Config.HeavyQuicktests.Contains(q.Leaf)))
        {
            var code = await LoadQuicktestCodeAsync(meta.ResourceName, ct);
            if (code == null) continue;
            await RunQuicktestAsShadowFindingAsync(meta.Leaf, code, ct);
            count++;
        }

        return count;
    }

    private static bool IsHttpDocumentUrl(string url) =>
        url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    private async Task RunLightQuicktestsAsync(CancellationToken ct)
    {
        if (_context?.NestedQuicktestRunner == null)
            return;
        if (_shadow!.Config.LightQuicktests.Count == 0)
            return;

        foreach (var meta in QuicktestCatalog.ResolveLightRunList(_shadow.Config.LightQuicktests))
        {
            var code = await LoadQuicktestCodeAsync(meta.ResourceName, ct);
            if (code == null) continue;
            await RunQuicktestAsShadowFindingAsync(meta.Leaf, code, ct);
        }
    }

    private async Task RunQuicktestAsShadowFindingAsync(string leaf, string code, CancellationToken ct)
    {
        if (_context?.NestedQuicktestRunner == null)
            return;

        var passBefore = _context.Assert.PassCount;
        var failBefore = _context.Assert.FailCount;
        try
        {
            await _context.NestedQuicktestRunner(code, ct);
        }
        catch (Exception ex)
        {
            _shadow?.AddCustomFinding(
                Severity.Medium,
                $"Quicktest failed: {leaf}",
                ex.Message,
                audit: $"quicktest:{leaf}",
                url: await _context.GetCurrentUrl());
            return;
        }

        var newFails = _context.Assert.FailCount - failBefore;
        if (newFails > 0)
        {
            _shadow?.AddCustomFinding(
                Severity.Medium,
                $"Quicktest assertions failed: {leaf}",
                $"{newFails} assertion(s) failed during Shadow quicktest run.",
                audit: $"quicktest:{leaf}",
                url: await _context.GetCurrentUrl());
        }
    }

    public static bool IsUserLawSource(string? sourceFile)
    {
        if (string.IsNullOrWhiteSpace(sourceFile))
            return false;
        if (sourceFile.StartsWith("embedded:", StringComparison.OrdinalIgnoreCase))
            return false;
        if (sourceFile.Equals("(script-console)", StringComparison.OrdinalIgnoreCase))
            return false;
        if (sourceFile.Equals("(validate)", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            var full = Path.GetFullPath(sourceFile);
            var folder = Path.TrimEndingDirectorySeparator(Path.GetFullPath(UserLawsFolder)) + Path.DirectorySeparatorChar;
            return full.StartsWith(folder, StringComparison.OrdinalIgnoreCase) && File.Exists(full);
        }
        catch
        {
            return false;
        }
    }

    public static string ResolveUserLawPath(string fileName)
    {
        EnsureUserLawsFolder();
        var name = fileName.Trim();
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        if (!name.EndsWith(".csx", StringComparison.OrdinalIgnoreCase))
            name += ".csx";
        return Path.Combine(UserLawsFolder, name);
    }

    public async Task<(bool ok, IReadOnlyList<string> errors, string? path)> ReplaceUserLawFileAsync(
        string fileName,
        string code,
        CancellationToken ct = default)
    {
        code = LawCodeGenerator.StripConsoleRunnerLines(code);
        if (string.IsNullOrWhiteSpace(code))
            return (false, new[] { "Law code is empty." }, null);

        var path = ResolveUserLawPath(fileName);
        var (valid, errors) = await Loader.ValidateAgainstRegistryAsync(code, Registry, path, ct);
        if (!valid)
            return (false, errors, path);

        await File.WriteAllTextAsync(path, code.TrimEnd() + Environment.NewLine, ct);
        await Loader.LoadFileAsync(path, ct);
        _shadow?.Config.EnsureLawSourceActive(path);
        return (true, Array.Empty<string>(), path);
    }

    public async Task<(bool ok, string? error)> AppendUserLawSourceAsync(
        string fileName,
        string code,
        CancellationToken ct = default)
    {
        code = LawCodeGenerator.StripConsoleRunnerLines(code);
        if (string.IsNullOrWhiteSpace(code))
            return (false, "Law code is empty.");

        var path = ResolveUserLawPath(fileName);
        var merged = File.Exists(path)
            ? await File.ReadAllTextAsync(path, ct) + Environment.NewLine + code.Trim() + Environment.NewLine
            : code.TrimEnd() + Environment.NewLine;

        var (valid, errors) = await Loader.ValidateAgainstRegistryAsync(merged, Registry, path, ct);
        if (!valid)
            return (false, string.Join("; ", errors));

        if (File.Exists(path))
            await File.AppendAllTextAsync(path, Environment.NewLine + code.Trim() + Environment.NewLine, ct);
        else
            await File.WriteAllTextAsync(path, merged, ct);

        await Loader.LoadFileAsync(path, ct);
        _shadow?.Config.EnsureLawSourceActive(path);
        return (true, null);
    }

    public async Task<bool> DeleteUserLawByFileNameAsync(string fileName, CancellationToken ct = default)
    {
        var path = ResolveUserLawPath(fileName);
        return await DeleteUserLawFileAsync(path, ct);
    }

    /// <summary>Removes a user Law file and unloads its definitions from the registry.</summary>
    public async Task<bool> DeleteUserLawFileAsync(string sourceFilePath, CancellationToken ct = default)
    {
        if (!IsUserLawSource(sourceFilePath))
            return false;

        Registry.RemoveSource(sourceFilePath);
        Loader.ForgetFile(sourceFilePath);
        _shadow?.Config.RemoveLawSourceKey(sourceFilePath);
        if (File.Exists(sourceFilePath))
            File.Delete(sourceFilePath);

        await Task.CompletedTask;
        return true;
    }

    public async Task<(string? path, bool createdNew)> CopyEmbeddedLawToUserAsync(string sourceFileKey, CancellationToken ct = default)
    {
        const string prefix = "embedded:";
        if (!sourceFileKey.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return (null, false);

        var virtualName = sourceFileKey[prefix.Length..];
        var resourceName = Assembly.GetExecutingAssembly().GetManifestResourceNames()
            .FirstOrDefault(n => n.Contains(virtualName.Replace('\\', '.').Replace(".csx", ""), StringComparison.OrdinalIgnoreCase)
                                 && n.EndsWith(".csx") && n.Contains(".Laws.", StringComparison.Ordinal));
        if (resourceName == null)
            return (null, false);

        await using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
        if (stream == null) return (null, false);
        using var reader = new StreamReader(stream);
        var code = await reader.ReadToEndAsync(ct);

        EnsureUserLawsFolder();
        var fileName = Path.GetFileName(virtualName);
        if (!fileName.EndsWith(".csx", StringComparison.OrdinalIgnoreCase))
            fileName += ".csx";
        var dest = Path.Combine(UserLawsFolder, fileName);
        var createdNew = !File.Exists(dest);
        if (createdNew)
            await File.WriteAllTextAsync(dest, code, ct);
        else
            await File.AppendAllTextAsync(dest, Environment.NewLine + Environment.NewLine + code.Trim() + Environment.NewLine, ct);

        await Loader.LoadFileAsync(dest, ct);
        if (createdNew)
            _shadow?.Config.EnsureLawSourceActive(dest);
        return (dest, createdNew);
    }

    private static async Task<string?> LoadQuicktestCodeAsync(string resourceName, CancellationToken ct)
    {
        await using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
        if (stream == null) return null;
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(ct);
    }
}
