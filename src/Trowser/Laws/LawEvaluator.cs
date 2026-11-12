using System.Globalization;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Laws;

public interface IPageFactsFetcher
{
    Task<Dictionary<string, object?>> FetchAsync(IReadOnlyList<string> keys, CancellationToken ct);
}

public sealed class LawEvaluator
{
    private int _predicateTimeoutMs = LawRuntimeLimits.DefaultPredicateTimeoutMs;

    public void SetPredicateTimeoutMs(int ms) =>
        _predicateTimeoutMs = ms > 0 ? ms : LawRuntimeLimits.DefaultPredicateTimeoutMs;

    public LawCheckResult EvaluatePageLaw(
        LawDefinition law,
        string pageUrl,
        string pageHost,
        string pageTitle,
        IPageFactsFetcher fetcher,
        CancellationToken ct) =>
        EvaluatePageLawAsync(law, pageUrl, pageHost, pageTitle, fetcher, ct).GetAwaiter().GetResult();

    /// <param name="prefetched">Facts already read for this page snapshot (see <see cref="PrefetchAsync"/>); copied, not mutated.</param>
    public async Task<LawCheckResult> EvaluatePageLawAsync(
        LawDefinition law,
        string pageUrl,
        string pageHost,
        string pageTitle,
        IPageFactsFetcher fetcher,
        CancellationToken ct,
        IReadOnlyDictionary<string, object?>? prefetched = null)
    {
        if (!LawPathMatch.HostMatches(law.SiteFilter, pageHost))
            return NotApplicable(law, pageUrl, "Site filter");

        if (!law.UsesPageFacts)
            return NotApplicable(law, pageUrl, "Wrong trigger");

        if (law.Trigger == LawTriggerKind.Page && !LawPathMatch.PagePathMatches(law.TriggerPattern, pageUrl))
            return NotApplicable(law, pageUrl, "Path pattern");

        return await EvaluatePageCore(law, pageUrl, pageTitle, fetcher, ct, prefetched);
    }

    /// <summary>
    /// Runs every Law's page predicates in collect mode to learn which DOM facts they need, then reads
    /// them all in one round trip. Laws that branch on facts may still fetch extra keys later.
    /// </summary>
    public async Task<Dictionary<string, object?>> PrefetchAsync(
        IEnumerable<LawDefinition> laws,
        string pageUrl,
        string pageTitle,
        IPageFactsFetcher fetcher,
        CancellationToken ct)
    {
        var cache = new Dictionary<string, object?>(StringComparer.Ordinal);
        var pending = new HashSet<string>(StringComparer.Ordinal);
        foreach (var law in laws)
        {
            foreach (var predicate in new[] { law.PageWhen, law.PageForbid, law.PageExpect })
            {
                if (predicate == null)
                    continue;
                var facts = new PageFacts(cache, pending, pageUrl, pageTitle) { CollectMode = true };
                try
                {
                    var run = Task.Run(() => RunInvariant(() => predicate(facts)), ct);
                    await run.WaitAsync(TimeSpan.FromMilliseconds(Math.Min(_predicateTimeoutMs, 1000)), ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (TimeoutException)
                {
                    break;
                }
                catch
                {
                    /* collect pass is best-effort; the real evaluation reports errors */
                }
            }
        }

        if (pending.Count == 0)
            return cache;

        var fetched = await fetcher.FetchAsync(pending.ToList(), ct);
        foreach (var kvp in fetched)
            cache[kvp.Key] = kvp.Value;
        return cache;
    }

    public LawCheckResult EvaluateResponseLaw(LawDefinition law, string pageUrl, string pageHost, NetworkEntry entry)
    {
        if (!LawPathMatch.HostMatches(law.SiteFilter, pageHost))
            return NotApplicable(law, pageUrl, "Site filter");

        if (law.Trigger != LawTriggerKind.Response)
            return NotApplicable(law, pageUrl, "Wrong trigger");

        if (!LawPathMatch.ResponseMatches(law.TriggerPattern, entry))
            return NotApplicable(law, pageUrl, "Response pattern");

        var contextUrl = string.IsNullOrWhiteSpace(entry.Url) ? pageUrl : entry.Url;

        try
        {
            var trace = new List<string>();
            var facts = new ResponseFacts(entry, trace);
            if (law.ResponseWhen != null)
            {
                var when = RunPredicateWithTimeout(() => law.ResponseWhen(facts));
                if (when.Error != null)
                    return Error(law, contextUrl, when.Error);
                if (when.Result != true)
                    return NotApplicable(law, contextUrl, "When guard");
            }

            if (law.ResponseForbid != null)
            {
                var forbid = RunPredicateWithTimeout(() => law.ResponseForbid(facts));
                if (forbid.Error != null)
                    return Error(law, contextUrl, forbid.Error);
                if (forbid.Result == true)
                    return Fail(law, contextUrl, "Forbidden condition held", ResponseFacts.FormatEvidence(trace));
            }

            if (law.ResponseExpect != null)
            {
                var expect = RunPredicateWithTimeout(() => law.ResponseExpect(facts));
                if (expect.Error != null)
                    return Error(law, contextUrl, expect.Error);
                if (expect.Result != true)
                    return Fail(law, contextUrl, "Expectation failed", ResponseFacts.FormatEvidence(trace));
            }

            return Pass(law, contextUrl);
        }
        catch (Exception ex)
        {
            return Error(law, contextUrl, ex.Message);
        }
    }

    public LawCheckResult EvaluateConsoleLaw(LawDefinition law, string pageUrl, string pageHost, ConsoleEntry entry)
    {
        if (!LawPathMatch.HostMatches(law.SiteFilter, pageHost))
            return NotApplicable(law, pageUrl, "Site filter");

        if (law.Trigger != LawTriggerKind.Console)
            return NotApplicable(law, pageUrl, "Wrong trigger");

        if (!string.IsNullOrEmpty(law.TriggerPattern)
            && !entry.Level.ToString().Contains(law.TriggerPattern, StringComparison.OrdinalIgnoreCase))
            return NotApplicable(law, pageUrl, "Console level");

        try
        {
            var facts = new ConsoleFacts(entry);
            if (law.ConsoleWhen != null)
            {
                var when = RunPredicateWithTimeout(() => law.ConsoleWhen(facts));
                if (when.Error != null)
                    return Error(law, pageUrl, when.Error);
                if (when.Result != true)
                    return NotApplicable(law, pageUrl, "When guard");
            }

            if (law.ConsoleForbid != null)
            {
                var forbid = RunPredicateWithTimeout(() => law.ConsoleForbid(facts));
                if (forbid.Error != null)
                    return Error(law, pageUrl, forbid.Error);
                if (forbid.Result == true)
                    return Fail(law, pageUrl, "Forbidden console message", $"c.Level = {facts.Level}; c.Message = {Trim(facts.Message)}");
            }

            if (law.ConsoleExpect != null)
            {
                var expect = RunPredicateWithTimeout(() => law.ConsoleExpect(facts));
                if (expect.Error != null)
                    return Error(law, pageUrl, expect.Error);
                if (expect.Result != true)
                    return Fail(law, pageUrl, "Console expectation failed", $"c.Level = {facts.Level}; c.Message = {Trim(facts.Message)}");
            }

            return Pass(law, pageUrl);
        }
        catch (Exception ex)
        {
            return Error(law, pageUrl, ex.Message);
        }
    }

    private async Task<LawCheckResult> EvaluatePageCore(
        LawDefinition law,
        string pageUrl,
        string pageTitle,
        IPageFactsFetcher fetcher,
        CancellationToken ct,
        IReadOnlyDictionary<string, object?>? prefetched = null)
    {
        try
        {
            var cache = prefetched != null
                ? new Dictionary<string, object?>(prefetched, StringComparer.Ordinal)
                : new Dictionary<string, object?>(StringComparer.Ordinal);

            if (law.PageWhen != null)
            {
                var when = await RunPagePredicateAsync(law, cache, pageUrl, pageTitle, fetcher, ct, law.PageWhen, trace: null);
                if (when.Error != null)
                    return Error(law, pageUrl, when.Error);
                if (when.Result == false)
                    return NotApplicable(law, pageUrl, "When guard");
            }

            var trace = new List<string>();

            if (law.PageForbid != null)
            {
                var forbid = await RunPagePredicateAsync(law, cache, pageUrl, pageTitle, fetcher, ct, law.PageForbid, trace);
                if (forbid.Error != null)
                    return Error(law, pageUrl, forbid.Error);
                if (forbid.Result == true)
                    return await ConfirmFailAsync(law, pageUrl, pageTitle, fetcher, ct, "Forbidden condition held", PageFacts.FormatEvidence(trace));
            }

            if (law.PageExpect != null)
            {
                var expect = await RunPagePredicateAsync(law, cache, pageUrl, pageTitle, fetcher, ct, law.PageExpect, trace);
                if (expect.Error != null)
                    return Error(law, pageUrl, expect.Error);
                if (expect.Result == false)
                    return await ConfirmFailAsync(law, pageUrl, pageTitle, fetcher, ct, "Expectation failed", PageFacts.FormatEvidence(trace));
            }

            return Pass(law, pageUrl);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Error(law, pageUrl, ex.Message);
        }
    }

    private readonly record struct PredicateRun(bool? Result, string? Error);

    private async Task<PredicateRun> RunPagePredicateAsync(
        LawDefinition law,
        Dictionary<string, object?> cache,
        string pageUrl,
        string pageTitle,
        IPageFactsFetcher fetcher,
        CancellationToken ct,
        Func<PageFacts, bool> predicate,
        List<string>? trace)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (var attempt = 0; attempt < 16; attempt++)
        {
            if (sw.ElapsedMilliseconds > _predicateTimeoutMs)
                return new PredicateRun(null, $"Law timed out after {_predicateTimeoutMs} ms");
            ct.ThrowIfCancellationRequested();
            var pending = new HashSet<string>(StringComparer.Ordinal);
            var facts = new PageFacts(cache, pending, pageUrl, pageTitle, trace);
            try
            {
                // Off the caller's (often UI) thread so a runaway predicate cannot freeze the browser.
                var remaining = Math.Max(1, _predicateTimeoutMs - (int)sw.ElapsedMilliseconds);
                var run = Task.Run(() => RunInvariant(() => predicate(facts)), ct);
                var result = await run.WaitAsync(TimeSpan.FromMilliseconds(remaining), ct);
                return new PredicateRun(result, null);
            }
            catch (TimeoutException)
            {
                return new PredicateRun(null, $"Law timed out after {_predicateTimeoutMs} ms");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (LawFactsPendingException)
            {
                if (pending.Count == 0)
                    return new PredicateRun(null, "Facts pending with empty selector set");

                var fetched = await fetcher.FetchAsync(pending.ToList(), ct);
                foreach (var kvp in fetched)
                    cache[kvp.Key] = kvp.Value;
            }
            catch (Exception ex)
            {
                return new PredicateRun(null, ex.Message);
            }
        }

        return new PredicateRun(null, "Too many DOM fetch rounds");
    }

    private PredicateRun RunPredicateWithTimeout(Func<bool> predicate)
    {
        var task = Task.Run(() => RunInvariant(predicate));
        if (!task.Wait(_predicateTimeoutMs))
            return new PredicateRun(null, $"Law timed out after {_predicateTimeoutMs} ms");

        if (task.IsFaulted)
            return new PredicateRun(null, task.Exception?.GetBaseException().Message ?? "Law predicate failed");

        return new PredicateRun(task.Result, null);
    }

    private async Task<LawCheckResult> ConfirmFailAsync(
        LawDefinition law,
        string pageUrl,
        string pageTitle,
        IPageFactsFetcher fetcher,
        CancellationToken ct,
        string message,
        string? evidence)
    {
        if (!law.ConfirmOnFail)
            return Fail(law, pageUrl, message, evidence);

        // Re-read the DOM after a short settle so late renders / transitions are not reported.
        await Task.Delay(ConfirmDelayMs, ct);
        var retry = await EvaluatePageCore(
            new LawDefinition
            {
                Id = law.Id,
                Name = law.Name,
                Trigger = law.Trigger,
                TriggerPattern = law.TriggerPattern,
                SiteFilter = law.SiteFilter,
                Severity = law.Severity,
                SourceFile = law.SourceFile,
                PageWhen = law.PageWhen,
                PageExpect = law.PageExpect,
                PageForbid = law.PageForbid,
                ConfirmOnFail = false
            },
            pageUrl,
            pageTitle,
            fetcher,
            ct);

        return retry.Verdict switch
        {
            LawVerdict.Fail => Fail(law, pageUrl, message, evidence ?? retry.Evidence),
            LawVerdict.Pass => Pass(law, pageUrl),
            LawVerdict.Error => Error(law, pageUrl, retry.Message ?? "Law errored on confirmation"),
            _ => NotApplicable(law, pageUrl, retry.Message ?? "Not applicable on confirmation")
        };
    }

    /// <summary>Delay before the confirmation re-read of a failing page Law.</summary>
    public int ConfirmDelayMs { get; set; } = 250;

    private static T RunInvariant<T>(Func<T> action)
    {
        var prev = CultureInfo.CurrentCulture;
        var prevUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
            CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = prev;
            CultureInfo.CurrentUICulture = prevUi;
        }
    }

    private static string Trim(string? s) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= 80 ? s : s[..77] + "...";

    private static LawCheckResult Pass(LawDefinition law, string url) =>
        Result(law, url, LawVerdict.Pass, null, null);

    private static LawCheckResult Fail(LawDefinition law, string url, string message, string? evidence) =>
        Result(law, url, LawVerdict.Fail, message, evidence);

    private static LawCheckResult NotApplicable(LawDefinition law, string url, string reason) =>
        Result(law, url, LawVerdict.NotApplicable, reason, null);

    private static LawCheckResult Error(LawDefinition law, string url, string message) =>
        Result(law, url, LawVerdict.Error, message, null);

    private static LawCheckResult Result(LawDefinition law, string url, LawVerdict verdict, string? message, string? evidence)
    {
        law.LastEvaluatedUtc = DateTime.UtcNow;
        if (verdict != LawVerdict.NotApplicable)
            law.LastVerdict = verdict;
        switch (verdict)
        {
            case LawVerdict.Pass:
                law.PassCount++;
                law.LastFailDetail = null;
                law.LastFailUrl = null;
                break;
            case LawVerdict.Fail:
                law.FailCount++;
                law.LastFailDetail = LawResultDetail.Format(message, evidence);
                law.LastFailUrl = url;
                break;
            case LawVerdict.NotApplicable: law.NotApplicableCount++; break;
        }

        return LawResultDetail.WithDetail(new LawCheckResult
        {
            LawId = law.Id,
            Name = law.Name,
            Verdict = verdict,
            Message = message,
            Evidence = evidence,
            Severity = law.Severity,
            SourceFile = law.SourceFile,
            ContextUrl = url
        });
    }
}
