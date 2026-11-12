using System.IO;
using System.Net;
using Trowser.Laws;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    internal async Task<ShadowHeavyRunReport> RunShadowHeavyOnUiAsync(CancellationToken ct = default)
    {
        var laws = _context.Laws ?? throw new InvalidOperationException("Law service not initialized.");
        Task<ShadowHeavyRunReport>? runTask = null;
        await _dispatcher.InvokeAsync(() => { runTask = laws.RunShadowHeavyAsync(ct); });
        return await runTask!;
    }

    internal async Task<LawCheckSummary> CheckLawsOnUiAsync(
        string? nameFilter,
        LawCheckScope scope,
        bool includeTraffic = false,
        CancellationToken ct = default)
    {
        var laws = _context.Laws ?? throw new InvalidOperationException("Law service not initialized.");
        Task<LawCheckSummary>? runTask = null;
        await _dispatcher.InvokeAsync(() => { runTask = laws.CheckLawsAsync(nameFilter, scope, includeTraffic, ct); });
        return await runTask!;
    }

    private async Task HandlePostShadowCheck(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (_context.Laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var report = await RunShadowHeavyOnUiAsync();
        var problems = report.Ran
            ? _context.Laws.LastResults
                .Where(r => r.Verdict is not (LawVerdict.Pass or LawVerdict.NotApplicable))
                .OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                .Select(r => new
                {
                    name = r.Name,
                    verdict = r.Verdict.ToString(),
                    severity = r.Severity.ToString(),
                    message = r.Message,
                    evidence = r.Evidence,
                    source = r.SourceFile
                })
                .ToList()
            : [];
        await WriteSuccess(response, new
        {
            message = report.SummaryLine,
            ran = report.Ran,
            skippedReason = report.SkippedReason,
            lawsEvaluated = report.LawsEvaluated,
            lawPasses = report.LawPasses,
            lawFailures = report.LawFailures,
            lawNotApplicable = report.LawNotApplicable,
            lawErrors = report.LawErrors,
            heavyQuicktestsRun = report.HeavyQuicktestsRun,
            pageUrl = report.PageUrl,
            results = problems
        });
    }

    private async Task HandleGetLaws(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var shadow = _context.SecurityShadow;
        await WriteSuccess(response, new
        {
            laws = laws.Registry.All.Select(l => new
            {
                id = l.Id,
                name = l.Name,
                trigger = l.Trigger.ToString().ToLowerInvariant(),
                pattern = l.TriggerPattern,
                severity = l.Severity.ToString().ToLowerInvariant(),
                sourceFile = l.SourceFile,
                sourceActiveForShadow = shadow?.Config.IsLawSourceActive(l.SourceFile) ?? true,
                muted = shadow?.Config.DisabledLaws.Contains(l.Id) ?? false,
                lastVerdict = l.LastVerdict?.ToString().ToLowerInvariant(),
                lastFailDetail = l.LastFailDetail,
                lastFailUrl = l.LastFailUrl,
                passCount = l.PassCount,
                failCount = l.FailCount
            }),
            activeLawSources = shadow?.Config.ActiveLawSources?.ToArray(),
            diagnostics = laws.Loader.Diagnostics.Select(d => new { file = d.SourceFile, message = d.Message })
        });
    }

    private async Task HandlePostLawsValidate(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var code = body.GetString("code") ?? "";
        var exclude = body.GetString("fileName") is { } fn && fn.Length > 0
            ? LawService.ResolveUserLawPath(fn)
            : null;
        var (ok, errors) = await laws.Loader.ValidateAgainstRegistryAsync(code, laws.Registry, exclude);
        await WriteSuccess(response, new { valid = ok, errors });
    }

    private async Task HandlePostLawsAdd(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var code = body.GetString("code") ?? "";
        var fileName = body.GetString("fileName") ?? "custom.csx";
        var (ok, error) = await laws.AppendUserLawSourceAsync(fileName, code);
        if (!ok)
        {
            await WriteSuccess(response, new { valid = false, errors = error?.Split("; ") ?? [] });
            return;
        }

        var path = LawService.ResolveUserLawPath(fileName);
        await WriteSuccess(response, new { valid = true, path, message = "Law appended." });
    }

    private async Task HandlePostLawsReplace(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var fileName = body.GetString("fileName") ?? "custom.csx";
        var code = body.GetString("code") ?? "";
        var (ok, errors, path) = await laws.ReplaceUserLawFileAsync(fileName, code);
        if (!ok)
        {
            await WriteSuccess(response, new { valid = false, errors, path });
            return;
        }

        await WriteSuccess(response, new { valid = true, path, message = "Law file replaced." });
    }

    private async Task HandlePostLawsDelete(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var fileName = body.GetString("fileName");
        var path = body.GetString("path");
        var deleted = !string.IsNullOrWhiteSpace(path)
            ? await laws.DeleteUserLawFileAsync(path)
            : !string.IsNullOrWhiteSpace(fileName)
                ? await laws.DeleteUserLawByFileNameAsync(fileName!)
                : false;

        if (!deleted)
        {
            await WriteError(response, 404, "User Law file not found or not deletable.");
            return;
        }

        await WriteSuccess(response, new { message = "Law file deleted." });
    }

    private async Task HandlePostLawsCheck(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (_context.Laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var nameFilter = body.GetString("nameFilter");
        var allLoaded = body.GetBool("allLoaded", true);
        var includeTraffic = body.GetBool("includeTraffic", false);
        var scope = allLoaded ? LawCheckScope.AllLoaded : LawCheckScope.ScriptConsoleDeclared;
        var summary = await CheckLawsOnUiAsync(nameFilter, scope, includeTraffic);
        await WriteSuccess(response, new
        {
            passed = summary.Passed,
            failed = summary.Failed,
            notApplicable = summary.NotApplicable,
            errors = summary.Errors,
            skipped = summary.Skipped,
            responseEntriesChecked = summary.ResponseEntriesChecked,
            consoleEntriesChecked = summary.ConsoleEntriesChecked,
            results = summary.Results.Select(r => new
            {
                id = r.LawId,
                name = r.Name,
                verdict = r.Verdict.ToString().ToLowerInvariant(),
                severity = r.Severity.ToString().ToLowerInvariant(),
                detail = r.Detail,
                message = r.Message,
                evidence = r.Evidence,
                sourceFile = r.SourceFile,
                url = r.ContextUrl
            })
        });
    }

    private async Task HandleGetLawProposals(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        await WriteSuccess(response, new
        {
            proposals = laws.Proposals.Proposals.Select(p => new
            {
                id = p.Id,
                title = p.Title,
                source = p.Source,
                kind = p.Kind,
                observations = p.Observations,
                counterexamples = p.Counterexamples,
                rationale = p.Rationale,
                evidence = p.Evidence,
                code = p.Code
            })
        });
    }

    private async Task HandlePostLawProposalAccept(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var id = body.GetString("id") ?? "";
        var proposal = laws.Proposals.Accept(id);
        if (proposal == null)
        {
            await WriteError(response, 404, "Proposal not found");
            return;
        }

        var path = await laws.AppendProposalToUserLawsAsync(proposal);
        await WriteSuccess(response, new { path, message = "Proposal accepted into user Laws." });
    }

    private async Task HandlePostLawProposalReject(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var id = body.GetString("id") ?? "";
        if (string.IsNullOrWhiteSpace(id))
        {
            await WriteError(response, 400, "Provide \"id\" of the proposal to reject.");
            return;
        }

        if (!laws.Proposals.Reject(id))
        {
            await WriteError(response, 404, "Proposal not found");
            return;
        }

        await WriteSuccess(response, new { message = "Proposal rejected." });
    }

    private async Task HandlePostLawsAuthor(HttpListenerRequest request, HttpListenerResponse response)
    {
        var laws = _context.Laws;
        if (laws == null)
        {
            await WriteError(response, 500, "Law service not initialized");
            return;
        }

        var body = await ReadJsonBody(request);
        var mode = body.GetString("mode") ?? "author";
        var author = laws.CreateAuthor();

        switch (mode.ToLowerInvariant())
        {
            case "fromfinding":
            {
                if (!body.HasProperty("fromFinding") && !body.HasProperty("findingId"))
                {
                    await WriteError(response, 400, "fromFinding (finding id) is required for mode fromfinding.");
                    return;
                }

                var findingId = body.HasProperty("fromFinding")
                    ? body.GetInt("fromFinding")
                    : body.GetInt("findingId");
                if (findingId <= 0)
                {
                    await WriteError(response, 400, "fromFinding must be a positive finding id.");
                    return;
                }

                var shadow = _context.SecurityShadow;
                if (shadow == null)
                {
                    await WriteError(response, 500, "Shadow is not initialized.");
                    return;
                }

                var finding = shadow.GetFindings().FirstOrDefault(f => f.Id == findingId);
                if (finding == null)
                {
                    await WriteError(response, 404, $"Finding {findingId} not found.");
                    return;
                }

                var code = LawCodeGenerator.FromFinding(finding);
                var (valid, errors) = await laws.Loader.ValidateAgainstRegistryAsync(code, laws.Registry);
                await WriteSuccess(response, new { valid, code, errors, findingId = finding.Id, title = finding.Title });
                return;
            }
            case "explain":
            {
                var lawName = body.GetString("lawName") ?? body.GetString("name") ?? "Law";
                var detail = body.GetString("detail") ?? body.GetString("failure") ?? body.GetString("text") ?? "";
                var (ok, explanation, error) = await author.ExplainViolationAsync(lawName, detail);
                if (!ok)
                    await WriteError(response, 400, error ?? "Explain failed.");
                else
                    await WriteSuccess(response, new { explanation });
                return;
            }
            case "refine":
            {
                var code = body.GetString("code") ?? "";
                var notes = body.GetString("notes");
                var (ok, refined, errors) = string.IsNullOrWhiteSpace(notes)
                    ? await author.RefineAsync(code)
                    : await author.RefineMinedProposalAsync(code, notes);
                await WriteSuccess(response, new { valid = ok, code = refined, errors });
                return;
            }
            case "context":
            {
                var context = body.GetString("context") ?? body.GetString("text") ?? "";
                var (ok, code, errors) = await author.ProposeFromContextAsync(context);
                await WriteSuccess(response, new { valid = ok, code, errors });
                return;
            }
            default:
            {
                var text = body.GetString("text") ?? body.GetString("prompt") ?? "";
                var (ok, code, errors) = await author.AuthorAsync(text);
                await WriteSuccess(response, new { valid = ok, code, errors });
                return;
            }
        }
    }
}
