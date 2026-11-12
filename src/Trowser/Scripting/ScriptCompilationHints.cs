using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;

namespace Trowser.Scripting;

/// <summary>
/// Post-processes Roslyn script compilation errors to surface clearer guidance for common mistakes
/// (especially missing <c>await</c> on Task-returning automation methods).
/// </summary>
internal static class ScriptCompilationHints
{
    private static readonly Regex TaskTypeInMessage = new(
        @"Task<[^>]+>|\bTask\b",
        RegexOptions.Compiled);

    private static readonly string[] AsyncAutomationMethods =
    [
        "Navigate", "GoBack", "GoForward", "GetCurrentUrl", "GetTitle", "GetPageSource",
        "GetPageText", "GetAllPageText", "GetScreenReaderTexts", "GetText", "GetAttribute",
        "GetProperty", "GetMetaContent", "IsChecked", "Exists", "Count", "Click", "Type",
        "Select", "Hover", "PressKey", "Scroll", "WaitForElement", "WaitForIdle",
        "WaitForNavigation", "WaitForFinalNavigation", "ExecuteJs", "ExecuteJsAsync",
        "Fetch", "Screenshot", "ScreenshotElement", "HandleDialog", "GetDialog",
        "AssertAccessible", "AssertCompatible", "AssertPageContains", "AssertPageNotContains",
        "AssertElementVisible", "AssertElementNotVisible", "AssertElementText",
        "AssertElementContainsText", "AssertElementAttribute", "AssertUrl", "AssertTitle",
        "AssertElementCount", "ClearConsoleLog", "ClearNetworkLog", "ClearAll", "ClearSession",
        "AddDocumentCreatedScriptAsync", "RemoveDocumentCreatedScriptAsync", "GetCookieHeaderForUrl",
        "PurgeNonAsciiCookiesAsync", "SetViewport", "SetNetworkThrottle", "ClearNetworkThrottle",
        "MockAdd", "MockRemove", "InterceptAdd", "InterceptContinue", "InterceptFulfill",
        "InterceptAbort", "RunAccessibilityAudit", "RunPerformanceAudit", "RunHtmlValidation",
        "CheckResourceSnapshot", "PrintResourceSnapshot", "CompareResourceUsage", "PrintResourceComparisonReport",
        "AssertResourceClean", "AssertResourceCleanSince", "RunResourceProbe", "PrintResourceProbeReport",
        "RunSeoAudit", "RunSecurityAudit", "RunCompatibilityCheck", "RunLinkCheck",
        "Extract", "DiffState", "TabOrder", "SendMessage", "JournalAdd",
        "PeerFetch", "AuthzDiff", "LaunchPeer"
    ];

    public static string FormatDiagnostics(string code, IEnumerable<Diagnostic> diagnostics)
    {
        var diagList = diagnostics.ToList();
        var lines = diagList.Select(d => d.ToString()).ToList();
        var hints = CollectHints(code, diagList);
        if (hints.Count == 0)
            return string.Join(Environment.NewLine, lines);

        lines.Add("");
        lines.AddRange(hints);
        return string.Join(Environment.NewLine, lines);
    }

    private static List<string> CollectHints(string code, IReadOnlyList<Diagnostic> diagnostics)
    {
        var taskRelated = diagnostics.Where(d =>
            d.Severity == DiagnosticSeverity.Error &&
            d.Id is "CS1929" or "CS1503" or "CS0029" or "CS1061" &&
            TaskTypeInMessage.IsMatch(d.GetMessage())).ToList();

        if (taskRelated.Count == 0)
            return [];

        var hints = new HashSet<string>(StringComparer.Ordinal);
        var sourceLines = code.Replace("\r\n", "\n").Split('\n');

        foreach (var diagnostic in taskRelated)
        {
            var span = diagnostic.Location.SourceSpan;
            if (span.Start >= 0 && span.Start < code.Length)
            {
                var lineIndex = diagnostic.Location.GetLineSpan().StartLinePosition.Line;
                if (lineIndex >= 0 && lineIndex < sourceLines.Length)
                {
                    foreach (var method in FindUnawaitedCalls(sourceLines[lineIndex]))
                        hints.Add($"Hint: Did you forget to await {method}()? Trowser automation methods return Task and must be awaited.");
                }
            }
        }

        if (hints.Count == 0)
        {
            hints.Add("Hint: Trowser automation methods return Task and must be awaited.");
            hints.Add("Example: var url = await GetCurrentUrl();  — not: var url = GetCurrentUrl();");
        }

        return hints.ToList();
    }

    private static IEnumerable<string> FindUnawaitedCalls(string line)
    {
        foreach (var method in AsyncAutomationMethods)
        {
            if (Regex.IsMatch(line, $@"(?<!\bawait\s){Regex.Escape(method)}\s*\("))
                yield return method;
        }
    }
}
