using System.Diagnostics;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using Trowser.Automation;

namespace Trowser.Scripting;

/// <summary>
/// Result of a script execution.
/// </summary>
public class ScriptResult
{
    public bool Success { get; init; }
    public bool IsCancelled { get; init; }
    public object? ReturnValue { get; init; }
    public string? Error { get; init; }
    public long ElapsedMs { get; init; }
}

/// <summary>
/// Roslyn-based C# script engine that executes scripts with AutomationContext as the global scope.
/// Scripts can call methods like Navigate(), Click(), Type() etc. directly.
/// </summary>
public class ScriptEngine
{
    private readonly AutomationContext _context;
    private readonly ScriptOptions _scriptOptions;

    public ScriptEngine(AutomationContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _scriptOptions = CreateDefaultScriptOptions();

        _context.NestedQuicktestRunner = (code, ct) =>
            CSharpScript.RunAsync(code, _scriptOptions, _context, typeof(AutomationContext), ct);
    }

    /// <summary>Roslyn options for embedded/regression scripts (shared with compile-only tests).</summary>
    public static ScriptOptions CreateDefaultScriptOptions() =>
        ScriptOptions.Default
            .AddReferences(
                typeof(AutomationContext).Assembly,
                typeof(object).Assembly,
                typeof(System.Console).Assembly,
                typeof(System.Text.Json.JsonSerializer).Assembly,
                typeof(System.Text.RegularExpressions.Regex).Assembly
            )
            .AddImports(
                "System",
                "System.Collections.Generic",
                "System.Linq",
                "System.Text",
                "System.Text.Json",
                "System.Text.RegularExpressions",
                "System.Threading",
                "System.Threading.Tasks",
                "Trowser.Automation",
                "Trowser.Accessibility",
                "Trowser.Consistency",
                "Trowser.HtmlValidation",
                "Trowser.LinkChecking",
                "Trowser.Performance",
                "Trowser.ResourceUsage",
                "Trowser.Robustness",
                "Trowser.Security",
                "Trowser.EndpointProbe",
                "Trowser.Testing",
                "Trowser.TextExtraction",
                "Trowser.ThirdParty",
                "Trowser.XssAudit",
                "Trowser.MixedContent",
                "Trowser.SessionLog",
                "Trowser.Laws",
                "System.Net"
            );

    /// <summary>
    /// Execute a C# script with the AutomationContext as the global scope.
    /// All public methods/properties of AutomationContext are available directly in the script.
    /// Pass a CancellationToken to allow stopping the script mid-execution.
    /// Optional <paramref name="runControl"/> enables pause/resume from the script console UI.
    /// </summary>
    public async Task<ScriptResult> ExecuteAsync(
        string code,
        CancellationToken cancellationToken = default,
        ScriptRunControl? runControl = null)
    {
        var ownsControl = runControl == null;
        runControl ??= new ScriptRunControl();
        if (cancellationToken.CanBeCanceled)
            cancellationToken.Register(() => runControl.Stop());

        _context.ScriptRunControl = runControl;
        _context.ScriptCancellation = runControl.StopToken;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var result = await CSharpScript.RunAsync(
                code,
                _scriptOptions,
                globals: _context,
                globalsType: typeof(AutomationContext),
                cancellationToken: runControl.StopToken);

            stopwatch.Stop();

            return new ScriptResult
            {
                Success = true,
                ReturnValue = result.ReturnValue,
                ElapsedMs = stopwatch.ElapsedMilliseconds
            };
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new ScriptResult
            {
                Success = false,
                IsCancelled = true,
                Error = "Script cancelled",
                ElapsedMs = stopwatch.ElapsedMilliseconds
            };
        }
        catch (CompilationErrorException ex)
        {
            stopwatch.Stop();

            var errors = ScriptCompilationHints.FormatDiagnostics(code, ex.Diagnostics);

            return new ScriptResult
            {
                Success = false,
                Error = $"Compilation error:\n{errors}",
                ElapsedMs = stopwatch.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();

            var innerEx = ex;
            while (innerEx is AggregateException agg && agg.InnerException != null)
            {
                innerEx = agg.InnerException;
            }

            if (innerEx is OperationCanceledException)
            {
                return new ScriptResult
                {
                    Success = false,
                    IsCancelled = true,
                    Error = "Script cancelled",
                    ElapsedMs = stopwatch.ElapsedMilliseconds
                };
            }

            return new ScriptResult
            {
                Success = false,
                Error = $"{innerEx.GetType().Name}: {innerEx.Message}",
                ElapsedMs = stopwatch.ElapsedMilliseconds
            };
        }
        finally
        {
            _context.ScriptRunControl = null;
            _context.ScriptCancellation = CancellationToken.None;
            _context.This = null;
            if (ownsControl)
                runControl.Dispose();
            GC.Collect(2, GCCollectionMode.Optimized, blocking: false);
        }
    }
}
