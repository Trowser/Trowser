using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;

namespace Trowser.Laws;

public sealed class LawCompileDiagnostic
{
    public required string SourceFile { get; init; }
    public required string Message { get; init; }
}

public sealed class LawLoader
{
    private readonly LawRegistry _registry;
    private readonly LawDeclarationContext _declarationContext;
    private readonly ScriptOptions _options;
    private readonly ConcurrentDictionary<string, string> _hashByFile = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _diagLock = new();
    private readonly List<LawCompileDiagnostic> _diagnostics = [];
    private readonly SemaphoreSlim _loadGate = new(1, 1);

    public LawLoader(LawRegistry registry)
    {
        _registry = registry;
        _declarationContext = new LawDeclarationContext(registry);
        _options = ScriptOptions.Default
            .AddReferences(
                typeof(LawDeclarationContext).Assembly,
                typeof(object).Assembly,
                typeof(System.Linq.Enumerable).Assembly,
                typeof(System.Text.Json.JsonSerializer).Assembly)
            .AddImports(
                "System",
                "System.Collections.Generic",
                "System.Linq",
                "System.Text.Json",
                "System.Text.RegularExpressions",
                "Trowser.Laws",
                "Trowser.Security",
                "Trowser.Automation");
    }

    public IReadOnlyList<LawCompileDiagnostic> Diagnostics
    {
        get
        {
            lock (_diagLock)
                return _diagnostics.ToList();
        }
    }

    public void ForgetFile(string path)
    {
        _hashByFile.TryRemove(path, out _);
        ClearDiagnosticsFor(path);
    }

    public async Task<bool> LoadFileAsync(string path, CancellationToken ct = default)
    {
        if (!File.Exists(path))
        {
            AddDiagnostic(path, "File not found.");
            return false;
        }

        var code = await File.ReadAllTextAsync(path, ct);
        return await LoadSourceAsync(path, code, ct);
    }

    public async Task<bool> LoadSourceAsync(string sourceFile, string code, CancellationToken ct = default)
    {
        await _loadGate.WaitAsync(ct);
        try
        {
            var hash = ComputeHash(code);
            if (_hashByFile.TryGetValue(sourceFile, out var prev) && prev == hash)
                return true;

            ClearDiagnosticsFor(sourceFile);

            // Never execute code that failed compile or sandbox checks. The last good version
            // of this file stays loaded so a typo while editing does not silently drop its Laws.
            var (script, errors) = Prepare(code);
            if (script == null)
            {
                foreach (var e in errors)
                    AddDiagnostic(sourceFile, e);
                return false;
            }

            _registry.RemoveSource(sourceFile);
            _declarationContext.BeginFile(sourceFile);
            try
            {
                await RunInvariantAsync(script, _declarationContext, ct);
            }
            catch (Exception ex)
            {
                _registry.RemoveSource(sourceFile);
                _hashByFile.TryRemove(sourceFile, out _);
                AddDiagnostic(sourceFile, ex.GetBaseException().Message);
                return false;
            }

            _hashByFile[sourceFile] = hash;
            return true;
        }
        finally
        {
            _loadGate.Release();
        }
    }

    public async Task<(bool ok, IReadOnlyList<string> errors)> ValidateAsync(string code, CancellationToken ct = default)
    {
        var (ok, errors, _) = await DeclareIntoTempRegistryAsync(code, "(validate)", ct);
        return (ok, errors);
    }

    /// <summary>Compile-check and ensure Law names do not collide with already-loaded definitions.</summary>
    public async Task<(bool ok, IReadOnlyList<string> errors)> ValidateAgainstRegistryAsync(
        string code,
        LawRegistry globalRegistry,
        string? excludeSourceFile = null,
        CancellationToken ct = default)
    {
        var (ok, errors, temp) = await DeclareIntoTempRegistryAsync(code, excludeSourceFile ?? "(validate)", ct);
        if (!ok)
            return (false, errors);

        var merged = new List<string>();
        foreach (var law in temp.All)
        {
            var conflict = globalRegistry.FindNameConflict(law, excludeSourceFile);
            if (conflict != null)
                merged.Add($"Duplicate Law name '{law.Name}' (already declared in {conflict}).");
        }

        return (merged.Count == 0, merged);
    }

    private async Task<(bool ok, List<string> errors, LawRegistry registry)> DeclareIntoTempRegistryAsync(
        string code,
        string sourceFile,
        CancellationToken ct)
    {
        var temp = new LawRegistry();
        var (script, errors) = Prepare(code);
        if (script == null)
            return (false, errors, temp);

        try
        {
            var ctx = new LawDeclarationContext(temp);
            ctx.BeginFile(sourceFile);
            await RunInvariantAsync(script, ctx, ct);
        }
        catch (Exception ex)
        {
            errors.Add(ex.GetBaseException().Message);
        }

        return (errors.Count == 0, errors, temp);
    }

    /// <summary>Compile once and run syntactic + semantic sandbox checks. Returns null when the code must not run.</summary>
    private (Script<object>? script, List<string> errors) Prepare(string code)
    {
        var errors = new List<string>(LawBannedApiChecker.FindViolations(code));
        var script = CSharpScript.Create(code, _options, typeof(LawDeclarationContext));
        var compilation = script.GetCompilation();
        var compileErrors = compilation.GetDiagnostics()
            .Where(d => d.Severity == Microsoft.CodeAnalysis.DiagnosticSeverity.Error)
            .Select(d => d.ToString())
            .ToList();
        errors.AddRange(compileErrors);
        if (compileErrors.Count == 0)
            errors.AddRange(LawSandbox.FindViolations(compilation));

        return (errors.Count == 0 ? script : null, errors);
    }

    private static async Task RunInvariantAsync(Script<object> script, LawDeclarationContext globals, CancellationToken ct)
    {
        var prevCulture = CultureInfo.CurrentCulture;
        var prevUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
            CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;
            await script.RunAsync(globals, ct);
        }
        finally
        {
            CultureInfo.CurrentCulture = prevCulture;
            CultureInfo.CurrentUICulture = prevUi;
        }
    }

    private void AddDiagnostic(string file, string message)
    {
        lock (_diagLock)
            _diagnostics.Add(new LawCompileDiagnostic { SourceFile = file, Message = message });
    }

    private void ClearDiagnosticsFor(string file)
    {
        lock (_diagLock)
            _diagnostics.RemoveAll(d => d.SourceFile.Equals(file, StringComparison.OrdinalIgnoreCase));
    }

    private static string ComputeHash(string code)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        return Convert.ToHexString(bytes);
    }
}
