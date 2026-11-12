using System.IO;
using System.Reflection;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using Trowser.Automation;
using Trowser.Laws;
using Trowser.Scripting;
using Xunit;

namespace Trowser.Tests;

/// <summary>Embedded quicktests and offline regression scripts must compile against the scripting surface.</summary>
public class ScriptCompileTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Trowser.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static void AssertCompiles(string code, string label)
    {
        var script = CSharpScript.Create(code, ScriptEngine.CreateDefaultScriptOptions(), typeof(AutomationContext));
        var diagnostics = script.Compile();
        var errors = diagnostics.Where(d => d.Severity == Microsoft.CodeAnalysis.DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, $"{label} compile errors:\n" + string.Join("\n", errors.Select(e => e.ToString())));
    }

    public static IEnumerable<object[]> EmbeddedQuicktests()
    {
        var asm = typeof(QuicktestCatalog).Assembly;
        foreach (var meta in QuicktestCatalog.Embedded)
        {
            using var stream = asm.GetManifestResourceStream(meta.ResourceName);
            Assert.NotNull(stream);
            using var reader = new StreamReader(stream);
            yield return new object[] { meta.Leaf, reader.ReadToEnd() };
        }
    }

    [Theory]
    [MemberData(nameof(EmbeddedQuicktests))]
    public void Embedded_quicktest_compiles(string leaf, string code) => AssertCompiles(code, $"Quicktest {leaf}");

    [Fact]
    public void User_example_quicktest_compiles()
    {
        var path = Path.Combine(RepoRoot(), "src", "Trowser", "Resources", "UserQuicktests", "ExampleQuicktest.csx");
        Assert.True(File.Exists(path));
        AssertCompiles(File.ReadAllText(path), "ExampleQuicktest");
    }

    public static IEnumerable<object[]> RegressionScripts()
    {
        var root = Path.Combine(RepoRoot(), "tests", "regression");
        var prelude = File.ReadAllText(Path.Combine(root, "_prelude.csx"));
        foreach (var dir in new[] { "functional", "security" })
        {
            var folder = Path.Combine(root, dir);
            if (!Directory.Exists(folder)) continue;
            foreach (var file in Directory.GetFiles(folder, "*.csx").OrderBy(f => f))
            {
                var body = File.ReadAllText(file);
                var combined = prelude + "\n\n// TEST\n" + body;
                yield return new object[] { Path.GetFileName(file), combined };
            }
        }
    }

    [Theory]
    [MemberData(nameof(RegressionScripts))]
    public void Regression_script_compiles(string name, string code) => AssertCompiles(code, $"Regression {name}");
}
