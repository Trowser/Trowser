using System.IO;
using System.Reflection;
using Trowser.Laws;

namespace Trowser.Automation;

public partial class AutomationContext
{
    /// <summary>
    /// Runs embedded quicktest C# script code with the same globals as the parent script.
    /// Set by <see cref="Scripting.ScriptEngine"/> at construction time.
    /// </summary>
    public Func<string, CancellationToken, Task>? NestedQuicktestRunner { get; set; }

    /// <summary>Name of the quicktest chosen by the most recent <see cref="SurpriseMe"/> call.</summary>
    public string? LastSurpriseQuicktest { get; private set; }

    /// <summary>
    /// Runs a randomly chosen non-destructive quicktest from the embedded Quicktests catalog.
    /// Category folders are balanced so Security does not dominate the pool.
    /// Eligibility uses quicktest <c>@effects</c> metadata (read-only scripts only).
    /// </summary>
    public async Task<string> SurpriseMe()
    {
        if (NestedQuicktestRunner == null)
            throw new InvalidOperationException("Nested quicktest execution is not available.");

        const string prefix = "Trowser.Resources.Quicktests.";
        var assembly = Assembly.GetExecutingAssembly();

        var candidates = new List<(string ResourceName, string Leaf, string Category)>();
        foreach (var n in assembly.GetManifestResourceNames())
        {
            if (!n.StartsWith(prefix, StringComparison.Ordinal) || !n.EndsWith(".csx"))
                continue;
            await using var stream = assembly.GetManifestResourceStream(n);
            if (stream == null) continue;
            using var reader = new StreamReader(stream);
            var code = await reader.ReadToEndAsync(ScriptCancellation);
            var relative = n[prefix.Length..^4];
            var parts = relative.Split('.');
            var leaf = parts[^1];
            if (leaf.Equals("SurpriseMe", StringComparison.OrdinalIgnoreCase))
                continue;
            var meta = QuicktestMetadata.Parse(code, n, leaf);
            if (!meta.IsReadOnlyEffects)
                continue;
            var category = parts.Length > 1 ? parts[0] : "General";
            candidates.Add((n, leaf, category));
        }

        if (candidates.Count == 0)
            throw new InvalidOperationException("No eligible quicktests found for SurpriseMe.");

        var categories = candidates.GroupBy(c => c.Category).ToList();
        var categoryGroup = categories[Random.Shared.Next(categories.Count)];
        var chosen = categoryGroup.ElementAt(Random.Shared.Next(categoryGroup.Count()));

        LastSurpriseQuicktest = chosen.Leaf;
        Log($"Surprise! Running: {chosen.Leaf}");

        await using var stream2 = assembly.GetManifestResourceStream(chosen.ResourceName)
            ?? throw new InvalidOperationException($"Quicktest resource not found: {chosen.ResourceName}");
        using var reader2 = new StreamReader(stream2);
        var code2 = await reader2.ReadToEndAsync(ScriptCancellation);

        await NestedQuicktestRunner(code2, ScriptCancellation);
        return chosen.Leaf;
    }
}
