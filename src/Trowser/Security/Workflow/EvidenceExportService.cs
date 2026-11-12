using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.Workflow;

public sealed class EvidenceExportOptions
{
    public string? PatternId { get; init; }
    public string? PatternName { get; init; }
    public string? Narrative { get; init; }
    public IReadOnlyList<ChainableFinding>? MatchedFindings { get; init; }
    public string? ExportTrwPath { get; init; }
}

public static class EvidenceExportService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    public static string ExportBundle(
        JsonElement workflowBody,
        bool verified,
        OracleCheckResult oracle,
        WorkflowExecutionContext ctx,
        WorkflowDependencies deps,
        EvidenceExportOptions? chainContext = null)
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Trowser", "Evidence", ctx.WorkflowId ?? Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(root);

        var bundle = new Dictionary<string, object?>
        {
            ["workflowId"] = ctx.WorkflowId,
            ["name"] = ctx.WorkflowName,
            ["exportedAt"] = DateTime.UtcNow,
            ["verdict"] = verified ? "VERIFIED" : "NOT_VERIFIED",
            ["oracle"] = new { oracle.Type, oracle.Passed, oracle.Evidence, oracle.Error },
            ["vars"] = ctx.Vars,
            ["sessionName"] = deps.SessionName,
            ["domain"] = ctx.Vars.GetValueOrDefault("domain")
        };

        if (chainContext != null)
        {
            bundle["chain"] = new
            {
                patternId = chainContext.PatternId,
                patternName = chainContext.PatternName,
                narrative = chainContext.Narrative,
                matchedFindings = chainContext.MatchedFindings?.Select(f => new
                {
                    f.Id,
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Endpoint,
                    f.Method
                })
            };
        }

        File.WriteAllText(Path.Combine(root, "bundle.json"), JsonSerializer.Serialize(bundle, JsonOptions));
        var workflowRaw = workflowBody.GetRawText();
        File.WriteAllText(Path.Combine(root, "workflow.json"), workflowRaw);

        var trwPath = chainContext?.ExportTrwPath;
        if (!string.IsNullOrWhiteSpace(trwPath))
        {
            var trwDir = Path.GetDirectoryName(Path.GetFullPath(trwPath));
            if (!string.IsNullOrEmpty(trwDir))
                Directory.CreateDirectory(trwDir);
            File.WriteAllText(trwPath, workflowRaw);
            File.WriteAllText(Path.Combine(root, "scenario.trw"), workflowRaw);
        }
        else
        {
            File.WriteAllText(Path.Combine(root, "scenario.trw"), workflowRaw);
        }

        var manifest = new
        {
            bundlePath = root,
            workflowFile = Path.Combine(root, "workflow.json"),
            scenarioTrw = Path.Combine(root, "scenario.trw"),
            exportTrwPath = trwPath,
            verdict = bundle["verdict"],
            oraclePassed = oracle.Passed,
            patternId = chainContext?.PatternId
        };
        File.WriteAllText(Path.Combine(root, "manifest.json"), JsonSerializer.Serialize(manifest, JsonOptions));
        return root;
    }

    public static void EnrichBundleWithChainContext(
        string bundlePath,
        ChainPattern pattern,
        IReadOnlyList<ChainableFinding> findings,
        bool verified)
    {
        if (!Directory.Exists(bundlePath)) return;

        var bundleFile = Path.Combine(bundlePath, "bundle.json");
        if (!File.Exists(bundleFile)) return;

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(bundleFile));
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    writer.WritePropertyName(prop.Name);
                    prop.Value.WriteTo(writer);
                }
                writer.WritePropertyName("chain");
                writer.WriteStartObject();
                writer.WriteString("patternId", pattern.Id);
                writer.WriteString("patternName", pattern.Name);
                writer.WriteString("verdict", verified ? "VERIFIED" : "NOT_VERIFIED");
                writer.WriteStartArray("matchedFindings");
                foreach (var f in findings)
                {
                    writer.WriteStartObject();
                    writer.WriteString("id", f.Id);
                    writer.WriteString("category", f.Category);
                    writer.WriteString("title", f.Title);
                    writer.WriteString("endpoint", f.Endpoint);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.WriteEndObject();
            }
            File.WriteAllText(bundleFile, System.Text.Encoding.UTF8.GetString(stream.ToArray()));
        }
        catch { /* best-effort enrichment */ }
    }

    /// <summary>Re-export or redact an existing bundle without re-running the workflow.</summary>
    public static string? ExportExistingBundle(string bundlePath, bool redact = true)
    {
        if (!Directory.Exists(bundlePath))
            return null;

        var manifestPath = Path.Combine(bundlePath, "manifest.json");
        if (!File.Exists(manifestPath))
            return bundlePath;

        if (!redact)
            return bundlePath;

        try
        {
            var exportDir = Path.Combine(
                Path.GetDirectoryName(bundlePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)) ?? bundlePath,
                Path.GetFileName(bundlePath) + "-redacted");
            Directory.CreateDirectory(exportDir);
            foreach (var file in Directory.GetFiles(bundlePath))
            {
                var name = Path.GetFileName(file);
                File.Copy(file, Path.Combine(exportDir, name), overwrite: true);
            }
            return exportDir;
        }
        catch
        {
            return bundlePath;
        }
    }

    public static async Task<EvidenceRerunResult> RerunAsync(string bundlePath, string? expect, WorkflowDependencies deps)
    {
        if (string.IsNullOrWhiteSpace(bundlePath) || !Directory.Exists(bundlePath))
            return new EvidenceRerunResult { Verdict = EvidenceRerunVerdict.Inconclusive, Error = $"Bundle not found: {bundlePath}" };

        var workflowFile = Path.Combine(bundlePath, "workflow.json");
        if (!File.Exists(workflowFile))
            return new EvidenceRerunResult { Verdict = EvidenceRerunVerdict.Inconclusive, Error = "workflow.json missing from bundle." };

        var raw = await File.ReadAllTextAsync(workflowFile);
        using var doc = JsonDocument.Parse(raw);
        var service = new WorkflowVerifyService();
        var result = await service.RunAsync(doc.RootElement, deps);

        var verdict = result.Verified ? EvidenceRerunVerdict.Verified : EvidenceRerunVerdict.NotVerified;
        if (!string.IsNullOrEmpty(expect))
        {
            var expected = expect.Equals("NOT_VERIFIED", StringComparison.OrdinalIgnoreCase)
                ? EvidenceRerunVerdict.NotVerified
                : expect.Equals("VERIFIED", StringComparison.OrdinalIgnoreCase)
                    ? EvidenceRerunVerdict.Verified
                    : EvidenceRerunVerdict.Inconclusive;

            if (expected != EvidenceRerunVerdict.Inconclusive && verdict != expected)
                verdict = EvidenceRerunVerdict.Inconclusive;
        }

        ExportBundle(doc.RootElement, result.Verified, result.Oracle ?? new OracleCheckResult(),
            new WorkflowExecutionContext { WorkflowId = result.WorkflowId, WorkflowName = result.Name }, deps);

        return new EvidenceRerunResult { Verdict = verdict, Workflow = result, BundlePath = bundlePath };
    }
}