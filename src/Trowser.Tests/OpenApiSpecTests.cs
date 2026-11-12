using System.IO;
using System.Text.RegularExpressions;
using Microsoft.OpenApi.Models;
using Microsoft.OpenApi.Readers;
using Xunit;

namespace Trowser.Tests;

public class OpenApiSpecTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Trowser.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static OpenApiDocument LoadSpec()
    {
        var path = Path.Combine(RepoRoot(), "trowserkit", "swagger", "openapi.yaml");
        using var stream = File.OpenRead(path);
        var reader = new OpenApiStreamReader();
        var doc = reader.Read(stream, out var diagnostic);
        Assert.True(!diagnostic.Errors.Any(), "OpenAPI parse errors: " + string.Join("; ", diagnostic.Errors.Select(e => e.Message)));
        return doc;
    }

    private static HashSet<(string Method, string Path)> IndexRestOps()
    {
        var indexPath = Path.Combine(RepoRoot(), "trowserkit", "trowser-api-index.md");
        var text = File.ReadAllText(indexPath);
        var row = new Regex(@"\| (GET|POST|PUT|DELETE|PATCH) \| `(/api/[^`]+)`", RegexOptions.Compiled);
        return row.Matches(text).Select(m => (m.Groups[1].Value, m.Groups[2].Value)).ToHashSet();
    }

    private static HashSet<(string Method, string Path)> SpecRestOps(OpenApiDocument doc)
    {
        var set = new HashSet<(string, string)>();
        foreach (var (path, item) in doc.Paths)
        {
            foreach (var op in item.Operations)
                set.Add((op.Key.ToString().ToUpperInvariant(), path));
        }
        return set;
    }

    private static bool IsStubOperation(OpenApiOperation op)
    {
        if (op.Responses == null || !op.Responses.TryGetValue("200", out var ok) ||
            ok.Description != "Success")
            return false;

        if (ok.Content != null && ok.Content.Count > 0)
            return false;

        if (op.RequestBody?.Content == null)
            return op.RequestBody == null;

        if (op.RequestBody.Content.TryGetValue("application/json", out var media) &&
            media.Schema?.Type == "object" &&
            (media.Schema.Properties == null || media.Schema.Properties.Count == 0) &&
            (media.Schema.Required == null || media.Schema.Required.Count == 0))
            return true;

        return false;
    }

    [Fact]
    public void Spec_matches_api_index_rest_operations()
    {
        var doc = LoadSpec();
        var spec = SpecRestOps(doc);
        var index = IndexRestOps();
        var missingInSpec = index.Except(spec).OrderBy(x => x).ToList();
        Assert.True(missingInSpec.Count == 0, "Index ops missing from openapi.yaml:\n" + string.Join("\n", missingInSpec));
    }

    [Fact]
    public void OperationIds_are_unique()
    {
        var doc = LoadSpec();
        var ids = doc.Paths.SelectMany(p => p.Value.Operations.Values.Select(o => o.OperationId)).Where(id => id != null).ToList();
        var dupes = ids.GroupBy(i => i!).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.True(dupes.Count == 0, "Duplicate operationIds: " + string.Join(", ", dupes));
    }

    [Fact]
    public void Stub_operation_count_does_not_exceed_baseline()
    {
        var doc = LoadSpec();
        var stubCount = doc.Paths.SelectMany(p => p.Value.Operations.Values).Count(IsStubOperation);
        var baselinePath = Path.Combine(RepoRoot(), "tests", "baselines", "openapi-stubs.txt");
        var baseline = int.Parse(File.ReadAllText(baselinePath).Trim());
        Assert.True(stubCount <= baseline,
            $"OpenAPI stub count {stubCount} exceeds baseline {baseline}. Add real schemas or bump the baseline intentionally.");
    }
}
