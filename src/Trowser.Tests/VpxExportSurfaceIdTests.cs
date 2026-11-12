using Trowser.Security.ChainEngine;
using Trowser.Security.Vpx;
using Xunit;

namespace Trowser.Tests;

public class VpxExportSurfaceIdTests
{
    [Fact]
    public void trailing_slash_variants_share_one_surface_and_do_not_throw()
    {
        var doc = Export(
            ("h1", "https://lab.example/admin", "GET"),
            ("h2", "https://lab.example/admin/", "GET"),
            ("h3", "/admin", "GET"));

        var surfaces = Surfaces(doc);
        Assert.Single(surfaces);
        Assert.Equal("surf-get-admin", (string?)surfaces[0]["id"]);
        Assert.Equal("/admin", (string?)surfaces[0]["route"]);

        foreach (var finding in Findings(doc))
            Assert.Equal("surf-get-admin", (string?)finding["surfaceId"]);
    }

    [Fact]
    public void double_slash_and_query_variants_share_one_surface()
    {
        var doc = Export(
            ("h1", "https://lab.example/foo/bar", "GET"),
            ("h2", "https://lab.example/foo//bar", "GET"),
            ("h3", "/foo/bar?x=1", "GET"));

        var surfaces = Surfaces(doc);
        Assert.Single(surfaces);
        Assert.Equal("surf-get-foo-bar", (string?)surfaces[0]["id"]);
    }

    [Fact]
    public void slug_collisions_get_unique_ids_instead_of_throwing()
    {
        var doc = Export(
            ("h1", "/users/{id}", "GET"),
            ("h2", "/users/-id-", "GET"));

        var surfaces = Surfaces(doc);
        Assert.Equal(2, surfaces.Count);

        var ids = surfaces.Select(s => (string)s["id"]!).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains("surf-get-users-id", ids, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("surf-get-users-id-2", ids, StringComparer.OrdinalIgnoreCase);

        var findingIds = Findings(doc).Select(f => (string)f["surfaceId"]!).ToList();
        Assert.Equal(2, findingIds.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(findingIds, id => Assert.Contains(id, ids));
    }

    [Theory]
    [InlineData("https://lab.example/admin/", "/admin")]
    [InlineData("/Admin/", "/admin")]
    [InlineData("admin", "/admin")]
    [InlineData("https://lab.example/admin?x=1", "/admin")]
    [InlineData("/", "/")]
    public void normalize_route_strips_trailing_slash_query_and_case(string endpoint, string expected)
    {
        Assert.Equal(expected, VpxExportService.NormalizeRoute(endpoint));
    }

    private static Dictionary<string, object?> Export(params (string id, string endpoint, string method)[] findings)
    {
        var input = new VpxExportService.ExportInput
        {
            Findings = findings.Select(f => new ChainableFinding
            {
                Id = f.id,
                Source = "test",
                Category = "missing-csp",
                Severity = "medium",
                Title = f.id,
                Endpoint = f.endpoint,
                Method = f.method
            }).ToList(),
            Proofs = []
        };
        return (Dictionary<string, object?>)VpxExportService.BuildDocument(input);
    }

    private static List<Dictionary<string, object?>> Surfaces(Dictionary<string, object?> doc) =>
        CastDictList(doc["surfaces"]);

    private static List<Dictionary<string, object?>> Findings(Dictionary<string, object?> doc) =>
        CastDictList(doc["findings"]);

    private static List<Dictionary<string, object?>> CastDictList(object? value) => value switch
    {
        List<Dictionary<string, object?>> typed => typed,
        IEnumerable<object> objects => objects.Cast<Dictionary<string, object?>>().ToList(),
        _ => throw new InvalidCastException($"Unexpected list type: {value?.GetType()}")
    };
}
