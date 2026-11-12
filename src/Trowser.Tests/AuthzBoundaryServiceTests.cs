using System.Text.Json;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class AuthzBoundaryServiceTests
{
    [Fact]
    public void ParseSpecs_accepts_authorizedIds_alias_and_numeric_values()
    {
        const string json = """
            {
              "endpoint": "http://app.example/item?artist=%7Bartist%7D",
              "parameter": "artist",
              "authorizedIds": [1, 2],
              "unauthorizedIds": [99999]
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var specs = AuthzBoundaryService.ParseSpecs(doc.RootElement, out var error);

        Assert.Null(error);
        Assert.Single(specs);
        Assert.Equal("http://app.example/item?artist={artist}", specs[0].UrlTemplate);
        Assert.Equal(["1", "2"], specs[0].AuthorizedValues);
        Assert.Equal(["99999"], specs[0].UnauthorizedValues);
    }
}
