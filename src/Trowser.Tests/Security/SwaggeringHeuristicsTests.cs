using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class SwaggeringHeuristicsTests
{
    [Fact]
    public void SpecUrl_IgnoresSwaggerInTheHostName()
    {
        Assert.False(OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(
            "https://petstore3.swagger.io/api/v3/pet/findByStatus?status=available"));
    }

    [Fact]
    public void SpecUrl_MatchesOpenApiAndSwaggerPaths()
    {
        Assert.True(OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(
            "https://petstore3.swagger.io/api/v3/openapi.json"));
        Assert.True(OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(
            "https://petstore.swagger.io/v2/swagger.json"));
        Assert.False(OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(
            "https://example.test/api/v1/Books"));
    }

    [Theory]
    [InlineData("HTTP 404", true)]
    [InlineData("/openapi.json: HTTP 410", true)]
    [InlineData("HTTP 401", false)]
    [InlineData("HTTP 403", false)]
    [InlineData("response is not OpenAPI", false)]
    public void ExpectedSpecMiss_IsOnlyNotFound(string message, bool expected)
    {
        Assert.Equal(expected, OpenApiSpecHeuristics.IsExpectedSpecMiss(message));
    }

    [Fact]
    public void MissingSpecMessage_MentionsLoginOnlyOnAuthFailure()
    {
        var notFound = OpenApiSpecHeuristics.DescribeMissingSpec(["/openapi.json: HTTP 404"]);
        Assert.DoesNotContain("log in", notFound, StringComparison.OrdinalIgnoreCase);

        var denied = OpenApiSpecHeuristics.DescribeMissingSpec(["/openapi.json: HTTP 401"]);
        Assert.Contains("401", denied, StringComparison.Ordinal);
        Assert.Contains("log in", denied, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SensitiveJson_ReportsPasswordFieldNamesWithoutValues()
    {
        var body = """[{"id":1,"userName":"User 1","password":"Password1"}]""";
        var names = SwaggeringProbe.FindSensitiveJsonProperties(body);
        Assert.Equal("password", Assert.Single(names));
        Assert.DoesNotContain("Password1", string.Join(",", names), StringComparison.Ordinal);
    }

    [Fact]
    public void SensitiveJson_SkipsPlaceholdersAndUnrelatedFields()
    {
        var body = """{"title":"Book 1","password":"string","pageCount":100}""";
        Assert.Empty(SwaggeringProbe.FindSensitiveJsonProperties(body));
    }

    [Fact]
    public void ResponseExcerpt_CollapsesWhitespaceAndCapsLength()
    {
        var excerpt = SwaggeringProbe.ResponseExcerpt("{\n  \"code\": 500\n}", 8);
        Assert.Equal("{ \"code\"…", excerpt);
    }
}
