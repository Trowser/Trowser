using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class EndpointDiscoveryBaselineTests
{
    [Fact]
    public void SpaMode_DropsHtmlShellDuplicates_AndKeepsDistinctPagesAndJson()
    {
        var baseline = HtmlBaseline();
        var raw = new[]
        {
            Html("/admin"),
            Html("/login"),
            Html("/config"),
            Html("/about", title: "About"),
            Html("/assets/app.js", length: 9000, contentType: "text/javascript", title: null),
            Json("/api/health", """{"ok":true}""")
        };

        var filtered = EndpointScanner.ApplyBaselineFilter(raw, baseline, spaMode: true);

        Assert.Equal(3, filtered.SpaFilteredCount);
        Assert.DoesNotContain(filtered.Kept, d => d.Path is "/admin" or "/login" or "/config");
        Assert.Contains(filtered.Kept, d => d.Path == "/about");
        Assert.Contains(filtered.Kept, d => d.Path == "/assets/app.js");
        Assert.Contains(filtered.Kept, d => d.Path == "/api/health");
        Assert.Contains("excluded", filtered.BaselineNote);
        Assert.Contains("Set spaMode to false", filtered.BaselineNote);
    }

    [Fact]
    public void SpaModeOff_KeepsShellDuplicates_AndWarns()
    {
        var raw = new[] { Html("/admin"), Html("/login"), Html("/real", title: "Real", length: 9000) };
        var filtered = EndpointScanner.ApplyBaselineFilter(raw, HtmlBaseline(), spaMode: false);

        Assert.Equal(0, filtered.SpaFilteredCount);
        Assert.Equal(3, filtered.Kept.Count);
        Assert.Contains("spaMode is false", filtered.BaselineNote);
        Assert.Contains("2 discovered", filtered.BaselineNote);
    }

    [Fact]
    public void AuthRedirects_AreFiltered_EvenWhenSpaModeIsOff()
    {
        var baseline = new SpaShellFingerprint
        {
            StatusCode = 302,
            ContentType = "text/html",
            Title = "Login",
            BodyLength = 0,
            RedirectLocation = "https://idp.example/sso?SAMLRequest=aaa"
        };
        var raw = new[]
        {
            new DiscoveredEndpoint
            {
                Path = "/admin",
                StatusCode = 302,
                ContentType = "text/html",
                Title = "Somewhere else",
                ContentLength = 1200,
                RedirectLocation = "https://idp.example/sso?SAMLRequest=bbb"
            }
        };

        var filtered = EndpointScanner.ApplyBaselineFilter(raw, baseline, spaMode: false);

        Assert.Empty(filtered.Kept);
        Assert.Equal(1, filtered.AuthRedirectFilteredCount);
        Assert.Null(filtered.BaselineNote);
    }

    [Fact]
    public void IdenticalApiBodies_StayInResults_AndWarnWhenTheyDominate()
    {
        const string echo = """{"error":"not found"}""";
        var baseline = new SpaShellFingerprint
        {
            StatusCode = 200,
            ContentType = "application/json",
            BodyLength = echo.Length,
            BodySnippet = echo
        };
        var raw = new[]
        {
            Json("/api/a", echo),
            Json("/api/b", echo),
            Json("/api/c", echo),
            Json("/api/users", """{"id":1,"name":"ada"}""")
        };

        var filtered = EndpointScanner.ApplyBaselineFilter(raw, baseline, spaMode: true);

        Assert.Equal(0, filtered.SpaFilteredCount);
        Assert.Equal(4, filtered.Kept.Count);
        Assert.Equal(3, filtered.ApiEchoCount);
        Assert.Contains("3 of 4", filtered.BaselineNote);
        Assert.Contains("API-shaped bodies stay in discovered", filtered.BaselineNote);
    }

    [Fact]
    public void NoBaseline_LeavesEveryResponse()
    {
        var raw = new[] { Html("/admin"), Json("/api/health", """{"ok":true}""") };
        var filtered = EndpointScanner.ApplyBaselineFilter(raw, baseline: null, spaMode: true);

        Assert.Equal(2, filtered.Kept.Count);
        Assert.Equal(0, filtered.SpaFilteredCount);
        Assert.Null(filtered.BaselineNote);
    }

    [Fact]
    public void MissingSqliTemplate_IncludesCopyPasteableExamples_ForFetchShapedBodies()
    {
        var message = InjectionRequestErrors.MissingSqliTemplate(fetchShapedBody: true);

        Assert.Contains("POST /api/fetch", message);
        Assert.Contains(InjectionRequestErrors.ShorthandExample, message);
        Assert.Contains(InjectionRequestErrors.RequestExample, message);
        Assert.Contains("§q§", message);
        Assert.Contains("\"param\":\"q\"", message);
    }

    [Fact]
    public void WithRequestExample_KeepsTheScannerSpecificReason()
    {
        var message = InjectionRequestErrors.WithRequestExample(
            "Template must contain at least one §marker§ or {{marker}} injection point in url, body, or headers (same as /api/fuzz).");

        Assert.StartsWith("Template must contain at least one", message);
        Assert.Contains("same as /api/fuzz", message);
        Assert.Contains(InjectionRequestErrors.RequestExample, message);
    }

    static SpaShellFingerprint HtmlBaseline() => new()
    {
        ProbePath = "/__trowser_spa_probe__/x/",
        StatusCode = 200,
        ContentType = "text/html",
        Title = "App",
        BodyLength = 4000,
        BodySnippet = "<!doctype html><title>App</title>"
    };

    static DiscoveredEndpoint Html(
        string path, int length = 4000, string? title = "App", string contentType = "text/html") => new()
    {
        Path = path,
        Url = "https://example.test" + path,
        StatusCode = 200,
        ContentType = contentType,
        Title = title,
        ContentLength = length,
        BodySnippet = "<!doctype html><title>App</title>"
    };

    static DiscoveredEndpoint Json(string path, string body) => new()
    {
        Path = path,
        Url = "https://example.test" + path,
        StatusCode = 200,
        ContentType = "application/json",
        ContentLength = body.Length,
        BodySnippet = body
    };
}
