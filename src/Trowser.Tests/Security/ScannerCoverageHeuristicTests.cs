using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class ScannerCoverageHeuristicTests
{
    [Fact]
    public void MassAssignment_AcceptsFormUrlEncoded_AndInjectsTheField()
    {
        Assert.True(MassAssignmentEvidence.TryPrepare(
            "displayName=cleo&email=cleo@example.test",
            "application/x-www-form-urlencoded",
            out var model,
            out var error));
        Assert.Null(error);
        Assert.Equal("form", model!.Kind);

        var injected = model.WithInjection("role", System.Text.Json.Nodes.JsonValue.Create("admin")!, "admin");
        var body = injected.Serialize();
        Assert.Contains("displayName=cleo", body, StringComparison.Ordinal);
        Assert.Contains("role=admin", body, StringComparison.Ordinal);
        Assert.Equal("application/x-www-form-urlencoded", injected.ContentType);
    }

    [Fact]
    public void MassAssignment_DoesNotTreatShortTokensInHtmlAsAHit()
    {
        const string page = "<html><body><p>true</p><a href=\"/users/2\">open</a><p>administrator</p></body></html>";
        Assert.False(MassAssignmentEvidence.Matches(page, "isAdmin", "true"));
        Assert.False(MassAssignmentEvidence.Matches(page, "userId", "2"));
        Assert.False(MassAssignmentEvidence.Matches(page, "role", "admin"));
        Assert.False(MassAssignmentEvidence.NewlyObserved(page, page, "isAdmin", "true"));
        Assert.False(MassAssignmentEvidence.NewlyObserved(page, page, "userId", "2"));
    }

    [Fact]
    public void MassAssignment_SeesARoleThatChangedBetweenFetches()
    {
        const string before = "<form><input name=\"role\" value=\"user\"></form>";
        const string after = "<form><input name=\"role\" value=\"admin\"></form>";
        Assert.False(MassAssignmentEvidence.Matches(before, "role", "admin"));
        Assert.True(MassAssignmentEvidence.Matches(after, "role", "admin"));
        Assert.True(MassAssignmentEvidence.NewlyObserved(before, after, "role", "admin"));
        Assert.False(MassAssignmentEvidence.NewlyObserved(after, after, "role", "admin"));
    }

    [Fact]
    public void MassAssignment_MatchesJsonFieldTypes_NotUnrelatedSubstrings()
    {
        Assert.True(MassAssignmentEvidence.Matches("{\"role\":\"admin\",\"note\":\"true\"}", "role", "admin"));
        Assert.True(MassAssignmentEvidence.Matches("{\"isAdmin\":true}", "isAdmin", "true"));
        Assert.False(MassAssignmentEvidence.Matches("{\"isAdmin\":false,\"banner\":\"true\"}", "isAdmin", "true"));
        Assert.True(MassAssignmentEvidence.Matches("{\"userId\":2}", "userId", "2"));
        Assert.False(MassAssignmentEvidence.Matches("{\"userId\":1,\"path\":\"/2\"}", "userId", "2"));
    }

    [Fact]
    public void Csrf_FormWithHiddenCsrfField_IsATokenToTest()
    {
        var forms = new List<FormProbeCloner.CapturedForm>
        {
            new()
            {
                Action = "http://127.0.0.1:8080/profile",
                Method = "POST",
                Fields =
                {
                    new FormProbeCloner.CapturedFormField { Name = "displayName", Value = "cleo", Type = "text" },
                    new FormProbeCloner.CapturedFormField { Name = "csrf", Value = "abc123", Type = "hidden" }
                }
            }
        };

        var planned = CsrfDomFormPlanner.Plan(forms, "127.0.0.1");
        var form = Assert.Single(planned);
        Assert.Equal("csrf", form.CsrfField);
        Assert.Contains("csrf=abc123", form.Body, StringComparison.Ordinal);
        Assert.True(CsrfDomFormPlanner.SameEndpoint("POST", "http://localhost:8080/profile", form));
    }

    [Fact]
    public void Csrf_FormWithoutToken_StaysUntokened()
    {
        var forms = new List<FormProbeCloner.CapturedForm>
        {
            new()
            {
                Action = "https://app.example/profile",
                Method = "POST",
                Fields =
                {
                    new FormProbeCloner.CapturedFormField { Name = "displayName", Value = "cleo", Type = "text" }
                }
            }
        };

        var form = Assert.Single(CsrfDomFormPlanner.Plan(forms, null));
        Assert.Null(form.CsrfField);
    }

    [Fact]
    public void Csrf_MultipartBody_ExposesNameAttributeToken()
    {
        const string body = """
            ------bound
            Content-Disposition: form-data; name="csrf"

            abc
            ------bound--
            """;
        Assert.True(CsrfTokenHeuristics.TryExtractFromBody(body, out var field));
        Assert.Equal("csrf", field);
    }

    [Theory]
    [InlineData(200, "profile saved", true, "medium")]
    [InlineData(302, "", true, "medium")]
    [InlineData(200, "password has been changed", true, "high")]
    [InlineData(403, "invalid csrf token", false, "info")]
    [InlineData(400, "bad request", false, "info")]
    public void Csrf_FormTokenProbe_SeparatesAcceptanceFromRejection(int status, string body, bool vulnerable, string severity)
    {
        var eval = CsrfProbeResponseEvaluator.EvaluateFormTokenProbe(status, body);
        Assert.Equal(vulnerable, eval.Vulnerable);
        Assert.Equal(severity, eval.Severity);
    }

    [Fact]
    public void LogoutMethod_OverridesADiscoveredGet()
    {
        var discovered = new AuthFormDiscovery.ResolvedForm
        {
            Url = "http://127.0.0.1:8080/logout",
            Method = "GET",
            Source = "path-hint"
        };

        var applied = LogoutInvalidationProbe.ApplyLogoutOverrides(discovered, new LogoutInvalidationProbe.ProbeOptions
        {
            LogoutMethod = "post"
        });

        Assert.Equal("POST", applied.Method);
        Assert.Contains("override", applied.Source, StringComparison.Ordinal);
        Assert.False(LogoutInvalidationProbe.ShouldRetryLogoutAsPost(405, applied.Method, applied.Source));
    }

    [Fact]
    public void LogoutGet405_RetriesAsPost_OnlyWhenTheMethodWasInferred()
    {
        Assert.True(LogoutInvalidationProbe.ShouldRetryLogoutAsPost(405, "GET", "path-hint"));
        Assert.False(LogoutInvalidationProbe.ShouldRetryLogoutAsPost(405, "GET", "path-hint+override"));
        Assert.False(LogoutInvalidationProbe.ShouldRetryLogoutAsPost(0, "GET", "path-hint"));
        Assert.False(LogoutInvalidationProbe.ShouldRetryLogoutAsPost(404, "GET", "path-hint"));
    }

    [Fact]
    public void CookieSecureCheck_OnHttp_IsSkip_NotFail()
    {
        var result = new CookieAuditChecker().Run("http://127.0.0.1/profile",
        [
            new Dictionary<string, object>
            {
                ["name"] = "session",
                ["value"] = "abc",
                ["domain"] = "127.0.0.1",
                ["path"] = "/",
                ["secure"] = false,
                ["httpOnly"] = true,
                ["sameSite"] = "lax",
                ["_sameSiteExplicit"] = true,
                ["session"] = true
            }
        ]);

        var item = result.Checklist["Secure flag on HTTPS"];
        Assert.True(item.Skipped);
        Assert.False(item.Pass);
        Assert.Equal("SKIP", item.StatusLabel);

        var line = result.Format().Split('\n').First(l => l.Contains("Secure flag on HTTPS", StringComparison.Ordinal));
        Assert.Contains("[SKIP]", line, StringComparison.Ordinal);
        Assert.DoesNotContain("[FAIL]", line, StringComparison.Ordinal);
    }
}
