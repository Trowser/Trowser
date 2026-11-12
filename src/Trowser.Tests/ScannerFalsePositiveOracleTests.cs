using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class ScannerFalsePositiveOracleTests
{
    [Theory]
    [InlineData(200, "")]
    [InlineData(200, "   ")]
    [InlineData(200, null)]
    public void WorkflowSkip_EmptyBodyNotAccepted(int status, string? body)
    {
        Assert.False(InsecureDesignDiscovery.LooksLikeWorkflowSkipAccepted(status, body ?? ""));
    }

    [Fact]
    public void WorkflowSkip_JsonSuccessAccepted()
    {
        Assert.True(InsecureDesignDiscovery.LooksLikeWorkflowSkipAccepted(200, """{"ok":true}"""));
    }

    [Fact]
    public void WorkflowSkip_ValidationErrorRejected()
    {
        Assert.False(InsecureDesignDiscovery.LooksLikeWorkflowSkipAccepted(200, """{"error":"validation failed"}"""));
    }

    [Fact]
    public void Ssti_ErrorSignatureSkippedWhenInBaseline()
    {
        var baseline = "Powered by handlebars.min.js";
        var probe = "handlebars template error";
        Assert.False(SstiScanner.DetectTemplateError(baseline, probe, out _));
    }

    [Fact]
    public void Ssti_ErrorSignatureNewOnProbe()
    {
        var baseline = "hello";
        var probe = "jinja2.exceptions.UndefinedError";
        Assert.True(SstiScanner.DetectTemplateError(baseline, probe, out var indicator));
        Assert.Equal("jinja2", indicator);
    }

    [Fact]
    public void NextJs_Classify_NoAbsoluteTimingWithoutBaseline()
    {
        Assert.Null(NextJsRscScanProbe.Classify(200, "", elapsedSeconds: 6.0));
    }

    [Fact]
    public void NextJs_Classify_EchoedPayloadNotCritical()
    {
        var body = """[1,"$E5",["new","Function","return process.versions"]]""";
        Assert.Null(NextJsRscScanProbe.Classify(500, body, elapsedSeconds: 0.1));
    }

    [Fact]
    public void NextJs_Classify_RealNodeShapeCritical()
    {
        var body = """{"node":"v20.10.0","modules":"108"}""";
        var result = NextJsRscScanProbe.Classify(200, body, elapsedSeconds: 0.1);
        Assert.NotNull(result);
        Assert.Equal("critical", result!.Value.severity);
    }

    [Fact]
    public void CmdCanary_UidCritical()
    {
        Assert.Equal("critical", CmdCanaryProbe.ResolveCmdSeverity("command-injection", "uid=0(root)"));
    }

    [Fact]
    public void CmdCanary_LinuxMedium()
    {
        Assert.Equal("medium", CmdCanaryProbe.ResolveCmdSeverity("command-injection", "Linux"));
    }

    [Fact]
    public void CmdCanary_DetectShellOutput_WeakVsStrong()
    {
        Assert.Equal("uid=", CmdCanaryProbe.DetectShellOutput("uid=0(root) gid=0 groups=0"));
        Assert.Equal("Linux", CmdCanaryProbe.DetectShellOutput("Linux x86_64 GNU"));
    }

    [Fact]
    public void SessionFixation_IgnoresCsrfWhenSessionRotated()
    {
        var pre = new List<(string Name, string Value)>
        {
            ("XSRF-TOKEN", "abc"),
            ("connect.sid", "old-session")
        };
        var post = new List<(string Name, string Value)>
        {
            ("XSRF-TOKEN", "abc"),
            ("connect.sid", "old-session"),
            ("session", "new-session-id")
        };

        var findings = SessionFixationScanProbe.CompareCookies(pre, post, "https://app.test/login", null);
        Assert.Empty(findings);
    }

    [Fact]
    public void SessionFixation_StableSessionCookieHigh()
    {
        var pre = new List<(string Name, string Value)> { ("connect.sid", "same") };
        var post = new List<(string Name, string Value)> { ("connect.sid", "same") };

        var findings = SessionFixationScanProbe.CompareCookies(pre, post, "https://app.test/login", null);
        Assert.Single(findings);
        Assert.Equal("high", findings[0].Severity);
    }

    [Fact]
    public void SessionFixation_StableAnalyticsIgnored()
    {
        var pre = new List<(string Name, string Value)> { ("_ga", "GA1.2.123456789") };
        var post = new List<(string Name, string Value)> { ("_ga", "GA1.2.123456789") };

        var findings = SessionFixationScanProbe.CompareCookies(pre, post, "https://app.test/login", null);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task TimingConfirm_ReplayMustMatchThreshold()
    {
        var confirmed = await SecurityProbeTimingConfirm.ConfirmDeltaAsync(
            _ => Task.FromResult(0.1),
            _ => Task.FromResult(0.2),
            (b, a) => a - b >= 3.0);

        Assert.False(confirmed);
    }
}
