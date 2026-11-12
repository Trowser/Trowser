using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class SsrfCheckerOracleTests
{
    [Fact]
    public void Weak_metadata_token_on_200_is_likely_not_confirmed()
    {
        var baseline = "{\"ok\":true}";
        var body = "{\"ok\":true,\"instance-type\":\"t2.micro\"}";
        var result = SsrfChecker.DetectSsrfIndicator(
            "http://169.254.169.254/latest/meta-data/",
            body,
            baseline,
            status: 200,
            baselineStatus: 200);

        Assert.NotNull(result);
        Assert.Equal("likely", result!.Confidence);
    }

    [Fact]
    public void Strong_aws_metadata_on_200_stays_confirmed()
    {
        var baseline = "";
        var body = """
                   {
                     "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                     "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                   }
                   """;
        var result = SsrfChecker.DetectSsrfIndicator(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            body,
            baseline,
            status: 200,
            baselineStatus: 404);

        Assert.NotNull(result);
        Assert.Equal("confirmed", result!.Confidence);
    }

    [Fact]
    public void Azure_metadata_error_page_is_suppressed()
    {
        var body = """{"error":"InvalidMetadata","message":"Must be called with a Bearer token"}""";
        var result = SsrfChecker.DetectSsrfIndicator(
            "http://169.254.169.254/metadata/instance",
            body,
            baseline: "",
            status: 200,
            baselineStatus: 200);

        Assert.Null(result);
    }

    [Fact]
    public void Passwd_like_html_document_is_not_confirmed_file_disclosure()
    {
        var baseline = "";
        var body = """
                   <!DOCTYPE html><html><body>
                   <p>Example /etc/passwd line for documentation: root:x:0:0:root:/root:/bin/bash</p>
                   </body></html>
                   """;
        var result = SsrfChecker.DetectSsrfIndicator(
            "file:///etc/passwd",
            body,
            baseline,
            status: 200,
            baselineStatus: 400);

        Assert.Null(result);
    }

    [Fact]
    public void Status_flip_without_content_signal_is_tentative()
    {
        var baseline = "blocked";
        var body = "ok response with more text but no fetch oracle signal in body content here";
        var result = SsrfChecker.DetectSsrfIndicator(
            "http://127.0.0.1/admin",
            body,
            baseline,
            status: 200,
            baselineStatus: 403);

        Assert.NotNull(result);
        Assert.Equal("status-anomaly-internal", result!.Indicator);
        Assert.Equal("tentative", result.Confidence);
    }
}
