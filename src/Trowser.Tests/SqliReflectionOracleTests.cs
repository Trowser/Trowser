using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class SqliReflectionOracleTests
{
    private const string Payload = "1' OR '1'='1";
    private const string BaselineValue = "1";

    [Fact]
    public void multi_site_echo_explains_length_delta()
    {
        var encoded = Uri.EscapeDataString(Payload);
        var htmlEncoded = System.Web.HttpUtility.HtmlEncode(Payload);
        var baseline = Page(BaselineValue, BaselineValue, BaselineValue);
        var probe = Page(Payload, encoded, htmlEncoded);

        var account = HttpSecurityProbes.MeasurePayloadReflection(baseline, probe, Payload, BaselineValue);
        var actual = probe.Length - baseline.Length;

        Assert.True(account.Count >= 5);
        Assert.Equal(actual, account.ReflectedBytes - account.Count * BaselineValue.Length);
        Assert.True(HttpSecurityProbes.PayloadReflectionExplainsLengthDelta(baseline, probe, Payload, BaselineValue));
        Assert.Equal(2, HttpSecurityProbes.TryCountResponseDataRows(baseline));
        Assert.Equal(2, HttpSecurityProbes.TryCountResponseDataRows(probe));
    }

    [Fact]
    public void extra_row_or_cell_is_not_reflection()
    {
        var encoded = Uri.EscapeDataString(Payload);
        var htmlEncoded = System.Web.HttpUtility.HtmlEncode(Payload);
        var baseline = Page(BaselineValue, BaselineValue, BaselineValue);
        var probe = Page(Payload, encoded, htmlEncoded);
        var extraRow = probe.Replace("</table>", "<tr><td>admin</td></tr></table>", StringComparison.Ordinal);
        var extraCell = probe.Replace(
            "<tr><td>Widget</td></tr>",
            "<tr><td>Widget</td><td>secret</td></tr>",
            StringComparison.Ordinal);

        Assert.False(HttpSecurityProbes.PayloadReflectionExplainsLengthDelta(baseline, extraRow, Payload, BaselineValue));
        Assert.Equal(3, HttpSecurityProbes.TryCountResponseDataRows(extraRow));
        Assert.False(HttpSecurityProbes.PayloadReflectionExplainsLengthDelta(baseline, extraCell, Payload, BaselineValue));
    }

    [Fact]
    public void sql_error_text_is_not_reflection()
    {
        var encoded = Uri.EscapeDataString(Payload);
        var htmlEncoded = System.Web.HttpUtility.HtmlEncode(Payload);
        var baseline = Page(BaselineValue, BaselineValue, BaselineValue);
        var probe = Page(Payload, encoded, htmlEncoded)
            .Replace("</body>", "You have an error in your SQL syntax</body>", StringComparison.Ordinal);

        Assert.False(HttpSecurityProbes.PayloadReflectionExplainsLengthDelta(baseline, probe, Payload, BaselineValue));
    }

    [Fact]
    public void json_list_length_is_the_oracle()
    {
        var baseline = """{"results":[{"id":1,"q":"1"},{"id":2,"q":"1"}]}""";
        var echoed = baseline.Replace("\"q\":\"1\"", $"\"q\":\"{Payload}\"", StringComparison.Ordinal);
        var extra = """{"results":[{"id":1,"q":"1' OR '1'='1"},{"id":2,"q":"1' OR '1'='1"},{"id":3,"name":"admin"}]}""";

        Assert.Equal(2, HttpSecurityProbes.TryCountResponseDataRows(baseline));
        Assert.True(HttpSecurityProbes.PayloadReflectionExplainsLengthDelta(baseline, echoed, Payload, BaselineValue));
        Assert.False(HttpSecurityProbes.PayloadReflectionExplainsLengthDelta(baseline, extra, Payload, BaselineValue));
    }

    [Fact]
    public void boolean_row_split_needs_a_stable_control()
    {
        var truthy = Row("1 AND 1=1", 10);
        var falsy = Row("1 AND 1=2", 1);
        var stable = new List<HttpSecurityProbes.SqliScanRow>
        {
            truthy,
            falsy,
            Row("aaaa", 2),
            Row("bbbb", 2)
        };
        Assert.True(HttpSecurityProbes.BooleanPairRowCountsCorroborate(truthy, falsy, stable));

        var unstable = new List<HttpSecurityProbes.SqliScanRow>
        {
            truthy,
            falsy,
            Row("aaaa", 2),
            Row("bbbb", 9)
        };
        Assert.False(HttpSecurityProbes.BooleanPairRowCountsCorroborate(truthy, falsy, unstable));
        Assert.False(HttpSecurityProbes.BooleanPairRowCountsCorroborate(truthy, Row("1 AND 1=2", 10), stable));
    }

    [Fact]
    public void reflected_union_length_delta_is_not_critical()
    {
        var echoed = new HttpSecurityProbes.SqliScanRow
        {
            Payload = "1 UNION SELECT NULL--",
            Status = 200,
            LengthDeltaExplainedByReflection = true,
            DataRowCount = 2,
            Types = ["union-based", "union-column-match"]
        };
        var other = new HttpSecurityProbes.SqliScanRow
        {
            Payload = "1 UNION SELECT NULL,NULL--",
            Status = 200,
            LengthDeltaExplainedByReflection = true,
            DataRowCount = 2,
            Types = ["union-based"]
        };

        Assert.True(HttpSecurityProbes.UnionPairIsReflectionArtifact(echoed, other));

        var rows = new List<HttpSecurityProbes.SqliScanRow> { echoed, other };
        HttpSecurityProbes.ApplySqliReflectionExplainedLengthHeuristics(rows);
        Assert.DoesNotContain("union-based", echoed.Types);
        Assert.DoesNotContain("union-column-match", echoed.Types);

        var severity = AutoScanPipeline.ResolveSqliSeverityForType("union-based", new HttpSecurityProbes.SqliScanRow
        {
            LengthDeltaExplainedByReflection = true,
            DataRowCount = 2,
            Types = ["union-based"]
        });
        Assert.Equal("low", severity.Severity);

        var findings = HttpSecurityProbes.BuildSqliFindings(
            [echoed],
            "http://localhost/search?q=§q§",
            ["q"]);
        Assert.Empty(findings);
    }

    [Fact]
    public void union_with_a_row_change_stays_critical()
    {
        var row = new HttpSecurityProbes.SqliScanRow
        {
            Payload = "1 UNION SELECT NULL--",
            Status = 200,
            DataRowCountDiverged = true,
            DataRowCount = 8,
            Types = ["union-based"]
        };

        Assert.False(HttpSecurityProbes.UnionPairIsReflectionArtifact(row, new HttpSecurityProbes.SqliScanRow
        {
            Payload = "1 UNION SELECT NULL,NULL--",
            Status = 200,
            DataRowCount = 2,
            Types = ["union-based"]
        }));

        var severity = AutoScanPipeline.ResolveSqliSeverityForType("union-based", row);
        Assert.Equal("critical", severity.Severity);

        var findings = HttpSecurityProbes.BuildSqliFindings(
            [row],
            "http://localhost/search?q=§q§",
            ["q"]);
        Assert.Single(findings);
        Assert.Equal("high", findings[0].Severity);
    }

    private static string Page(string raw, string urlEncoded, string htmlEncoded) =>
        "<html><body>" +
        $"<form action=\"/search?q={urlEncoded}&amp;x=1\">" +
        $"<input type=\"hidden\" name=\"q\" value=\"{raw}\">" +
        $"<input type=\"hidden\" name=\"echo\" value=\"{htmlEncoded}\">" +
        $"<a href=\"/search?q={urlEncoded}&sort=name\">Name</a>" +
        $"<a href=\"/search?q={urlEncoded}&sort=price\">Price</a>" +
        $"<a href=\"/search?q={urlEncoded}&sort=date\">Date</a>" +
        "<table><tr><th>Name</th></tr><tr><td>Widget</td></tr><tr><td>Gadget</td></tr></table>" +
        "</body></html>";

    private static HttpSecurityProbes.SqliScanRow Row(string payload, int rows) =>
        new()
        {
            Payload = payload,
            DataRowCount = rows,
            Status = 200
        };
}
