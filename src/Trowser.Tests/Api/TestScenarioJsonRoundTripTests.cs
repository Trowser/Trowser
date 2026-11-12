using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

namespace Trowser.Tests.Api;

/// <summary>
/// Mirrors POST /api/test-scenario step capture: UTF-8 JSON → JsonElement → aggregated response.
/// </summary>
public class TestScenarioJsonRoundTripTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    [Fact]
    public void Scenario_step_body_preserves_non_ascii_title_and_symbols()
    {
        var inner = JsonSerializer.SerializeToUtf8Bytes(
            new Dictionary<string, object?>
            {
                ["success"] = true,
                ["data"] = new { title = "React • TodoMVC", footer = "© Sauce Labs" }
            },
            typeof(Dictionary<string, object?>),
            JsonOptions);

        using var doc = JsonDocument.Parse(inner);
        var payload = doc.RootElement.Clone();
        var stepOut = new { body = (object)payload };

        var final = JsonSerializer.SerializeToUtf8Bytes(
            new { results = new object[] { stepOut } },
            JsonOptions);

        var json = System.Text.Encoding.UTF8.GetString(final);
        Assert.Contains("React • TodoMVC", json);
        Assert.Contains("© Sauce Labs", json);
        Assert.DoesNotContain("\uFFFD", json);
    }
}
