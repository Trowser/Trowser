using Trowser.Chat;
using Xunit;

namespace Trowser.Tests;

public class LlmToolArgumentsSanitizationTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void empty_or_whitespace_becomes_object(string? input)
    {
        Assert.Equal("{}", LlmClient.SanitizeToolArgumentsForProvider(input));
    }

    [Fact]
    public void valid_object_is_kept_verbatim()
    {
        const string json = """{"requests":[{"url":"/api/x"}],"concurrent":true}""";
        Assert.Same(json, LlmClient.SanitizeToolArgumentsForProvider(json));
    }

    [Fact]
    public void leading_zero_number_is_replaced()
    {
        const string json = """{"requests":[{"url":"/api/x","json":{"id":00}}]}""";
        Assert.Equal("{}", LlmClient.SanitizeToolArgumentsForProvider(json));
    }

    [Fact]
    public void truncated_json_is_replaced()
    {
        Assert.Equal("{}", LlmClient.SanitizeToolArgumentsForProvider("""{"requests":["""));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("0")]
    [InlineData("true")]
    [InlineData("\"requests\"")]
    public void non_object_json_is_replaced(string json)
    {
        Assert.Equal("{}", LlmClient.SanitizeToolArgumentsForProvider(json));
    }
}
