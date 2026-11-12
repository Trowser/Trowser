using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class PostMessagePayloadInferenceTests
{
    [Fact]
    public void ShapeForDispatch_wraps_html_property_from_json_parse_handler()
    {
        var handler = """
            var postMessageHandler = function(msg) {
              var content = JSON.parse(msg.data);
              div.innerHTML = content.html;
            };
            """;
        var shaped = PostMessagePayloadInference.ShapeForDispatch("<img src=x onerror=alert(1)>", [handler]);
        Assert.Contains("\"html\"", shaped);
        Assert.Contains("onerror", shaped);
    }

    [Fact]
    public void ShapeForDispatch_leaves_json_object_unchanged()
    {
        var raw = """{"html":"<b>1</b>"}""";
        var shaped = PostMessagePayloadInference.ShapeForDispatch(raw, null);
        Assert.Equal(raw, shaped);
    }
}
