using Trowser.Api;
using Xunit;

namespace Trowser.Tests;

public class HttpHeaderDictionaryTests
{
    [Fact]
    public void Normalize_merges_content_type_differing_only_by_case()
    {
        var raw = new Dictionary<string, string>
        {
            ["content-type"] = "application/json",
            ["Content-Type"] = "application/json"
        };

        var merged = HttpHeaderDictionary.Normalize(raw);

        Assert.NotNull(merged);
        Assert.Single(merged!);
        Assert.Equal("application/json", merged!["Content-Type"]);
    }

    [Fact]
    public void PrepareForJsonBody_does_not_override_existing_content_type()
    {
        var headers = new Dictionary<string, string> { ["content-type"] = "application/vnd.api+json" };

        var prepared = HttpHeaderDictionary.PrepareForJsonBody(headers);

        Assert.Equal("application/vnd.api+json", prepared["Content-Type"]);
        Assert.Single(prepared);
    }

    [Fact]
    public void PrepareForJsonBody_defaults_content_type_when_absent()
    {
        var prepared = HttpHeaderDictionary.PrepareForJsonBody(null);

        Assert.Equal("application/json", prepared["Content-Type"]);
    }

    [Fact]
    public void PrepareForJsonBody_fixes_duplicate_keys_before_defaulting()
    {
        var raw = new Dictionary<string, string>
        {
            ["Authorization"] = "Bearer x",
            ["content-type"] = "application/json",
            ["Content-Type"] = "application/json"
        };

        var prepared = HttpHeaderDictionary.PrepareForJsonBody(raw);

        Assert.Equal(2, prepared.Count);
        Assert.Equal("Bearer x", prepared["Authorization"]);
        Assert.Equal("application/json", prepared["Content-Type"]);
    }
}
