using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class AuthzBodyMatcherTests
{
    [Fact]
    public void BodiesMatch_HtmlMain_IgnoresHeaderChrome()
    {
        var options = new AuthzBodyMatchOptions { Strategy = AuthzBodyMatchStrategy.HtmlMain };
        var left = "<html><header>Ada</header><main><p>Secret note</p></main></html>";
        var right = "<html><header>Ben</header><main><p>Secret note</p></main></html>";
        Assert.True(AuthzBodyMatcher.BodiesMatch(left, right, options));
    }

    [Fact]
    public void BodiesMatch_Exact_DifferByWhitespace_DoNotMatch()
    {
        var options = new AuthzBodyMatchOptions { Strategy = AuthzBodyMatchStrategy.Exact };
        Assert.False(AuthzBodyMatcher.BodiesMatch("{\"a\":1}", "{\"a\": 1}", options));
    }

    [Fact]
    public void BodiesMatch_NormalizedJson_IgnoresDefaultVolatileFields()
    {
        var options = new AuthzBodyMatchOptions { Strategy = AuthzBodyMatchStrategy.NormalizedJson };
        var left = "{\"id\":1,\"name\":\"widget\",\"requestId\":\"aaa\",\"timestamp\":\"2024-01-01\"}";
        var right = "{\"id\":1,\"name\":\"widget\",\"requestId\":\"bbb\",\"timestamp\":\"2024-06-06\"}";

        Assert.True(AuthzBodyMatcher.BodiesMatch(left, right, options));
    }

    [Fact]
    public void BodiesMatch_NormalizedJson_DifferentDataDoesNotMatch()
    {
        var options = new AuthzBodyMatchOptions { Strategy = AuthzBodyMatchStrategy.NormalizedJson };
        var left = "{\"id\":1,\"owner\":\"alice\"}";
        var right = "{\"id\":1,\"owner\":\"bob\"}";

        Assert.False(AuthzBodyMatcher.BodiesMatch(left, right, options));
    }

    [Fact]
    public void BodiesMatch_Structural_SameShapeDifferentValues_Matches()
    {
        var options = new AuthzBodyMatchOptions { Strategy = AuthzBodyMatchStrategy.Structural };
        var left = "{\"id\":1,\"owner\":\"alice\"}";
        var right = "{\"id\":2,\"owner\":\"bob\"}";

        Assert.True(AuthzBodyMatcher.BodiesMatch(left, right, options));
    }

    [Fact]
    public void NonJsonBodiesMatchWithLengthTolerance_SmallDifference_ConsideredSame()
    {
        var left = new string('x', 1000);
        var right = new string('x', 1030); // within max(64, 2%) tolerance

        Assert.True(AuthzBodyMatcher.NonJsonBodiesMatchWithLengthTolerance(left, right));
    }

    [Fact]
    public void NonJsonBodiesMatchWithLengthTolerance_LargeDifference_ConsideredDifferent()
    {
        var left = new string('x', 1000);
        var right = new string('x', 1500);

        Assert.False(AuthzBodyMatcher.NonJsonBodiesMatchWithLengthTolerance(left, right));
    }

    [Fact]
    public void NonJsonBodiesMatchWithLengthTolerance_ShortBodies_UseMinimumByteTolerance()
    {
        // 40 vs 90 bytes: 2% ratio tolerance would be tiny, but the 64-byte floor covers it.
        var left = new string('a', 40);
        var right = new string('a', 90);

        Assert.True(AuthzBodyMatcher.NonJsonBodiesMatchWithLengthTolerance(left, right));
    }

    [Fact]
    public void NonJsonBodiesMatchWithLengthTolerance_JsonBodies_DefersAndReturnsFalse()
    {
        // JSON should go through NormalizedJson/Structural, not the length-tolerant fallback.
        Assert.False(AuthzBodyMatcher.NonJsonBodiesMatchWithLengthTolerance("{\"a\":1}", "{\"a\":1}"));
    }
}
