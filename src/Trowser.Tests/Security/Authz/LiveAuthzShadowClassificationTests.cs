using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class LiveAuthzShadowClassificationTests
{
    [Theory]
    [InlineData("A", AccessSensitivity.Public, AccessOwnership.Shared)]
    [InlineData("a", AccessSensitivity.Public, AccessOwnership.Shared)]
    [InlineData("B", AccessSensitivity.Sensitive, AccessOwnership.PerUser)]
    [InlineData("C", AccessSensitivity.Sensitive, AccessOwnership.PerTenant)]
    [InlineData("D", AccessSensitivity.Internal, AccessOwnership.RoleGated)]
    public void MapAnswerToClassification_KnownKeys_MapToExpectedIntent(
        string key, AccessSensitivity expectedSensitivity, AccessOwnership expectedOwnership)
    {
        var (sensitivity, ownership) = LiveAuthzShadow.MapAnswerToClassification(key);

        Assert.Equal(expectedSensitivity, sensitivity);
        Assert.Equal(expectedOwnership, ownership);
    }

    [Theory]
    [InlineData("E")]
    [InlineData("other")]
    [InlineData("")]
    public void MapAnswerToClassification_UnknownKeys_ReturnUnknown(string key)
    {
        var (sensitivity, ownership) = LiveAuthzShadow.MapAnswerToClassification(key);

        Assert.Equal(AccessSensitivity.Unknown, sensitivity);
        Assert.Equal(AccessOwnership.Unknown, ownership);
    }
}
