using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class AccessModelTests
{
    [Fact]
    public void Key_IsMethodUppercaseAndUrlTemplate()
    {
        var resource = new AccessModelResource { Method = "get", UrlTemplate = "/api/orders/{id}" };
        Assert.Equal("GET /api/orders/{id}", resource.Key);
    }

    [Theory]
    [InlineData(AccessSensitivity.Sensitive, AccessOwnership.PerUser, "deny-cross-owner")]
    [InlineData(AccessSensitivity.Sensitive, AccessOwnership.PerTenant, "deny-cross-tenant")]
    [InlineData(AccessSensitivity.Internal, AccessOwnership.RoleGated, "deny-below-tier")]
    [InlineData(AccessSensitivity.Public, AccessOwnership.Unknown, "allow")]
    [InlineData(AccessSensitivity.Internal, AccessOwnership.Shared, "allow")]
    [InlineData(AccessSensitivity.Unknown, AccessOwnership.Unknown, "unknown")]
    public void ExpectedCrossIdentityOutcome_DerivedFromSensitivityAndOwnership(
        AccessSensitivity sensitivity, AccessOwnership ownership, string expected)
    {
        var resource = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/api/x",
            Sensitivity = sensitivity,
            Ownership = ownership
        };

        Assert.Equal(expected, resource.ExpectedCrossIdentityOutcome);
    }

    [Fact]
    public void IsUnclassified_TrueOnlyWhenBothUnknown()
    {
        var unclassified = new AccessModelResource { Method = "GET", UrlTemplate = "/x" };
        Assert.True(unclassified.IsUnclassified);

        var partial = new AccessModelResource
        {
            Method = "GET", UrlTemplate = "/x", Sensitivity = AccessSensitivity.Public
        };
        Assert.False(partial.IsUnclassified);
    }

    [Fact]
    public void FindResource_And_FindIdentity_LookUpByKey()
    {
        var model = new AccessModel { Host = "app.test" };
        var resource = new AccessModelResource { Method = "GET", UrlTemplate = "/api/orders/{id}" };
        model.Resources[resource.Key] = resource;
        model.Identities.Add(new AccessModelIdentity { Name = "alice", Tier = 1 });

        Assert.Same(resource, model.FindResource("get", "/api/orders/{id}"));
        Assert.NotNull(model.FindIdentity("ALICE"));
        Assert.Null(model.FindResource("POST", "/api/orders/{id}"));
    }
}
