using Trowser.Security;
using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class AccessModelSeederTests
{
    private static AttackSurfaceEndpoint MakeEndpoint(
        string urlTemplate,
        string method = "GET",
        bool authRequired = false,
        string priority = "medium",
        List<string>? pathParams = null)
    {
        return new AttackSurfaceEndpoint
        {
            Url = $"https://app.test{urlTemplate}",
            UrlTemplate = urlTemplate,
            Methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { method },
            Auth = new AttackSurfaceAuth { Required = authRequired, Type = authRequired ? "session-cookie" : "none" },
            TestPriority = priority,
            Parameters = new AttackSurfaceParameters { Path = pathParams ?? [] }
        };
    }

    [Fact]
    public void Seed_PerUserAuthenticatedResourceWithPathId_ClassifiedSensitivePerUser()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/api/orders/{id}", authRequired: true, pathParams: ["id"]);

        var count = AccessModelSeeder.Seed(model, [ep]);

        Assert.Equal(1, count);
        var resource = model.FindResource("GET", "/api/orders/{id}");
        Assert.NotNull(resource);
        Assert.Equal(AccessSensitivity.Sensitive, resource!.Sensitivity);
        Assert.Equal(AccessOwnership.PerUser, resource.Ownership);
        Assert.Equal(AccessSource.Heuristic, resource.Source);
    }

    [Fact]
    public void Seed_UnauthenticatedContentPath_ClassifiedPublicShared()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/blog/{slug}", authRequired: false);

        AccessModelSeeder.Seed(model, [ep]);

        var resource = model.FindResource("GET", "/blog/{slug}");
        Assert.NotNull(resource);
        Assert.Equal(AccessSensitivity.Public, resource!.Sensitivity);
        Assert.Equal(AccessOwnership.Shared, resource.Ownership);
    }

    [Fact]
    public void Seed_AdminPath_ClassifiedSensitiveRoleGated()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/admin/users", authRequired: true);

        AccessModelSeeder.Seed(model, [ep]);

        var resource = model.FindResource("GET", "/admin/users");
        Assert.NotNull(resource);
        Assert.Equal(AccessSensitivity.Sensitive, resource!.Sensitivity);
        Assert.Equal(AccessOwnership.RoleGated, resource.Ownership);
    }

    [Fact]
    public void Seed_NeverOverwritesNonHeuristicClassification()
    {
        var model = new AccessModel { Host = "app.test" };
        model.Resources["GET /api/orders/{id}"] = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/api/orders/{id}",
            Sensitivity = AccessSensitivity.Public, // deliberately "wrong" vs. heuristic, to prove it's untouched
            Ownership = AccessOwnership.Shared,
            Source = AccessSource.Human,
            Confidence = 1.0
        };
        var ep = MakeEndpoint("/api/orders/{id}", authRequired: true, pathParams: ["id"]);

        var count = AccessModelSeeder.Seed(model, [ep]);

        Assert.Equal(0, count);
        var resource = model.FindResource("GET", "/api/orders/{id}");
        Assert.Equal(AccessSensitivity.Public, resource!.Sensitivity);
        Assert.Equal(AccessSource.Human, resource.Source);
    }

    [Fact]
    public void Seed_RefreshesExistingHeuristicEntry()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/api/orders/{id}", authRequired: true, pathParams: ["id"]);
        AccessModelSeeder.Seed(model, [ep]);

        var epUpdated = MakeEndpoint("/admin/orders/{id}", authRequired: true, pathParams: ["id"]);
        var count = AccessModelSeeder.Seed(model, [ep, epUpdated]);

        Assert.Equal(2, count);
        Assert.Equal(2, model.Resources.Count);
    }

    [Fact]
    public void Seed_UnclassifiableAuthenticatedEndpoint_LeavesLowConfidenceUnknown()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/api/widgets", authRequired: true);

        AccessModelSeeder.Seed(model, [ep]);

        var resource = model.FindResource("GET", "/api/widgets");
        Assert.NotNull(resource);
        Assert.True(resource!.IsUnclassified);
        Assert.True(resource.Confidence < 0.2);
    }

    [Fact]
    public void Seed_PerUserNounWithoutObservedAuth_IsNotClassifiedPublic()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/order/details", authRequired: false);

        AccessModelSeeder.Seed(model, [ep]);

        var resource = model.FindResource("GET", "/order/details");
        Assert.NotNull(resource);
        Assert.Equal(AccessSensitivity.Sensitive, resource!.Sensitivity);
        Assert.Equal(AccessOwnership.PerUser, resource.Ownership);
        Assert.Equal("deny-cross-owner", resource.ExpectedCrossIdentityOutcome);
    }

    [Fact]
    public void Seed_CartUnderCatalog_PrefersPerUserOverPublicNoun()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/catalog/cart", authRequired: false);

        AccessModelSeeder.Seed(model, [ep]);

        var resource = model.FindResource("GET", "/catalog/cart");
        Assert.Equal(AccessOwnership.PerUser, resource!.Ownership);
    }

    [Fact]
    public void Seed_UnknownUnauthenticatedPath_StaysUnclassified()
    {
        var model = new AccessModel { Host = "app.test" };
        var ep = MakeEndpoint("/api/widgets", authRequired: false);

        AccessModelSeeder.Seed(model, [ep]);

        var resource = model.FindResource("GET", "/api/widgets");
        Assert.True(resource!.IsUnclassified);
    }
}
