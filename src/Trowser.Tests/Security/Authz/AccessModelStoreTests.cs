using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class AccessModelStoreTests : IDisposable
{
    private readonly string _tempDir;
    private readonly AccessModelStore _store;

    public AccessModelStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "TrowserTests_AccessModel_" + Guid.NewGuid().ToString("N"));
        _store = new AccessModelStore(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    [Fact]
    public void GetOrCreate_NoSavedModel_ReturnsEmptyModelForHost()
    {
        var model = _store.GetOrCreate("app.test");
        Assert.Equal("app.test", model.Host);
        Assert.Empty(model.Resources);
        Assert.Empty(model.Identities);
    }

    [Fact]
    public void GetOrCreate_DefaultPort_UsesTheSameModelAsTheBareHost()
    {
        _store.UpsertResource("example.com", new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/api/products",
            Sensitivity = AccessSensitivity.Public,
            Ownership = AccessOwnership.Shared,
            Source = AccessSource.Human
        });

        var viaPort = _store.Load("example.com:443");
        Assert.NotNull(viaPort);
        Assert.Equal("example.com", viaPort!.Host);
        Assert.NotNull(viaPort.FindResource("GET", "/api/products"));

        var nonDefault = _store.GetOrCreate("127.0.0.1:8099");
        nonDefault.Resources["GET /x"] = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/x",
            Sensitivity = AccessSensitivity.Public
        };
        _store.Save(nonDefault);

        Assert.Null(_store.Load("127.0.0.1"));
        Assert.NotNull(_store.Load("127.0.0.1:8099"));
        Assert.True(File.Exists(Path.Combine(_tempDir, "127.0.0.1_8099.json")));
    }

    [Fact]
    public void Load_NoSavedModel_ReturnsNull()
    {
        Assert.Null(_store.Load("app.test"));
    }

    [Fact]
    public void Save_ThenLoad_RoundTripsResourcesAndIdentities()
    {
        var model = _store.GetOrCreate("app.test");
        model.Resources["GET /api/orders/{id}"] = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/api/orders/{id}",
            Sensitivity = AccessSensitivity.Sensitive,
            Ownership = AccessOwnership.PerUser,
            Source = AccessSource.Human,
            Confidence = 1.0
        };
        model.Identities.Add(new AccessModelIdentity { Name = "alice", Role = "customer", Tier = 1, OwnerTags = ["alice@test.com"] });

        _store.Save(model);
        var reloaded = _store.Load("app.test");

        Assert.NotNull(reloaded);
        var resource = reloaded!.FindResource("GET", "/api/orders/{id}");
        Assert.NotNull(resource);
        Assert.Equal(AccessSensitivity.Sensitive, resource!.Sensitivity);
        Assert.Equal(AccessOwnership.PerUser, resource.Ownership);
        Assert.Equal(AccessSource.Human, resource.Source);

        var identity = reloaded.FindIdentity("alice");
        Assert.NotNull(identity);
        Assert.Equal("customer", identity!.Role);
        Assert.Equal(1, identity.Tier);
        Assert.Contains("alice@test.com", identity.OwnerTags);
    }

    [Fact]
    public void UpsertResource_PersistsWithoutNeedingExplicitSave()
    {
        _store.UpsertResource("app.test", new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/api/x",
            Sensitivity = AccessSensitivity.Public
        });

        var reloaded = _store.Load("app.test");
        Assert.NotNull(reloaded);
        Assert.Single(reloaded!.Resources);
    }

    [Fact]
    public void UpsertIdentity_ReplacesExistingByName()
    {
        _store.UpsertIdentity("app.test", new AccessModelIdentity { Name = "bob", Tier = 1 });
        _store.UpsertIdentity("app.test", new AccessModelIdentity { Name = "bob", Tier = 2, Role = "admin" });

        var reloaded = _store.Load("app.test");
        Assert.NotNull(reloaded);
        Assert.Single(reloaded!.Identities);
        Assert.Equal(2, reloaded.Identities[0].Tier);
        Assert.Equal("admin", reloaded.Identities[0].Role);
    }

    [Fact]
    public void ListHosts_ReturnsAllPersistedHosts()
    {
        _store.Save(_store.GetOrCreate("a.test"));
        _store.Save(_store.GetOrCreate("b.test"));

        var hosts = _store.ListHosts();
        Assert.Contains("a.test", hosts);
        Assert.Contains("b.test", hosts);
    }

    [Fact]
    public void Delete_RemovesPersistedModel()
    {
        _store.Save(_store.GetOrCreate("app.test"));
        Assert.True(_store.Delete("app.test"));
        Assert.Null(_store.Load("app.test"));
        Assert.False(_store.Delete("app.test"));
    }

    [Theory]
    [InlineData("app.test", true)]
    [InlineData("app.test:8080", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidHost_ValidatesExpectedShapes(string? host, bool expected)
    {
        Assert.Equal(expected, AccessModelStore.IsValidHost(host));
    }
}
