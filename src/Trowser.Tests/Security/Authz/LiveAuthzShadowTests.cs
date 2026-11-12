using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Security;
using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class LiveAuthzShadowTests
{
    [Theory]
    [InlineData("XHR", true)]
    [InlineData("Fetch", true)]
    [InlineData("Document", true)]
    [InlineData("Script", false)]
    [InlineData("Stylesheet", false)]
    [InlineData("Image", false)]
    [InlineData("Font", false)]
    public void IsAuthzRelevantResourceType_OnlyApiLikeTypesAreRelevant(string resourceType, bool expected)
    {
        Assert.Equal(expected, LiveAuthzShadow.IsAuthzRelevantResourceType(resourceType));
    }

    [Theory]
    [InlineData("GET", "passive", true)]
    [InlineData("GET", "safe", true)]
    [InlineData("HEAD", "safe", true)]
    [InlineData("OPTIONS", "safe", true)]
    [InlineData("QUERY", "safe", true)]
    [InlineData("get", "safe", true)]
    public void IsMethodAllowed_ReadMethodsAlwaysAllowed(string method, string safetyMode, bool expected)
    {
        Assert.Equal(expected, LiveAuthzShadow.IsMethodAllowed(method, safetyMode));
    }

    [Theory]
    [InlineData("POST", "passive", false)]
    [InlineData("POST", "safe", false)]
    [InlineData("PUT", "safe", false)]
    [InlineData("DELETE", "safe", false)]
    [InlineData("POST", "active", true)]
    [InlineData("PATCH", "aggressive", true)]
    public void IsMethodAllowed_StateChangingMethodsRequireActiveOrAbove(string method, string safetyMode, bool expected)
    {
        Assert.Equal(expected, LiveAuthzShadow.IsMethodAllowed(method, safetyMode));
    }

    [Theory]
    [InlineData("/my-account", true)]
    [InlineData("/api/users/me", true)]
    [InlineData("/rest/user/whoami", true)]
    [InlineData("/accounting", false)]
    [InlineData("/orders/1", false)]
    public void IsSelfEndpoint_MatchesIdentityPagesOnly(string path, bool expected)
    {
        Assert.Equal(expected, LiveAuthzShadow.IsSelfEndpoint(path));
    }

    [Fact]
    public void Classify_WebSocketUpgrade_IsCoverageGap()
    {
        var shadow = NewShadow(out _);
        shadow.Configure(true, "safe");
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://app.test/socket",
            StatusCode = 101,
            ResourceType = "WebSocket"
        };

        Assert.Equal(AuthzShadowSkipReason.WebSocket, shadow.Classify(entry));
    }

    [Fact]
    public void NoteWebSocket_RecordsGapWithoutReplay()
    {
        var shadow = NewShadow(out _);
        shadow.Configure(true, "safe");
        shadow.NoteWebSocket("wss://app.test/socket.io/?sid=abc");
        shadow.NoteWebSocket("wss://app.test/socket.io/?sid=def");

        Assert.Equal(1, shadow.WebSocketGapCount);
        var skip = Assert.Single(shadow.GetSkips());
        Assert.Equal("websocket", skip.Kind);
        Assert.Equal("WS", skip.Method);
    }

    [Fact]
    public void Classify_SuccessfulPostAtSafe_IsSafetyMode()
    {
        var shadow = NewShadow(out _);
        shadow.Configure(true, "safe");
        var entry = new NetworkEntry
        {
            Method = "POST",
            Url = "https://app.test/login",
            StatusCode = 200,
            ResourceType = "Document"
        };

        Assert.Equal(AuthzShadowSkipReason.SafetyMode, shadow.Classify(entry));
    }

    [Fact]
    public void TemplatizePath_KeepsIdentityQueryAndDropsPresentationParams()
    {
        Assert.Equal("/order/details?orderId={id}",
            AttackSurfaceMapper.TemplatizePath("/order/details?orderId=0254809&utm=spring"));
        Assert.Equal("/catalog",
            AttackSurfaceMapper.TemplatizePath("/catalog?page=2&sort=name"));
        Assert.Equal("/api/orders/{id}",
            AttackSurfaceMapper.TemplatizePath("/api/orders/42"));
        Assert.Equal("/api/users/one/{email}/adminpermission",
            AttackSurfaceMapper.TemplatizePath("/api/users/one/alice.trowser.eval@example.com/adminpermission"));
        Assert.Equal("/api/users/one/{email}",
            AttackSurfaceMapper.TemplatizePath("/api/users/one/alice.trowser.eval%40example.com"));
    }

    [Fact]
    public void Classify_ApiCallLabeledOther_IsReplayed()
    {
        var shadow = NewShadow(out _);
        shadow.Configure(true, "safe");
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://app.test/api/products/views",
            StatusCode = 200,
            ResourceType = "Other",
            RequestHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig" }
        };

        Assert.Equal(AuthzShadowSkipReason.None, shadow.Classify(entry));
    }

    [Fact]
    public void Classify_ThirdPartyPixel_IsThirdParty()
    {
        var shadow = NewShadow(out _);
        shadow.Configure(true, "safe");
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://maps.googleapis.com/maps/api/mapsjs/gen_204?csp_test=true",
            StatusCode = 200,
            ResourceType = "Image"
        };

        Assert.Equal(AuthzShadowSkipReason.ThirdParty, shadow.Classify(entry, "https://brokencrystals.com/marketplace"));
    }

    [Fact]
    public void Classify_AuthenticatedImage_IsReplayed()
    {
        var shadow = NewShadow(out _);
        shadow.Configure(true, "safe");
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://app.test/api/users/one/a@b.co/photo",
            StatusCode = 204,
            ResourceType = "Other"
        };

        Assert.Equal(AuthzShadowSkipReason.None, shadow.Classify(entry));
        Assert.True(LiveAuthzShadow.ShouldReplayResource(new NetworkEntry
        {
            Method = "GET",
            Url = "https://app.test/api/file?path=1.png",
            StatusCode = 200,
            ResourceType = "Image",
            RequestHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer t" }
        }));
    }

    [Fact]
    public void RecommendClassification_NoIdIsPublic_LeakIsPerUser()
    {
        Assert.Equal("A", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.BolaSuspected, "/marketplace", identicalPublicDocument: true));
        Assert.Equal("A", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.BolaSuspected, "/swagger-json"));
        Assert.Equal("B", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.BolaSuspected, "/api/users/id/{id}"));
        Assert.Equal("B", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.ConfirmedLeak, "/"));
        Assert.Equal("B", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.SameShapeDifferentData, "/contacts"));
        Assert.Equal("B", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.FilteredResponse, "/contacts"));
        Assert.Equal("B", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.ReplayedWrite, "/contacts", method: "POST"));
        Assert.Equal("B", LiveAuthzShadow.RecommendClassification(AuthzVerdictKind.BolaSuspected, "/contacts", method: "POST"));
    }

    [Fact]
    public void Classify_ContactsLabeledOther_IsReplayed()
    {
        var shadow = NewShadow(out _);
        shadow.Configure(true, "safe");
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://thinking-tester-contact-list.herokuapp.com/contacts",
            StatusCode = 200,
            ResourceType = "Other"
        };

        Assert.Equal(AuthzShadowSkipReason.None, shadow.Classify(entry));
    }

    [Fact]
    public void ClassifyWriteReplay_OwnSuccessIsIsolatedWrite_TokenMatchStaysLeak()
    {
        var different = new AuthzVerdict
        {
            Kind = AuthzVerdictKind.SameShapeDifferentData,
            Confidence = "low",
            Reason = "could be the peer's own equivalent resource, or a partial leak."
        };
        var write = LiveAuthzShadow.ClassifyWriteReplay(different, "both", peerSucceeded: true);
        Assert.Equal(AuthzVerdictKind.ReplayedWrite, write.Kind);
        Assert.Contains("isolated write", write.Reason);

        var leak = new AuthzVerdict { Kind = AuthzVerdictKind.ConfirmedLeak, Confidence = "high", Reason = "owner token" };
        Assert.Equal(AuthzVerdictKind.ConfirmedLeak, LiveAuthzShadow.ClassifyWriteReplay(leak, "both", true).Kind);

        var none = LiveAuthzShadow.ClassifyWriteReplay(different, "none", peerSucceeded: true);
        Assert.Equal(AuthzVerdictKind.PeerUnauthenticated, none.Kind);
    }

    [Fact]
    public void ClassifyWriteReplay_PeerSucceededOwnerFailedOnNamedObject_IsBola()
    {
        var inconclusive = new AuthzVerdict
        {
            Kind = AuthzVerdictKind.Inconclusive,
            Confidence = "low",
            Reason = "Owner baseline was not a 2xx response (status 404); cannot judge cross-identity access."
        };

        var write = LiveAuthzShadow.ClassifyWriteReplay(
            inconclusive, "both", peerSucceeded: true, "/api/invoices/{id}",
            ownerSucceeded: false);

        Assert.Equal(AuthzVerdictKind.BolaSuspected, write.Kind);
        Assert.Equal("high", write.Confidence);
        Assert.Contains("before the owner", write.Reason);
    }

    [Fact]
    public void ClassifyWriteReplay_NamedObjectWithIdDelta_IsBola()
    {
        var different = new AuthzVerdict
        {
            Kind = AuthzVerdictKind.SameShapeDifferentData,
            Confidence = "medium",
            Reason = "same shape"
        };
        var owner = """{"id":"111","name":"Invoice","status":"saved"}""";
        var peer = """{"id":"222","name":"Invoice","status":"saved"}""";

        var write = LiveAuthzShadow.ClassifyWriteReplay(
            different, "both", peerSucceeded: true, "/api/invoices/{id}", owner, peer);

        Assert.Equal(AuthzVerdictKind.BolaSuspected, write.Kind);
        Assert.Equal("high", write.Confidence);
        Assert.Contains("specific object", write.Reason);
    }

    [Fact]
    public void ClassifyWriteReplay_CollectionCreateWithDifferentOwner_StaysIsolated()
    {
        var different = new AuthzVerdict
        {
            Kind = AuthzVerdictKind.SameShapeDifferentData,
            Confidence = "medium",
            Reason = "same shape"
        };
        var owner = """{"_id":"aaa","firstName":"Nia","owner":"alice"}""";
        var peer = """{"_id":"bbb","firstName":"Nia","owner":"bob"}""";

        var write = LiveAuthzShadow.ClassifyWriteReplay(
            different, "both", peerSucceeded: true, "/contacts", owner, peer);

        Assert.Equal(AuthzVerdictKind.ReplayedWrite, write.Kind);
        Assert.Contains("isolated write", write.Reason);
    }

    [Fact]
    public void ClassifyWriteReplay_CollectionCreateMatchingExceptId_SaysSo()
    {
        var different = new AuthzVerdict
        {
            Kind = AuthzVerdictKind.FilteredResponse,
            Confidence = "low",
            Reason = "different"
        };
        var owner = """{"id":"111","saved":true}""";
        var peer = """{"id":"222","saved":true}""";

        var write = LiveAuthzShadow.ClassifyWriteReplay(
            different, "both", peerSucceeded: true, "/api/save", owner, peer);

        Assert.Equal(AuthzVerdictKind.ReplayedWrite, write.Kind);
        Assert.Equal("medium", write.Confidence);
        Assert.Contains("match except an id", write.Reason);
    }

    [Fact]
    public void Register_LoopbackIp_IsRejectedAndNotStored()
    {
        var registry = new PeerRegistry();
        var stored = registry.Register(
            new PeerEntry { Name = "attacker", BaseUrl = "http://127.0.0.1:6924" },
            out var error);

        Assert.False(stored);
        Assert.Contains("localhost", error);
        Assert.Null(registry.Get("attacker"));

        Assert.True(registry.Register(
            new PeerEntry { Name = "attacker", BaseUrl = "http://localhost:6924" },
            out _));
    }

    [Fact]
    public void TemplatizePath_HexObjectId_IsIdNotToken()
    {
        Assert.Equal(
            "/contacts/{id}",
            AttackSurfaceMapper.TemplatizePath("/contacts/6abcce9ddc63e0001520ac1c"));
    }

    [Fact]
    public void Verdict_SerializesAsTheDocumentedName()
    {
        var result = new LiveAuthzShadowResult
        {
            Host = "example.com",
            Method = "GET",
            Url = "https://example.com/contacts",
            UrlTemplate = "/contacts",
            Peer = "attacker",
            Verdict = AuthzVerdictKind.BolaSuspected,
            Confidence = "low",
            Reason = "test"
        };
        var json = System.Text.Json.JsonSerializer.Serialize(result, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
        });
        Assert.Contains("\"verdict\":\"BolaSuspected\"", json);
    }

    [Fact]
    public void BearerFromCookieJson_UsesTokenCookie()
    {
        var json = """{"data":{"cookies":[{"name":"token","value":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig"}]}}""";
        Assert.Equal(
            "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig",
            PeerAuthMaterial.BearerFromCookieJson(json));
    }

    [Fact]
    public void ExtractIdentityTokens_HarvestsEmailAndIdFromAuthenticatedUserJson()
    {
        var body = """{"email":"alice.trowser.eval@example.com","userName":"Alice","id":23487,"userId":"u-alice"}""";
        var tokens = LiveAuthzShadow.ExtractIdentityTokens(body);
        Assert.Contains("alice.trowser.eval@example.com", tokens);
        Assert.Contains("u-alice", tokens);
        Assert.DoesNotContain("23487", tokens);
    }

    [Fact]
    public void ExtractIdentityTokens_HarvestsEmailsInsideArrays_NotRecordIds()
    {
        var body = """[{"email":"ada.private@example.test","id":"1001"},{"email":"bob@example.test","id":"1002"}]""";
        var tokens = LiveAuthzShadow.ExtractIdentityTokens(body);
        Assert.Contains("ada.private@example.test", tokens);
        Assert.Contains("bob@example.test", tokens);
        Assert.DoesNotContain("1001", tokens);
    }

    [Fact]
    public void PromoteMissingAuth_SameBodyWithoutPeerSession_IsConfirmedLeak()
    {
        var same = new AuthzVerdict
        {
            Kind = AuthzVerdictKind.BolaSuspected,
            Confidence = "low",
            Reason = "No id in the path; identical content is not by itself per-user data."
        };

        var leak = LiveAuthzShadow.PromoteMissingAuth(same, "none", ownerHadCredential: true, peerSucceeded: true, htmlDocument: false);
        Assert.Equal(AuthzVerdictKind.ConfirmedLeak, leak.Kind);
        Assert.Equal("high", leak.Confidence);
        Assert.Contains("no session", leak.Reason);

        var room = LiveAuthzShadow.PromoteMissingAuth(same, "none", ownerHadCredential: false, peerSucceeded: true, htmlDocument: false);
        Assert.Equal(AuthzVerdictKind.BolaSuspected, room.Kind);

        var shell = LiveAuthzShadow.PromoteMissingAuth(same, "none", ownerHadCredential: true, peerSucceeded: true, htmlDocument: true);
        Assert.Equal(AuthzVerdictKind.BolaSuspected, shell.Kind);
    }

    [Fact]
    public void IsOwnerBodyMissing_NullBodyOn200_IsMissing_ContentLengthZeroIsNot()
    {
        Assert.True(LiveAuthzShadow.IsOwnerBodyMissing(new NetworkEntry
        {
            Method = "GET",
            Url = "https://app.test/",
            StatusCode = 200
        }));
        Assert.False(LiveAuthzShadow.IsOwnerBodyMissing(new NetworkEntry
        {
            Method = "GET",
            Url = "https://app.test/",
            StatusCode = 200,
            ResponseHeaders = new Dictionary<string, string> { ["Content-Length"] = "0" }
        }));
    }

    [Fact]
    public void DemoteUnauthenticatedDeny_DoesNotCallACredentialLess403Correct()
    {
        var denied = new AuthzVerdict
        {
            Kind = AuthzVerdictKind.ProperlyDenied,
            Confidence = "high",
            Reason = "Peer got HTTP 403 while the owner session succeeded — access correctly denied."
        };

        var demoted = PeerAuthMaterial.DemoteUnauthenticatedDeny(denied, "none");
        Assert.Equal(AuthzVerdictKind.Inconclusive, demoted.Kind);
        Assert.DoesNotContain("correctly denied", demoted.Reason, StringComparison.OrdinalIgnoreCase);

        var kept = PeerAuthMaterial.DemoteUnauthenticatedDeny(denied, "bearer");
        Assert.Equal(AuthzVerdictKind.ProperlyDenied, kept.Kind);
    }

    [Fact]
    public void MergeReplayHeaders_InstallsPeerBearer_NotTheOwnerToken()
    {
        var owner = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Authorization"] = "Bearer owner-token",
            ["Accept"] = "application/json"
        };
        var peer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Authorization"] = "Bearer peer-token"
        };

        var merged = PeerAuthMaterial.MergeReplayHeaders(
            AuthzComparisonService.SanitizeReplayHeaders(owner),
            owner,
            peer,
            out var applied);

        Assert.True(applied);
        Assert.Equal("Bearer peer-token", merged!["Authorization"]);
        Assert.Equal("bearer", PeerAuthMaterial.ClassifyApplied(true, applied, cookiesSent: false));
        Assert.Equal("both", PeerAuthMaterial.ClassifyApplied(true, applied, cookiesSent: true));
        Assert.Equal("none", PeerAuthMaterial.ClassifyApplied(true, peerHeaderApplied: false, cookiesSent: true));
    }

    [Fact]
    public void BearerFromStorage_PrefersJwtInSessionStorageShape()
    {
        var token = PeerAuthMaterial.BearerFromStorage(new Dictionary<string, string>
        {
            ["email"] = "alice@example.com",
            ["token"] = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature"
        });

        Assert.Equal("Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature", token);
    }

    [Fact]
    public void WithStorageToken_KeepsSessionCookieName()
    {
        var merged = SessionIdentityIntrospection.WithStorageToken(new SessionIdentityIntrospection.MechanismInfo("session-cookie", "connect.sid"));
        Assert.Equal("storage-token", merged.Mechanism);
        Assert.Equal("connect.sid", merged.SessionCookie);
    }

    [Fact]
    public void Analyze_BearerOnSuccess_MarksAuthRequired()
    {
        var mapper = new AttackSurfaceMapper();
        var result = mapper.Analyze(
        [
            new NetworkEntry
            {
                Method = "GET",
                Url = "https://app.test/api/products/views",
                StatusCode = 200,
                ResourceType = "Other",
                RequestHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer abc" }
            }
        ]);

        Assert.Single(result.Endpoints);
        Assert.True(result.Endpoints[0].Auth.Required);
    }

    [Theory]
    [InlineData("example.com:443", "example.com")]
    [InlineData("example.com:80", "example.com")]
    [InlineData("https://brokencrystals.com/marketplace", "brokencrystals.com")]
    [InlineData("127.0.0.1:8099", "127.0.0.1:8099")]
    [InlineData("http://127.0.0.1:8099/api", "127.0.0.1:8099")]
    public void AuthzHostKey_CollapsesDefaultPortsOnly(string input, string expected)
    {
        Assert.Equal(expected, AuthzHostKey.Canonical(input));
    }

    [Fact]
    public void ImportBundle_RestoresResultsAndDoesNotDowngradeHumanClassification()
    {
        var shadow = NewShadow(out var store);
        store.UpsertResource("app.test", new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/order/details?orderId={id}",
            Sensitivity = AccessSensitivity.Public,
            Ownership = AccessOwnership.Shared,
            Source = AccessSource.Human,
            Confidence = 1.0
        });

        var bundle = new AuthzShadowBundle
        {
            Models =
            [
                new AccessModel
                {
                    Host = "app.test",
                    Identities =
                    [
                        new AccessModelIdentity { Name = "self", Role = "customer", Tier = 1, OwnerTags = ["ada"] }
                    ],
                    Resources = new Dictionary<string, AccessModelResource>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["GET /order/details?orderId={id}"] = new AccessModelResource
                        {
                            Method = "GET",
                            UrlTemplate = "/order/details?orderId={id}",
                            Sensitivity = AccessSensitivity.Sensitive,
                            Ownership = AccessOwnership.PerUser,
                            Source = AccessSource.Heuristic,
                            Confidence = 0.25
                        }
                    }
                }
            ],
            Results =
            [
                new LiveAuthzShadowResult
                {
                    Host = "app.test",
                    Method = "GET",
                    Url = "https://app.test/order/details?orderId=1",
                    UrlTemplate = "/order/details?orderId={id}",
                    Peer = "peer1",
                    Verdict = AuthzVerdictKind.BolaSuspected,
                    Confidence = "medium",
                    Reason = "near-identical length",
                    NeedsClassification = true,
                    OwnerStatus = 200,
                    PeerStatus = 200,
                    OwnerBodyLength = 100,
                    PeerBodyLength = 100,
                    OwnerTokenCount = 1
                }
            ]
        };

        shadow.ImportBundle(bundle, replaceResults: true);

        var saved = store.Load("app.test");
        var resource = saved!.FindResource("GET", "/order/details?orderId={id}");
        Assert.Equal(AccessSource.Human, resource!.Source);
        Assert.Equal(AccessSensitivity.Public, resource.Sensitivity);
        Assert.Contains("ada", saved.FindIdentity("self")!.OwnerTags);

        var exported = shadow.ExportBundle();
        Assert.Single(exported.Results);
        Assert.Equal(200, exported.Results[0].OwnerStatus);
        Assert.Equal(200, exported.Results[0].PeerStatus);

        var roundTrip = JsonSerializer.Deserialize<AuthzShadowBundle>(
            JsonSerializer.Serialize(exported, AuthzShadowBundle.JsonOptions),
            AuthzShadowBundle.JsonOptions);
        Assert.NotNull(roundTrip);
        Assert.Equal(AuthzVerdictKind.BolaSuspected, roundTrip!.Results[0].Verdict);
        Assert.Equal(100, roundTrip.Results[0].PeerBodyLength);

        shadow.ImportBundle(exported, replaceResults: false);
        Assert.Single(shadow.GetResults());
    }

    [Fact]
    public void HasCommittedClassification_IgnoresHeuristicSeeds()
    {
        Assert.False(LiveAuthzShadow.HasCommittedClassification(null));
        Assert.False(LiveAuthzShadow.HasCommittedClassification(new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/products",
            Sensitivity = AccessSensitivity.Public,
            Ownership = AccessOwnership.Shared,
            Source = AccessSource.Heuristic
        }));
        Assert.True(LiveAuthzShadow.HasCommittedClassification(new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/products",
            Sensitivity = AccessSensitivity.Public,
            Ownership = AccessOwnership.Shared,
            Source = AccessSource.Human,
            Confidence = 1
        }));
    }

    [Fact]
    public void ClassifyResource_DropsMatchingResultsFromNeedsClassification()
    {
        var shadow = NewShadow(out var store);
        shadow.ImportBundle(new AuthzShadowBundle
        {
            Results =
            [
                Result("peer-a"),
                Result("peer-b")
            ]
        }, replaceResults: true);

        shadow.ClassifyResource("app.test", "GET", "/orders/{id}", AccessSensitivity.Sensitive, AccessOwnership.PerUser);

        Assert.All(shadow.GetResults(), r => Assert.False(r.NeedsClassification));
        Assert.Equal("deny-cross-owner", shadow.GetResults()[0].ExpectedOutcome);
        var session = shadow.FindSessionClassification("app.test", "GET", "/orders/{id}");
        Assert.Equal(AccessSource.Human, session!.Source);
        Assert.Equal(AccessOwnership.PerUser, session.Ownership);
        Assert.Null(store.Load("app.test")?.FindResource("GET", "/orders/{id}"));

        var exported = shadow.ExportBundle();
        var exportedResource = exported.Models.SelectMany(m => m.Resources.Values).Single();
        Assert.Equal(AccessOwnership.PerUser, exportedResource.Ownership);

        shadow.ClearResults();
        Assert.Null(shadow.FindSessionClassification("app.test", "GET", "/orders/{id}"));

        var restarted = new LiveAuthzShadow(store);
        Assert.Null(restarted.FindSessionClassification("app.test", "GET", "/orders/{id}"));
    }

    private static LiveAuthzShadowResult Result(string peer) => new()
    {
        Host = "app.test",
        Method = "GET",
        Url = "https://app.test/orders/1",
        UrlTemplate = "/orders/{id}",
        Peer = peer,
        Verdict = AuthzVerdictKind.BolaSuspected,
        Confidence = "medium",
        Reason = "near-identical body",
        NeedsClassification = true
    };

    private static LiveAuthzShadow NewShadow(out AccessModelStore store)
    {
        var dir = Path.Combine(Path.GetTempPath(), "trowser-authz-" + Guid.NewGuid().ToString("n"));
        store = new AccessModelStore(dir);
        return new LiveAuthzShadow(store);
    }
}
