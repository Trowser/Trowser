namespace Trowser.Security.Authz;

/// <summary>How sensitive a resource's data is, as declared by heuristics or a human/AI answer.</summary>
public enum AccessSensitivity
{
    Unknown,
    Public,
    Internal,
    Sensitive
}

/// <summary>Who is allowed to see a resource's data, as declared by heuristics or a human/AI answer.</summary>
public enum AccessOwnership
{
    Unknown,
    /// <summary>Anyone (including anonymous) may see it.</summary>
    Shared,
    /// <summary>Only the resource's owner (the identity that created/owns it) may see it.</summary>
    PerUser,
    /// <summary>Only members of the owning tenant/org may see it.</summary>
    PerTenant,
    /// <summary>Only identities at or above a minimum role tier may see it.</summary>
    RoleGated
}

/// <summary>Who — or what — set an <see cref="AccessModelResource"/>'s classification.</summary>
public enum AccessSource
{
    /// <summary>Pre-filled from attack-surface heuristics; low confidence, never a hard finding.</summary>
    Heuristic,
    /// <summary>Inferred from an actually-observed cross-identity response.</summary>
    Observed,
    /// <summary>A human answered a review-lane Decision.</summary>
    Human,
    /// <summary>An AI/agent answered a review-lane Decision via <c>AnsweredBy</c>.</summary>
    Ai
}

/// <summary>
/// A captured/peer identity as known to the access model: its role, a coarse privilege tier used
/// to evaluate <see cref="AccessOwnership.RoleGated"/> resources, and any owner tags (ids, emails,
/// usernames) that let the live shadow recognize when a peer response leaked *this* identity's data.
/// </summary>
public sealed class AccessModelIdentity
{
    public required string Name { get; set; }

    /// <summary>Free-text role label (e.g. "admin", "customer"). Informational — <see cref="Tier"/> drives comparisons.</summary>
    public string? Role { get; set; }

    /// <summary>Coarse privilege ordering: anonymous = 0, standard user = 1, admin/elevated = 2 (or higher).</summary>
    public int Tier { get; set; }

    /// <summary>Ids/emails/usernames that identify this identity's own data in a response body.</summary>
    public List<string> OwnerTags { get; set; } = [];
}

/// <summary>
/// The declared intent for one <c>(method, urlTemplate)</c> resource: how sensitive its data is,
/// who should be able to see it, and how confident/provenanced that classification is. This is
/// the intent <see cref="LiveAuthzShadow"/> compares traffic against.
/// </summary>
public sealed class AccessModelResource
{
    public required string Method { get; set; }
    public required string UrlTemplate { get; set; }

    public AccessSensitivity Sensitivity { get; set; } = AccessSensitivity.Unknown;
    public AccessOwnership Ownership { get; set; } = AccessOwnership.Unknown;
    public AccessSource Source { get; set; } = AccessSource.Heuristic;

    /// <summary>0.0-1.0. Heuristic seeding is always low confidence; human/AI answers are 1.0.</summary>
    public double Confidence { get; set; }

    public string? Notes { get; set; }
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Dictionary key: <c>"{METHOD} {urlTemplate}"</c>, case-insensitive on method.</summary>
    public static string KeyOf(string method, string urlTemplate) =>
        $"{method.Trim().ToUpperInvariant()} {urlTemplate.Trim()}";

    public string Key => KeyOf(Method, UrlTemplate);

    /// <summary>
    /// The derived expectation for what a live shadow replay from a *different* identity than the
    /// owner should see. Not hand-authored — computed from <see cref="Sensitivity"/> and
    /// <see cref="Ownership"/> so the model stays small and consistent.
    /// </summary>
    public string ExpectedCrossIdentityOutcome => (Sensitivity, Ownership) switch
    {
        (AccessSensitivity.Sensitive, AccessOwnership.PerUser) => "deny-cross-owner",
        (AccessSensitivity.Sensitive, AccessOwnership.PerTenant) => "deny-cross-tenant",
        (_, AccessOwnership.RoleGated) => "deny-below-tier",
        (AccessSensitivity.Public, _) => "allow",
        (_, AccessOwnership.Shared) => "allow",
        _ => "unknown"
    };

    /// <summary>True while intent has not been classified by any source — the "needs classification" bucket.</summary>
    public bool IsUnclassified => Sensitivity == AccessSensitivity.Unknown && Ownership == AccessOwnership.Unknown;
}

/// <summary>A request Live Authz Shadow declined to replay, kept with the access model.</summary>
public sealed class AccessModelSkip
{
    public required string Method { get; set; }
    public required string UrlTemplate { get; set; }

    /// <summary><c>safety</c>, <c>resourceType</c>, <c>nonSuccess</c>, or <c>thirdParty</c>.</summary>
    public required string Kind { get; set; }
}

/// <summary>
/// The persisted access model for one host: declared identities and per-resource intent. See
/// <see cref="AccessModelStore"/> for persistence and <see cref="AccessModelSeeder"/> for heuristic
/// pre-fill from the attack surface map.
/// </summary>
public sealed class AccessModel
{
    public required string Host { get; set; }
    public List<AccessModelIdentity> Identities { get; set; } = [];
    public Dictionary<string, AccessModelResource> Resources { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Requests the shadow saw and did not replay. Survives a result clear so coverage can still say why.</summary>
    public List<AccessModelSkip> SkippedRequests { get; set; } = [];

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public AccessModelResource? FindResource(string method, string urlTemplate) =>
        Resources.GetValueOrDefault(AccessModelResource.KeyOf(method, urlTemplate));

    public AccessModelIdentity? FindIdentity(string name) =>
        Identities.FirstOrDefault(i => i.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
}
