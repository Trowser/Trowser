namespace Trowser.Security;

public sealed class IdentitySnapshot
{
    public string Name { get; set; } = "";
    public IdentityMetadata Metadata { get; set; } = new();
    public List<IdentityCookie> Cookies { get; set; } = [];
    public Dictionary<string, string> LocalStorage { get; set; } = new(StringComparer.Ordinal);
    public Dictionary<string, string> SessionStorage { get; set; } = new(StringComparer.Ordinal);
    public List<IdentityAuthHeader> AuthHeaders { get; set; } = [];
}

public sealed class IdentityMetadata
{
    public string? SessionName { get; set; }
    public DateTime CapturedAt { get; set; }
    public string? CurrentUrl { get; set; }
    public string? Domain { get; set; }
    public string? InferredMechanism { get; set; }
    public string? SessionCookie { get; set; }
    public int CookieCount { get; set; }
    public int LocalStorageCount { get; set; }
    public int SessionStorageCount { get; set; }
}

public sealed class IdentityCookie
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Path { get; set; } = "/";
    public bool Secure { get; set; }
    public bool HttpOnly { get; set; }
    public string SameSite { get; set; } = "lax";
    public bool Session { get; set; } = true;
    public string? Expires { get; set; }
}

public sealed class IdentityAuthHeader
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public string Host { get; set; } = "";
    public DateTime LastSeen { get; set; }
    public string? Url { get; set; }
}

public sealed class IdentityCatalogEntry
{
    public string Name { get; set; } = "";
    public DateTime CapturedAt { get; set; }
    public string? Domain { get; set; }
    public string? InferredMechanism { get; set; }
    public string? SessionName { get; set; }
    public int CookieCount { get; set; }
    public int LocalStorageCount { get; set; }
    public int SessionStorageCount { get; set; }
    public string? CurrentUrl { get; set; }
}

public sealed class IdentityApplyResult
{
    public bool Applied { get; set; }
    public bool Verified { get; set; }
    public int? VerifyStatus { get; set; }
    public string? VerifyError { get; set; }
    public string? NavigatedTo { get; set; }
    public int CookiesApplied { get; set; }
    public int LocalStorageApplied { get; set; }
    public int SessionStorageApplied { get; set; }
}

public sealed class IdentityHandoffState
{
    public string Name { get; init; } = "";
    public string Status { get; set; } = "waiting";
    public DateTime StartedAt { get; init; }
    public DateTime ExpiresAt { get; init; }
    public string? LivenessUrl { get; init; }
    public int BaselineCookieCount { get; init; }
    public string BaselineCookieFingerprint { get; init; } = "";
    public int BaselineLocalStorageCount { get; init; }
    public int BaselineSessionStorageCount { get; init; }
    public int? BaselineLivenessStatus { get; init; }
    public string? CapturedIdentity { get; set; }
    public string? Message { get; set; }
}
