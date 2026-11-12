using System.Text.Json.Serialization;

namespace Trowser.Security;

/// <summary>
/// Internal model for a stored SSL client certificate.
/// Persisted to disk with DPAPI-encrypted PKCS#12 bytes.
/// </summary>
public class SslCertificateEntry
{
    /// <summary>User-friendly alias for quick switching (unique key for API/MCP/scripting).</summary>
    public string Alias { get; set; } = "";

    /// <summary>Original file name (for display only — not used at runtime).</summary>
    public string OriginalFileName { get; set; } = "";

    /// <summary>PKCS#12 (.pfx/.p12) bytes, encrypted with DPAPI (CurrentUser scope). Base64 encoded for JSON storage.</summary>
    public string EncryptedPkcs12Base64 { get; set; } = "";

    /// <summary>X.509 certificate thumbprint (SHA-1 hex). Used for matching in WebView2 ClientCertificateRequested.</summary>
    public string Thumbprint { get; set; } = "";

    /// <summary>Certificate subject distinguished name.</summary>
    public string Subject { get; set; } = "";

    /// <summary>Certificate issuer distinguished name.</summary>
    public string Issuer { get; set; } = "";

    /// <summary>Certificate not-valid-after date.</summary>
    public DateTime NotAfter { get; set; }

    /// <summary>Certificate not-valid-before date.</summary>
    public DateTime NotBefore { get; set; }

    /// <summary>When the certificate was added to the manager.</summary>
    public DateTime AddedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Public DTO returned by API/MCP/scripting — never includes secrets.
/// </summary>
public class SslCertificateInfo
{
    public string Alias { get; set; } = "";
    public string OriginalFileName { get; set; } = "";
    public string Thumbprint { get; set; } = "";
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public DateTime NotAfter { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime AddedAt { get; set; }
    public bool IsActive { get; set; }
    public bool IsExpired => DateTime.UtcNow > NotAfter;

    public static SslCertificateInfo FromEntry(SslCertificateEntry entry, bool isActive) => new()
    {
        Alias = entry.Alias,
        OriginalFileName = entry.OriginalFileName,
        Thumbprint = entry.Thumbprint,
        Subject = entry.Subject,
        Issuer = entry.Issuer,
        NotAfter = entry.NotAfter,
        NotBefore = entry.NotBefore,
        AddedAt = entry.AddedAt,
        IsActive = isActive
    };
}

/// <summary>
/// Persisted state for the SSL Manager.
/// </summary>
public class SslManagerState
{
    public List<SslCertificateEntry> Certificates { get; set; } = new();
    public string? ActiveAlias { get; set; }
}
