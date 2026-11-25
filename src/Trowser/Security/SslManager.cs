using System.IO;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trowser.Security;

/// <summary>
/// Manages SSL client certificates for mutual TLS.
/// Supports .pfx and .p12 formats. Stores PKCS#12 bytes encrypted with DPAPI.
/// Provides the active certificate for WebView2 (browser navigation) and outbound HttpClient / raw TLS (via <see cref="ClientTlsHelper"/>).
/// </summary>
public class SslManager
{
    private readonly List<SslCertificateEntry> _certificates = new();
    private readonly object _lock = new();
    private string? _activeAlias;
    private SslStreamCertificateContext? _cachedClientContext;
    private X509Certificate2Collection? _cachedCertificateBag;
    private string? _cachedClientContextAlias;
    private string? _lastTlsLoadError;

    /// <summary>All loaded certificates (thread-safe snapshot).</summary>
    public IReadOnlyList<SslCertificateEntry> Certificates
    {
        get { lock (_lock) return _certificates.ToList().AsReadOnly(); }
    }

    /// <summary>Alias of the currently active certificate, or null if none.</summary>
    public string? ActiveAlias
    {
        get { lock (_lock) return _activeAlias; }
    }

    /// <summary>
    /// Add a certificate from a .pfx/.p12 file.
    /// The PKCS#12 bytes are encrypted with DPAPI and stored; the original file is not needed afterwards.
    /// </summary>
    /// <param name="filePath">Path to .pfx or .p12 file.</param>
    /// <param name="password">Password for the PKCS#12 file.</param>
    /// <param name="alias">User-friendly alias. Auto-generated from filename if null.</param>
    /// <returns>Info about the added certificate.</returns>
    public SslCertificateInfo AddCertificate(string filePath, string password, string? alias = null)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path is required.");

        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Certificate file not found: {filePath}");

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext == ".jks")
            throw new NotSupportedException(
                "JKS (Java KeyStore) format is not directly supported. " +
                "Convert to PKCS#12 (.p12) first using: keytool -importkeystore -srckeystore keystore.jks " +
                "-destkeystore keystore.p12 -deststoretype PKCS12");
        if (ext is not ".pfx" and not ".p12")
            throw new NotSupportedException($"Unsupported certificate format: {ext}. Use .pfx or .p12 files.");

        var pkcs12Bytes = File.ReadAllBytes(filePath);

        byte[] sealedPkcs12;
        string thumbprint;
        string subject;
        string issuer;
        DateTime notAfter;
        DateTime notBefore;
        try
        {
            sealedPkcs12 = SslPkcs12Helper.SealForStorage(pkcs12Bytes, password);
            var metaBag = new X509Certificate2Collection();
            metaBag.Import(sealedPkcs12, string.Empty,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
            try
            {
                var leafMeta = metaBag.Cast<X509Certificate2>().FirstOrDefault(static c => c.HasPrivateKey)
                               ?? throw new CryptographicException("No certificate with a private key.");
                thumbprint = leafMeta.Thumbprint;
                subject = leafMeta.Subject;
                issuer = leafMeta.Issuer;
                notAfter = leafMeta.NotAfter.ToUniversalTime();
                notBefore = leafMeta.NotBefore.ToUniversalTime();
            }
            finally
            {
                foreach (X509Certificate2 c in metaBag)
                    c.Dispose();
            }
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException($"Failed to load certificate. Wrong password or invalid file? {ex.Message}");
        }

        var resolvedAlias = alias?.Trim();
        if (string.IsNullOrWhiteSpace(resolvedAlias))
            resolvedAlias = Path.GetFileNameWithoutExtension(filePath);

        lock (_lock)
        {
            // Ensure unique alias
            if (_certificates.Any(c => c.Alias.Equals(resolvedAlias, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException($"A certificate with alias '{resolvedAlias}' already exists. Use a different alias.");

            // DPAPI protects password-free PKCS#12 (full chain). Original .pfx password is not stored.
            var encrypted = ProtectedData.Protect(sealedPkcs12, null, DataProtectionScope.CurrentUser);

            var entry = new SslCertificateEntry
            {
                Alias = resolvedAlias,
                OriginalFileName = Path.GetFileName(filePath),
                EncryptedPkcs12Base64 = Convert.ToBase64String(encrypted),
                Thumbprint = thumbprint,
                Subject = subject,
                Issuer = issuer,
                NotAfter = notAfter,
                NotBefore = notBefore,
                AddedAt = DateTime.UtcNow
            };

            _certificates.Add(entry);
            InvalidateClientCertificateContext();
            Save();

            return SslCertificateInfo.FromEntry(entry, _activeAlias == resolvedAlias);
        }
    }

    /// <summary>Remove a certificate by alias.</summary>
    public bool RemoveCertificate(string alias)
    {
        if (string.IsNullOrWhiteSpace(alias))
            throw new ArgumentException("Alias is required.");

        lock (_lock)
        {
            var entry = _certificates.FirstOrDefault(c => c.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase));
            if (entry == null) return false;

            _certificates.Remove(entry);
            if (_activeAlias?.Equals(alias, StringComparison.OrdinalIgnoreCase) == true)
                _activeAlias = null;

            InvalidateClientCertificateContext();
            Save();
            return true;
        }
    }

    /// <summary>Set the active certificate by alias. Pass null or empty to clear.</summary>
    public SslCertificateInfo? SetActive(string? alias)
    {
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(alias))
            {
                _activeAlias = null;
                InvalidateClientCertificateContext();
                Save();
                return null;
            }

            var entry = _certificates.FirstOrDefault(c => c.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase));
            if (entry == null)
                throw new KeyNotFoundException($"No certificate found with alias '{alias}'.");

            _activeAlias = entry.Alias;
            InvalidateClientCertificateContext();
            Save();
            return SslCertificateInfo.FromEntry(entry, true);
        }
    }

    /// <summary>Get info about the active certificate, or null if none.</summary>
    public SslCertificateInfo? GetActive()
    {
        lock (_lock)
        {
            if (_activeAlias == null) return null;
            var entry = _certificates.FirstOrDefault(c => c.Alias.Equals(_activeAlias, StringComparison.OrdinalIgnoreCase));
            return entry == null ? null : SslCertificateInfo.FromEntry(entry, true);
        }
    }

    /// <summary>List all certificates as public DTOs (no secrets).</summary>
    public List<SslCertificateInfo> ListCertificates()
    {
        lock (_lock)
        {
            return _certificates.Select(c =>
                SslCertificateInfo.FromEntry(c, _activeAlias?.Equals(c.Alias, StringComparison.OrdinalIgnoreCase) == true)
            ).ToList();
        }
    }

    /// <summary>
    /// Schannel-ready client cert context for the active PKCS#12 (leaf + intermediates).
    /// Returns null when nothing is active or the store cannot be decrypted.
    /// </summary>
    /// <summary>Error from the last failed TLS load of the active cert, or null if load succeeded / nothing active.</summary>
    public string? GetActiveClientTlsLoadError()
    {
        lock (_lock)
        {
            if (_activeAlias == null)
                return null;
            if (GetActiveClientCertificateContext() != null)
                return null;
            return _lastTlsLoadError ?? "The active client certificate could not be loaded for TLS.";
        }
    }

    public SslStreamCertificateContext? GetActiveClientCertificateContext()
    {
        lock (_lock)
        {
            if (_activeAlias == null)
            {
                _lastTlsLoadError = null;
                InvalidateClientCertificateContext();
                return null;
            }

            if (_cachedClientContext != null &&
                _cachedClientContextAlias?.Equals(_activeAlias, StringComparison.OrdinalIgnoreCase) == true)
                return _cachedClientContext;

            InvalidateClientCertificateContext();
            _lastTlsLoadError = null;

            var entry = _certificates.FirstOrDefault(c =>
                c.Alias.Equals(_activeAlias, StringComparison.OrdinalIgnoreCase));
            if (entry == null)
            {
                _lastTlsLoadError = $"Active alias '{_activeAlias}' was not found in the certificate list.";
                return null;
            }

            try
            {
                var encrypted = Convert.FromBase64String(entry.EncryptedPkcs12Base64);
                var pkcs12Bytes = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);

                if (!SslPkcs12Helper.TryLoadPersisted(pkcs12Bytes, out var bag, out var importError))
                {
                    _lastTlsLoadError = importError;
                    TrowserLog.Error($"Active client certificate '{entry.Alias}': {importError}");
                    return null;
                }

                var ctx = SslPkcs12Helper.CreateClientContext(bag, out var ctxError);
                if (ctx == null)
                {
                    DisposeCertificateBag(bag);
                    _lastTlsLoadError = ctxError ?? "Failed to create TLS client certificate context.";
                    TrowserLog.Error($"Active client certificate '{entry.Alias}': {_lastTlsLoadError}");
                    return null;
                }

                _cachedCertificateBag = bag;
                _cachedClientContext = ctx;
                _cachedClientContextAlias = _activeAlias;
                return _cachedClientContext;
            }
            catch (Exception ex)
            {
                _lastTlsLoadError = ex.Message;
                TrowserLog.Error($"Failed to load active client certificate '{entry.Alias}'", ex);
                return null;
            }
        }
    }

    /// <summary>Leaf certificate for the active client cert, if any.</summary>
    public X509Certificate2? GetActiveX509Certificate() =>
        GetActiveClientCertificateContext()?.TargetCertificate;

    /// <summary>One-line summary for UI when mutual TLS is active (no secrets).</summary>
    public string? GetActiveClientTlsSummary()
    {
        var ctx = GetActiveClientCertificateContext();
        if (ctx == null)
            return null;
        var leaf = ctx.TargetCertificate;
        var cn = TryGetCommonName(leaf.Subject);
        var intermediateCount = ctx.IntermediateCertificates.Count;
        return string.IsNullOrEmpty(cn)
            ? $"Client certificate: {leaf.Thumbprint} (+{intermediateCount} issuing CA certs)"
            : $"Client certificate: {cn} (+{intermediateCount} issuing CA certs)";
    }

    private static string? TryGetCommonName(string subject)
    {
        foreach (var part in subject.Split(',', StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return part[3..];
        }
        return null;
    }

    private void InvalidateClientCertificateContext()
    {
        DisposeCertificateBag(_cachedCertificateBag);
        _cachedCertificateBag = null;
        _cachedClientContext = null;
        _cachedClientContextAlias = null;
        _lastTlsLoadError = null;
    }

    private static void DisposeCertificateBag(X509Certificate2Collection? bag)
    {
        if (bag == null) return;
        foreach (X509Certificate2 c in bag)
            c.Dispose();
        bag.Clear();
    }

    /// <summary>Get the thumbprint of the active certificate (for WebView2 matching).</summary>
    public string? GetActiveThumbprint()
    {
        lock (_lock)
        {
            if (_activeAlias == null) return null;
            return _certificates
                .FirstOrDefault(c => c.Alias.Equals(_activeAlias, StringComparison.OrdinalIgnoreCase))
                ?.Thumbprint;
        }
    }

    #region Persistence

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private static string StatePath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "ssl-certificates.json");
        }
    }

    private void Save()
    {
        try
        {
            var state = new SslManagerState
            {
                Certificates = _certificates.ToList(),
                ActiveAlias = _activeAlias
            };
            var json = JsonSerializer.Serialize(state, JsonOptions);
            File.WriteAllText(StatePath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save SSL certificates", ex);
        }
    }

    /// <summary>Load persisted certificates from disk.</summary>
    public static SslManager Load()
    {
        var manager = new SslManager();
        try
        {
            if (File.Exists(StatePath))
            {
                var json = File.ReadAllText(StatePath);
                var state = JsonSerializer.Deserialize<SslManagerState>(json, JsonOptions);
                if (state != null)
                {
                    manager._certificates.AddRange(state.Certificates);
                    manager._activeAlias = state.ActiveAlias;
                }
            }
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to load SSL certificates", ex);
        }
        return manager;
    }

    #endregion
}
