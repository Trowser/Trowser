using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Trowser.Security;

/// <summary>
/// PKCS#12 import/export for SSL Manager — normalizes bundles for DPAPI storage and Schannel client TLS.
/// </summary>
internal static class SslPkcs12Helper
{
    private static X509KeyStorageFlags RuntimeImportFlags =>
        OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet
            : X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.EphemeralKeySet;

    private const X509KeyStorageFlags ValidateImportFlags =
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>Import with user password, then seal as empty-password PKCS#12 for DPAPI persistence.</summary>
    public static byte[] SealForStorage(byte[] pkcs12Bytes, string? password)
    {
        var bag = Import(pkcs12Bytes, password, ValidateImportFlags);
        try
        {
            if (!bag.Cast<X509Certificate2>().Any(static c => c.HasPrivateKey))
                throw new CryptographicException("The file does not contain a certificate with a private key.");

            return bag.Export(X509ContentType.Pkcs12, string.Empty)
                   ?? throw new CryptographicException("Failed to export client certificate for storage.");
        }
        finally
        {
            foreach (X509Certificate2 c in bag)
                c.Dispose();
        }
    }

    /// <summary>Load persisted PKCS#12 (re-sealed or legacy passwordless).</summary>
    public static bool TryLoadPersisted(byte[] pkcs12Bytes, out X509Certificate2Collection bag, out string? error)
    {
        error = null;
        bag = new X509Certificate2Collection();

        foreach (var pwd in new[] { string.Empty, (string?)null })
        {
            try
            {
                bag.Import(pkcs12Bytes, pwd, RuntimeImportFlags);
                if (bag.Cast<X509Certificate2>().Any(static c => c.HasPrivateKey))
                    return true;
                error = "PKCS#12 loaded but no certificate with a private key was found.";
                return false;
            }
            catch (CryptographicException ex) when (LooksLikePasswordRequired(ex))
            {
                error =
                    "This client certificate is stored in an older password-locked format and cannot be used for TLS. " +
                    "Remove it in SSL Manager (Settings) and add the .pfx/.p12 again — your password is only needed once at import.";
                return false;
            }
            catch (CryptographicException ex)
            {
                error = ex.Message;
                return false;
            }
        }

        error ??= "Failed to load PKCS#12 client certificate.";
        return false;
    }

    public static SslStreamCertificateContext? CreateClientContext(X509Certificate2Collection bag, out string? error)
    {
        error = null;
        X509Certificate2? leaf = null;
        var intermediates = new X509Certificate2Collection();

        foreach (X509Certificate2 c in bag)
        {
            if (c.HasPrivateKey)
            {
                if (leaf != null && !ReferenceEquals(leaf, c))
                {
                    error = "PKCS#12 contains more than one certificate with a private key.";
                    return null;
                }
                leaf = c;
            }
            else if (!IsLikelyRootCa(c))
            {
                intermediates.Add(c);
            }
        }

        if (leaf == null || !leaf.HasPrivateKey)
        {
            error = "No client certificate with a private key was found in the PKCS#12.";
            return null;
        }

        EnrichIntermediatesFromBuiltChain(leaf, intermediates);
        WindowsClientTlsBootstrap.EnsureSchannelStores(leaf, intermediates);

        Exception? last = null;
        foreach (var offline in new[] { false, true })
        {
            try
            {
                return SslStreamCertificateContext.Create(leaf, intermediates, offline);
            }
            catch (Exception ex)
            {
                last = ex;
            }
        }

        error = last?.Message ?? "Failed to create TLS client certificate context.";
        return null;
    }

    private static void EnrichIntermediatesFromBuiltChain(X509Certificate2 leaf, X509Certificate2Collection intermediates)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = false;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
                                              | X509VerificationFlags.IgnoreEndRevocationUnknown
                                              | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
        if (!chain.Build(leaf))
            return;

        var known = new HashSet<string>(
            intermediates.Cast<X509Certificate2>().Select(static c => c.Thumbprint),
            StringComparer.OrdinalIgnoreCase) { leaf.Thumbprint };

        foreach (var element in chain.ChainElements)
        {
            var c = element.Certificate;
            if (c.HasPrivateKey || known.Contains(c.Thumbprint) || IsLikelyRootCa(c))
                continue;
            intermediates.Add(c);
            known.Add(c.Thumbprint);
        }
    }

    private static X509Certificate2Collection Import(byte[] bytes, string? password, X509KeyStorageFlags flags)
    {
        var bag = new X509Certificate2Collection();
        bag.Import(bytes, password, flags);
        return bag;
    }

    private static bool LooksLikePasswordRequired(CryptographicException ex)
    {
        var msg = ex.Message;
        return msg.Contains("password", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("network password", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("networkslösenord", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("nätverkslösenord", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("PFX", StringComparison.OrdinalIgnoreCase)
               || ex.HResult is unchecked((int)0x80070056);
    }

    private static bool IsLikelyRootCa(X509Certificate2 cert)
    {
        if (string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase))
            return true;
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509BasicConstraintsExtension bc && bc.CertificateAuthority
                && string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}