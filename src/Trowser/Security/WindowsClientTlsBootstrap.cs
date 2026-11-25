using System.Security.Cryptography.X509Certificates;

namespace Trowser.Security;

/// <summary>
/// Schannel on Windows often requires the leaf and issuing CAs to be visible in the user certificate stores
/// even when using <see cref="System.Net.Security.SslStreamCertificateContext"/>.
/// </summary>
internal static class WindowsClientTlsBootstrap
{
    public static void EnsureSchannelStores(X509Certificate2 leaf, X509Certificate2Collection intermediates)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            using var my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadWrite);
            if (my.Certificates.Find(X509FindType.FindByThumbprint, leaf.Thumbprint, validOnly: false).Count == 0)
                my.Add(leaf);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Could not install client certificate leaf to CurrentUser\\My", ex);
        }

        try
        {
            using var ca = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            ca.Open(OpenFlags.ReadWrite);
            foreach (X509Certificate2 ic in intermediates)
            {
                if (ic.HasPrivateKey || IsLikelyRootCa(ic))
                    continue;
                if (ca.Certificates.Find(X509FindType.FindByThumbprint, ic.Thumbprint, validOnly: false).Count == 0)
                    ca.Add(ic);
            }
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Could not install client certificate intermediates to CurrentUser\\CertificateAuthority", ex);
        }
    }

    private static bool IsLikelyRootCa(X509Certificate2 cert) =>
        string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase);
}