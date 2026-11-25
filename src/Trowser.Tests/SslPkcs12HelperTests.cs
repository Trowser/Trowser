using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class SslPkcs12HelperTests
{
    [Fact]
    public void SealForStorage_PasswordProtectedPfx_ReloadsWithoutPassword()
    {
        var password = "test-password";
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Trowser-Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var protectedBytes = cert.Export(X509ContentType.Pkcs12, password);

        var sealedBytes = SslPkcs12Helper.SealForStorage(protectedBytes, password);

        Assert.True(SslPkcs12Helper.TryLoadPersisted(sealedBytes, out var bag, out var error), error);
        try
        {
            var ctx = SslPkcs12Helper.CreateClientContext(bag, out var ctxError);
            Assert.NotNull(ctx);
            Assert.Null(ctxError);
            Assert.True(ctx!.TargetCertificate.HasPrivateKey);
        }
        finally
        {
            foreach (X509Certificate2 c in bag)
                c.Dispose();
        }
    }

    [Fact]
    public void TryLoadPersisted_LegacyPasswordLockedPfx_ReturnsReimportMessage()
    {
        var password = "locked";
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Trowser-Legacy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var protectedBytes = cert.Export(X509ContentType.Pkcs12, password);

        Assert.False(SslPkcs12Helper.TryLoadPersisted(protectedBytes, out _, out var error));
        Assert.Contains("add the .pfx", error, StringComparison.OrdinalIgnoreCase);
    }
}