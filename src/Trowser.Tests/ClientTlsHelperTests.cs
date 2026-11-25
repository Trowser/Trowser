using System.Net.Http;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class ClientTlsHelperTests
{
    [Fact]
    public void ApplyActiveClientCertificate_WithNullManager_DoesNotThrow()
    {
        using var handler = new System.Net.Http.SocketsHttpHandler();
        ClientTlsHelper.ApplyActiveClientCertificate(handler, null);
        Assert.Null(handler.SslOptions.ClientCertificateContext);
    }

    [Fact]
    public void ApplyActiveClientCertificate_WithNoActiveCert_LeavesHandlerEmpty()
    {
        using var handler = new System.Net.Http.SocketsHttpHandler();
        var manager = new SslManager();
        ClientTlsHelper.ApplyActiveClientCertificate(handler, manager);
        Assert.Null(handler.SslOptions.ClientCertificateContext);
    }
}