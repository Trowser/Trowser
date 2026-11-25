using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Trowser.Security;

/// <summary>
/// Attaches the user's active client certificate to outbound TLS when one is configured in <see cref="SslManager"/>.
/// On Windows (Schannel), <see cref="SslStreamCertificateContext"/> is required so the leaf key and intermediates are usable.
/// </summary>
internal static class ClientTlsHelper
{
    public static void ApplyActiveClientCertificate(SocketsHttpHandler handler, SslManager? sslManager)
    {
        var ctx = sslManager?.GetActiveClientCertificateContext();
        if (ctx == null)
            return;
        handler.SslOptions.ClientCertificateContext = ctx;
        handler.SslOptions.LocalCertificateSelectionCallback =
            (_, _, _, _, _) => ctx.TargetCertificate;
    }

    /// <summary>Legacy handler; prefer <see cref="SocketsHttpHandler"/> for mTLS.</summary>
    public static void ApplyActiveClientCertificate(HttpClientHandler handler, SslManager? sslManager)
    {
        var ctx = sslManager?.GetActiveClientCertificateContext();
        if (ctx == null)
            return;
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        handler.ClientCertificates.Add(ctx.TargetCertificate);
    }

    public static void ApplyActiveClientCertificate(SslClientAuthenticationOptions options, SslManager? sslManager)
    {
        var ctx = sslManager?.GetActiveClientCertificateContext();
        if (ctx == null)
            return;
        options.ClientCertificateContext = ctx;
    }

    /// <summary>Configure a <see cref="SocketsHttpHandler"/> for typical Trowser direct / fetch traffic.</summary>
    public static SocketsHttpHandler CreateSocketsHandler(
        SslManager? sslManager,
        bool allowAutoRedirect,
        bool automaticDecompression,
        bool useProxy = false)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = allowAutoRedirect,
            UseCookies = false,
            UseProxy = useProxy,
            AutomaticDecompression = automaticDecompression ? DecompressionMethods.All : DecompressionMethods.None
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        ApplyActiveClientCertificate(handler, sslManager);
        return handler;
    }
}