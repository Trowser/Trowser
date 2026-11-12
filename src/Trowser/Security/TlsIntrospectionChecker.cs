using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Passive TLS/certificate introspection for HTTPS origins (document + API hosts from network log).
/// Uses direct TLS handshake (testssl-style stub); optional CDP Security state when available.
/// </summary>
public static class TlsIntrospectionChecker
{
    public sealed class IntrospectionOptions
    {
        public int MaxOrigins { get; set; } = 8;
        public int ConnectTimeoutMs { get; set; } = 8000;
        public int CertExpiryWarningDays { get; set; } = 30;
        public bool IncludeNetworkOrigins { get; set; } = true;
        /// <summary>When true, probe each origin with TLS 1.0 and TLS 1.1 client offers (legacy support detection).</summary>
        public bool IncludeLegacyTlsProbes { get; set; } = true;
    }

    public sealed class LegacyTlsSupport
    {
        public bool? Tls10Supported { get; init; }
        public bool? Tls11Supported { get; init; }
        public string? Tls10Protocol { get; init; }
        public string? Tls11Protocol { get; init; }
        public string? Tls10Cipher { get; init; }
        public string? Tls11Cipher { get; init; }
        public string? Tls10Error { get; init; }
        public string? Tls11Error { get; init; }
    }

    public sealed class OriginTlsInfo
    {
        public string Origin { get; init; } = "";
        public string Host { get; init; } = "";
        public int Port { get; init; } = 443;
        public string? Protocol { get; init; }
        public string? CipherAlgorithm { get; init; }
        public string? Subject { get; init; }
        public DateTime? ValidFromUtc { get; init; }
        public DateTime? ValidToUtc { get; init; }
        public int? DaysUntilExpiry { get; init; }
        public string Source { get; init; } = "ssl-handshake";
        public string? Error { get; init; }
        public LegacyTlsSupport? LegacyTls { get; init; }
    }

    public sealed class TlsFinding
    {
        public string Origin { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Category { get; init; } = "weak-tls";
        public string Title { get; init; } = "";
        public string Description { get; init; } = "";
        public string Recommendation { get; init; } = "";
    }

    public sealed class IntrospectionResult
    {
        public List<OriginTlsInfo> Origins { get; init; } = [];
        public List<TlsFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public bool CdpAvailable { get; init; }
        public string? ExternalScannerNote { get; init; }
        public bool IsClean => Findings.Count == 0;
    }

    public static async Task<IntrospectionResult> RunAsync(
        AutomationContext ctx,
        IntrospectionOptions options,
        CancellationToken ct = default)
    {
        var pageUrl = await ctx.GetCurrentUrl();
        var origins = await ResolveOriginsAsync(ctx, pageUrl, options, ct);
        var infos = new List<OriginTlsInfo>();
        var findings = new List<TlsFinding>();

        foreach (var origin in origins.Take(Math.Max(1, options.MaxOrigins)))
        {
            ct.ThrowIfCancellationRequested();
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Scheme != "https")
                continue;

            var info = await ProbeOriginAsync(uri.Host, uri.Port > 0 ? uri.Port : 443, options.ConnectTimeoutMs, ct);
            LegacyTlsSupport? legacy = null;
            if (options.IncludeLegacyTlsProbes && string.IsNullOrEmpty(info.Error))
                legacy = await ProbeLegacyTlsAsync(uri.Host, uri.Port > 0 ? uri.Port : 443, options.ConnectTimeoutMs, ct);

            if (legacy != null)
            {
                info = new OriginTlsInfo
                {
                    Origin = info.Origin,
                    Host = info.Host,
                    Port = info.Port,
                    Protocol = info.Protocol,
                    CipherAlgorithm = info.CipherAlgorithm,
                    Subject = info.Subject,
                    ValidFromUtc = info.ValidFromUtc,
                    ValidToUtc = info.ValidToUtc,
                    DaysUntilExpiry = info.DaysUntilExpiry,
                    Source = info.Source,
                    Error = info.Error,
                    LegacyTls = legacy
                };
                findings.AddRange(AnalyzeLegacyTls(info.Origin, legacy));
            }

            infos.Add(info);
            findings.AddRange(AnalyzeOrigin(info, options.CertExpiryWarningDays));
        }

        var cdpNote = await TryCdpSecurityStateAsync(ctx, pageUrl);

        var summary = new List<string>();
        if (findings.Count == 0)
            summary.Add($"Probed {infos.Count} HTTPS origin(s); no weak TLS or expiring cert findings.");
        else
            summary.Add($"{findings.Count} TLS/certificate finding(s) across {infos.Count} origin(s).");

        if (!string.IsNullOrEmpty(cdpNote))
            summary.Add(cdpNote);

        return new IntrospectionResult
        {
            Origins = infos,
            Findings = findings,
            Summary = summary,
            CdpAvailable = cdpNote != null,
            ExternalScannerNote =
                "For full cipher suite enumeration, integrate testssl.sh or SSL Labs API — this probe uses direct handshake only."
        };
    }

    private static async Task<List<string>> ResolveOriginsAsync(
        AutomationContext ctx,
        string pageUrl,
        IntrospectionOptions options,
        CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri) && pageUri.Scheme == "https")
            set.Add(pageUri.GetLeftPart(UriPartial.Authority));

        if (options.IncludeNetworkOrigins)
        {
            foreach (var entry in ctx.Network.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var u) || u.Scheme != "https")
                    continue;
                if (entry.ResourceType is "Document" or "Fetch" or "XHR" or "Script" or "Stylesheet")
                    set.Add(u.GetLeftPart(UriPartial.Authority));
            }
        }

        return set.ToList();
    }

    private static async Task<OriginTlsInfo> ProbeOriginAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        var origin = $"https://{host}:{port}";
        try
        {
            using var tcp = new TcpClient();
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeoutMs);
            await tcp.ConnectAsync(host, port, connectCts.Token);

            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            }, connectCts.Token);

            var cert = ssl.RemoteCertificate != null
                ? new X509Certificate2(ssl.RemoteCertificate)
                : null;

            DateTime? validFrom = cert?.NotBefore.ToUniversalTime();
            DateTime? validTo = cert?.NotAfter.ToUniversalTime();
            int? daysLeft = validTo.HasValue
                ? (int)Math.Floor((validTo.Value - DateTime.UtcNow).TotalDays)
                : null;

            return new OriginTlsInfo
            {
                Origin = origin,
                Host = host,
                Port = port,
                Protocol = ssl.SslProtocol.ToString(),
                CipherAlgorithm = ssl.CipherAlgorithm.ToString(),
                Subject = cert?.Subject,
                ValidFromUtc = validFrom,
                ValidToUtc = validTo,
                DaysUntilExpiry = daysLeft,
                Source = "ssl-handshake"
            };
        }
        catch (Exception ex)
        {
            return new OriginTlsInfo
            {
                Origin = origin,
                Host = host,
                Port = port,
                Error = ex.Message,
                Source = "ssl-handshake"
            };
        }
    }

    private static List<TlsFinding> AnalyzeOrigin(OriginTlsInfo info, int expiryWarningDays)
    {
        var findings = new List<TlsFinding>();
        if (!string.IsNullOrEmpty(info.Error))
        {
            findings.Add(new TlsFinding
            {
                Origin = info.Origin,
                Severity = "low",
                Category = "weak-tls",
                Title = $"TLS handshake failed for {info.Host}",
                Description = info.Error,
                Recommendation = "Verify host reachability and TLS configuration."
            });
            return findings;
        }

        if (info.Protocol != null &&
            (info.Protocol.Contains("Tls10", StringComparison.OrdinalIgnoreCase)
             || info.Protocol.Contains("Tls11", StringComparison.OrdinalIgnoreCase)
             || info.Protocol.Contains("Ssl3", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new TlsFinding
            {
                Origin = info.Origin,
                Severity = "high",
                Category = "weak-tls",
                Title = $"Deprecated TLS protocol ({info.Protocol})",
                Description = $"Negotiated {info.Protocol} with {info.CipherAlgorithm}. TLS 1.2+ required.",
                Recommendation = "Disable TLS 1.0/1.1 and SSLv3 on the server."
            });
        }

        if (info.DaysUntilExpiry is <= 0)
        {
            findings.Add(new TlsFinding
            {
                Origin = info.Origin,
                Severity = "critical",
                Category = "expiring-cert",
                Title = "Certificate expired",
                Description = $"Certificate for {info.Host} expired ({info.ValidToUtc:yyyy-MM-dd}).",
                Recommendation = "Renew the TLS certificate immediately."
            });
        }
        else if (info.DaysUntilExpiry is int days && days > 0 && days <= expiryWarningDays)
        {
            findings.Add(new TlsFinding
            {
                Origin = info.Origin,
                Severity = days <= 7 ? "high" : "medium",
                Category = "expiring-cert",
                Title = $"Certificate expiring in {days} day(s)",
                Description = $"Certificate for {info.Host} expires {info.ValidToUtc:yyyy-MM-dd}.",
                Recommendation = "Renew before expiry to avoid service disruption."
            });
        }

        return findings;
    }

    private static async Task<LegacyTlsSupport> ProbeLegacyTlsAsync(
        string host, int port, int timeoutMs, CancellationToken ct)
    {
        var tls10 = await TryLegacyHandshakeAsync(host, port, LegacyTls10Protocols, timeoutMs, ct);
#pragma warning disable SYSLIB0039
        var tls11 = await TryLegacyHandshakeAsync(host, port, SslProtocols.Tls11, timeoutMs, ct);
#pragma warning restore SYSLIB0039

        return new LegacyTlsSupport
        {
            Tls10Supported = tls10.Supported,
            Tls11Supported = tls11.Supported,
            Tls10Protocol = tls10.Protocol,
            Tls11Protocol = tls11.Protocol,
            Tls10Cipher = tls10.Cipher,
            Tls11Cipher = tls11.Cipher,
            Tls10Error = tls10.Error,
            Tls11Error = tls11.Error
        };
    }

#pragma warning disable SYSLIB0039
    private static SslProtocols LegacyTls10Protocols =>
        Enum.TryParse<SslProtocols>("Tls10", out var tls10) ? tls10 : SslProtocols.Tls;
#pragma warning restore SYSLIB0039

    private sealed class LegacyHandshakeResult
    {
        public bool Supported { get; init; }
        public string? Protocol { get; init; }
        public string? Cipher { get; init; }
        public string? Error { get; init; }
    }

    private static async Task<LegacyHandshakeResult> TryLegacyHandshakeAsync(
        string host, int port, SslProtocols protocols, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var tcp = new TcpClient();
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeoutMs);
            await tcp.ConnectAsync(host, port, connectCts.Token);

            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = protocols
            }, connectCts.Token);

            return new LegacyHandshakeResult
            {
                Supported = true,
                Protocol = ssl.SslProtocol.ToString(),
                Cipher = ssl.CipherAlgorithm.ToString()
            };
        }
        catch (Exception ex)
        {
            var msg = ex.Message;
            if (msg.Contains("protocol", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("Ssl", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("TLS", StringComparison.OrdinalIgnoreCase))
            {
                return new LegacyHandshakeResult { Supported = false, Error = msg };
            }

            return new LegacyHandshakeResult { Supported = false, Error = msg };
        }
    }

    private static List<TlsFinding> AnalyzeLegacyTls(string origin, LegacyTlsSupport legacy)
    {
        var findings = new List<TlsFinding>();

        if (legacy.Tls10Supported == true)
        {
            findings.Add(new TlsFinding
            {
                Origin = origin,
                Severity = "high",
                Category = "legacy-tls",
                Title = "Server accepts TLS 1.0",
                Description =
                    $"Legacy TLS 1.0 handshake succeeded ({legacy.Tls10Protocol}, cipher {legacy.Tls10Cipher}). " +
                    "TLS 1.0 is deprecated and vulnerable to BEAST/POODLE-class attacks.",
                Recommendation = "Disable TLS 1.0 on the server; require TLS 1.2+."
            });
        }
        else if (!string.IsNullOrEmpty(legacy.Tls10Error)
                 && legacy.Tls10Error.Contains("enabled", StringComparison.OrdinalIgnoreCase)
                 && legacy.Tls10Error.Contains("OS", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new TlsFinding
            {
                Origin = origin,
                Severity = "info",
                Category = "legacy-tls",
                Title = "TLS 1.0 probe skipped (client OS policy)",
                Description = legacy.Tls10Error,
                Recommendation = "Run testssl.sh or SSL Labs if the OS blocks legacy client protocols."
            });
        }

        if (legacy.Tls11Supported == true)
        {
            findings.Add(new TlsFinding
            {
                Origin = origin,
                Severity = "high",
                Category = "legacy-tls",
                Title = "Server accepts TLS 1.1",
                Description =
                    $"Legacy TLS 1.1 handshake succeeded ({legacy.Tls11Protocol}, cipher {legacy.Tls11Cipher}). " +
                    "TLS 1.1 is deprecated.",
                Recommendation = "Disable TLS 1.1 on the server; require TLS 1.2+."
            });
        }

        return findings;
    }

    private static async Task<string?> TryCdpSecurityStateAsync(AutomationContext ctx, string pageUrl)
    {
        if (string.IsNullOrWhiteSpace(pageUrl) || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri))
            return null;

        try
        {
            var webView = ctx.ActiveTab.WebView;
            var json = await await webView.Dispatcher.InvokeAsync(async () =>
            {
                if (webView.CoreWebView2 == null) return null;
                try
                {
                    await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Security.enable", "{}");
                    var origin = uri.GetLeftPart(UriPartial.Authority);
                    return await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                        "Security.getCertificate",
                        JsonSerializer.Serialize(new { origin }));
                }
                catch
                {
                    return null;
                }
            });

            if (string.IsNullOrEmpty(json)) return null;
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("tableNames", out _))
                return "CDP Security.getCertificate available (table metadata returned).";
            return "CDP Security domain enabled for page origin.";
        }
        catch
        {
            return null;
        }
    }
}
