using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Trowser.Security.Vpx;

/// <summary>
/// Computes <c>vpx-fingerprint-1</c> as specified in VPX 1.1 Appendix D.
/// </summary>
public static class VpxFingerprint
{
    public const string Algorithm = "vpx-fingerprint-1";
    private const char UnitSeparator = '\u001F';

    public sealed class Input
    {
        public string? Repository { get; init; }
        public string? File { get; init; }
        public string? Kind { get; init; }
        public string? SourceFile { get; init; }
        public int? SourceLine { get; init; }
        public string? SinkFile { get; init; }
        public int? SinkLine { get; init; }
        public string? Route { get; init; }
        public string? Method { get; init; }
        public string? Param { get; init; }
    }

    public static Dictionary<string, object?> Compute(Input input)
    {
        var canonical = string.Join(UnitSeparator, new[]
        {
            Algorithm,
            NormalizeRepository(input.Repository),
            NormalizeFile(input.File),
            Nfc(input.Kind?.Trim().ToLowerInvariant() ?? ""),
            NormalizeLocation(input.SourceFile, input.SourceLine),
            NormalizeLocation(input.SinkFile, input.SinkLine),
            NormalizeRoute(input.Route),
            Nfc(input.Method?.Trim().ToUpperInvariant() ?? ""),
            Nfc(input.Param?.Trim() ?? "")
        });

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
            .ToLowerInvariant();
        return new Dictionary<string, object?>
        {
            ["algorithm"] = Algorithm,
            ["value"] = "sha256:" + hash
        };
    }

    public static string NormalizeRepository(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) return "";
        if (Uri.TryCreate(v, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            v = $"{uri.Scheme.ToLowerInvariant()}://{uri.Host.ToLowerInvariant()}{uri.AbsolutePath}";
        }
        else
        {
            v = v.ToLowerInvariant();
        }

        v = v.TrimEnd('/');
        if (v.EndsWith(".git", StringComparison.Ordinal))
            v = v[..^4];
        return Nfc(v);
    }

    public static string NormalizeFile(string? value)
    {
        var v = (value ?? "").Trim().Replace('\\', '/');
        if (v.StartsWith("./", StringComparison.Ordinal))
            v = v[2..];
        return Nfc(v);
    }

    public static string NormalizeLocation(string? file, int? line)
    {
        var f = NormalizeFile(file);
        if (f.Length == 0) return "";
        if (line is > 0)
            return $"{f}:{line.Value.ToString(CultureInfo.InvariantCulture)}";
        return f;
    }

    public static string NormalizeRoute(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) return "";
        if (Uri.TryCreate(v, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            v = string.IsNullOrEmpty(uri.AbsolutePath) ? "/" : uri.AbsolutePath;
        }

        var cut = v.IndexOfAny(['?', '#']);
        if (cut >= 0) v = v[..cut];
        v = v.ToLowerInvariant();
        while (v.Contains("//", StringComparison.Ordinal))
            v = v.Replace("//", "/", StringComparison.Ordinal);
        if (v.Length > 1) v = v.TrimEnd('/');
        return Nfc(v);
    }

    private static string Nfc(string s) => s.Normalize(NormalizationForm.FormC);
}
