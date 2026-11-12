namespace Trowser.Security.Nuclei;

/// <summary>Per-target Nuclei URL placeholders (subset of ProjectDiscovery nuclei variables).</summary>
public readonly record struct NucleiTargetVariables(
    string BaseUrl,
    string RootUrl,
    string Hostname,
    string Host,
    string Port,
    string Scheme,
    string Path,
    string File)
{
    public static NucleiTargetVariables FromUri(Uri targetUri)
    {
        var baseUrl = targetUri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        var rootUrl = $"{targetUri.Scheme}://{targetUri.Authority}";
        var host = targetUri.Host;
        var hostname = targetUri.IsDefaultPort
            ? host
            : $"{host}:{targetUri.Port}";
        var port = targetUri.IsDefaultPort
            ? (targetUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? "443"
                : targetUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) ? "80"
                : targetUri.Port.ToString())
            : targetUri.Port.ToString();
        var absolutePath = targetUri.AbsolutePath;
        if (string.IsNullOrEmpty(absolutePath))
            absolutePath = "/";

        var file = "";
        var lastSlash = absolutePath.LastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < absolutePath.Length - 1)
            file = absolutePath[(lastSlash + 1)..];

        var pathDir = lastSlash > 0 ? absolutePath[..lastSlash] : "/";
        if (pathDir.Length == 0)
            pathDir = "/";

        return new NucleiTargetVariables(
            baseUrl,
            rootUrl,
            hostname,
            host,
            port,
            targetUri.Scheme,
            pathDir,
            file);
    }

    public string Apply(string template, string? pathsPayload = null)
    {
        if (string.IsNullOrEmpty(template))
            return template;

        var s = template
            .Replace("{{BaseURL}}", BaseUrl, StringComparison.OrdinalIgnoreCase)
            .Replace("{{RootURL}}", RootUrl, StringComparison.OrdinalIgnoreCase)
            .Replace("{{Hostname}}", Hostname, StringComparison.OrdinalIgnoreCase)
            .Replace("{{Host}}", Host, StringComparison.OrdinalIgnoreCase)
            .Replace("{{Port}}", Port, StringComparison.OrdinalIgnoreCase)
            .Replace("{{Scheme}}", Scheme, StringComparison.OrdinalIgnoreCase)
            .Replace("{{Path}}", Path, StringComparison.OrdinalIgnoreCase)
            .Replace("{{File}}", File, StringComparison.OrdinalIgnoreCase);

        if (pathsPayload != null)
            s = s.Replace("{{paths}}", pathsPayload, StringComparison.OrdinalIgnoreCase);

        return s;
    }
}
