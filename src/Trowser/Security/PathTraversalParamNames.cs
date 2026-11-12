namespace Trowser.Security;

/// <summary>Heuristics for path / file inclusion parameter names (CWE-22).</summary>
public static class PathTraversalParamNames
{
    public static readonly string[] DefaultParamNames =
    [
        "file", "path", "page", "doc", "include", "load", "read", "filename", "document",
        "dir", "folder", "template", "view", "content", "resource", "url", "img",
        "filepath", "pathname", "src", "name"
    ];

    private static readonly HashSet<string> Exact = new(DefaultParamNames, StringComparer.OrdinalIgnoreCase);

    private static readonly string[] Suffixes =
    [
        "path", "file", "filepath", "filename", "pathname", "folder", "directory", "document"
    ];

    public static bool IsPathLikeParamName(string name, ISet<string>? extraNames = null)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (extraNames != null && extraNames.Contains(name.ToLowerInvariant())) return true;
        if (Exact.Contains(name)) return true;
        foreach (var suffix in Suffixes)
        {
            if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
