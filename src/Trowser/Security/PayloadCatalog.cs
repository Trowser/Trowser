using System.Collections.Concurrent;
using System.IO;
using Trowser.Robustness;

namespace Trowser.Security;

/// <summary>
/// Central payload resolver. <see cref="PayloadProfile.Small"/> returns built-in catalogs;
/// <see cref="PayloadProfile.Big"/> merges external corpora subsets with hard caps.
/// </summary>
public static class PayloadCatalog
{
    /// <summary>Hard per-set caps so corpus size cannot explode request counts.</summary>
    public static class Caps
    {
        public const int SmallDefault = 64;
        public const int BigDefault = 200;
        public const int BigXss = 150;
        public const int BigSqli = 200;
        public const int BigSsti = 80;
        public const int BigPathTraversal = 120;
        public const int BigNosql = 80;
        public const int BigLdap = 60;
        public const int BigSsrf = 80;
        public const int BigOpenRedirect = 80;
    }

    private static readonly ConcurrentDictionary<string, string[]> FileCache = new(StringComparer.OrdinalIgnoreCase);

    private static readonly Dictionary<string, (string RelativePath, int Cap)> BigMappings =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["xss-basic"] = ("PayloadsAllTheThings/XSS Injection/Intruder/xss.txt", Caps.BigXss),
            ["xss-bypass"] = ("SecLists/Fuzzing/XSS/XSS-Jhaddix.txt", Caps.BigXss),
            ["sqli-basic"] = ("SecLists/Fuzzing/SQLi/Generic-SQLi.txt", Caps.BigSqli),
            ["ssti"] = ("PayloadsAllTheThings/Server Side Template Injection/Intruder/ssti.txt", Caps.BigSsti),
            ["path-traversal"] = ("SecLists/Fuzzing/LFI/LFI-Jhaddix.txt", Caps.BigPathTraversal),
            ["nosql-injection"] = ("PayloadsAllTheThings/NoSQL Injection/Intruder/nosqli.txt", Caps.BigNosql),
            ["ldap-injection"] = ("SecLists/Fuzzing/LDAP/LDAP.fuzzdb.txt", Caps.BigLdap),
            ["ssrf"] = ("PayloadsAllTheThings/Server Side Request Forgery/Intruder/ssrf.txt", Caps.BigSsrf),
            ["open-redirect"] = ("SecLists/Fuzzing/URI/redirect-urls.txt", Caps.BigOpenRedirect),
        };

    /// <summary>
    /// Resolve a named payload set. For <see cref="PayloadProfile.Big"/>, merges built-in
    /// with external file when present; if corpora are missing, falls back to small.
    /// </summary>
    public static string[] Resolve(string name, PayloadProfile profile = PayloadProfile.Small, int? maxPayloads = null)
    {
        // Read builtins directly from the dictionary. Do NOT call FuzzerPayloads.Resolve here:
        // FuzzerPayloads.Resolve(name, profile) delegates back into this method, so calling it
        // from here would create infinite recursion (StackOverflow, process crash).
        var builtin = FuzzerPayloads.BuiltIn.TryGetValue(name, out var b) ? b : Array.Empty<string>();
        if (profile == PayloadProfile.Small)
            return Cap(builtin, maxPayloads ?? Caps.SmallDefault);

        if (!BigMappings.TryGetValue(name, out var map))
            return Cap(builtin, maxPayloads ?? Caps.BigDefault);

        var external = LoadCorporaFile(map.RelativePath);
        if (external.Length == 0)
            return Cap(builtin, maxPayloads ?? Caps.SmallDefault);

        var merged = MergeUnique(builtin, external);
        return Cap(merged, maxPayloads ?? map.Cap);
    }

    /// <summary>Resolve with an explicit fallback list (for scanners that don't use FuzzerPayloads names).</summary>
    public static string[] ResolveWithFallback(
        string setName,
        IReadOnlyList<string> smallFallback,
        PayloadProfile profile,
        int? maxPayloads = null)
    {
        if (profile == PayloadProfile.Small)
            return Cap(smallFallback, maxPayloads ?? Caps.SmallDefault);

        if (BigMappings.TryGetValue(setName, out var map))
        {
            var external = LoadCorporaFile(map.RelativePath);
            if (external.Length > 0)
            {
                var merged = MergeUnique(smallFallback, external);
                return Cap(merged, maxPayloads ?? map.Cap);
            }
        }

        return Cap(smallFallback, maxPayloads ?? Caps.SmallDefault);
    }

    public static string? GetCorporaRoot()
    {
        var env = Environment.GetEnvironmentVariable("TROWSER_CORPORA");
        if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env))
            return env;

        var exeDir = Path.GetDirectoryName(Environment.ProcessPath);
        if (!string.IsNullOrEmpty(exeDir))
        {
            var beside = Path.Combine(exeDir, "corpora");
            if (Directory.Exists(beside)) return beside;
        }

        return null;
    }

    public static bool CorporaAvailable => GetCorporaRoot() != null;

    private static string[] LoadCorporaFile(string relativePath)
    {
        var root = GetCorporaRoot();
        if (root == null) return Array.Empty<string>();

        var full = Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar));
        return FileCache.GetOrAdd(full, path =>
        {
            if (!File.Exists(path)) return Array.Empty<string>();
            try
            {
                return File.ReadAllLines(path)
                    .Select(l => l.TrimEnd('\r'))
                    .Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith("//"))
                    .ToArray();
            }
            catch
            {
                return Array.Empty<string>();
            }
        });
    }

    private static string[] MergeUnique(IReadOnlyList<string> first, IReadOnlyList<string> second)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<string>(first.Count + second.Count);
        foreach (var s in first.Concat(second))
        {
            if (seen.Add(s)) list.Add(s);
        }
        return list.ToArray();
    }

    private static string[] Cap(IReadOnlyList<string> payloads, int max)
    {
        if (payloads.Count <= max) return payloads as string[] ?? payloads.ToArray();
        return payloads.Take(max).ToArray();
    }
}
