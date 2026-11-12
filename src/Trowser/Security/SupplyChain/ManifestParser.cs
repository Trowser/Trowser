using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security.SupplyChain;

/// <summary>
/// Parses dependency manifests leaked or discovered on web targets.
/// </summary>
public static class ManifestParser
{
    public static readonly IReadOnlyDictionary<string, string> EcosystemByFileName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["package.json"] = "npm",
        ["package-lock.json"] = "npm",
        ["yarn.lock"] = "npm",
        ["composer.json"] = "Packagist",
        ["composer.lock"] = "Packagist",
        ["requirements.txt"] = "PyPI",
        ["Pipfile"] = "PyPI",
        ["pyproject.toml"] = "PyPI",
        ["Gemfile"] = "RubyGems",
        ["Gemfile.lock"] = "RubyGems",
        ["go.mod"] = "Go",
        ["pom.xml"] = "Maven",
        ["Cargo.lock"] = "crates.io",
        ["Cargo.toml"] = "crates.io",
    };

    public static string? ResolveEcosystem(string fileName)
    {
        var baseName = Path.GetFileName(fileName.Split('?')[0].Split('%')[0]);
        if (EcosystemByFileName.TryGetValue(baseName, out var eco))
            return eco;
        if (baseName.StartsWith("package.json", StringComparison.OrdinalIgnoreCase))
            return "npm";
        return null;
    }

    public static bool LooksLikeManifestPath(string path)
    {
        var lower = path.ToLowerInvariant();
        return lower.Contains("package.json") || lower.Contains("package-lock")
            || lower.Contains("yarn.lock") || lower.Contains("composer.")
            || lower.Contains("requirements.txt") || lower.Contains("pyproject.toml")
            || lower.Contains("gemfile") || lower.Contains("pom.xml")
            || lower.Contains("cargo.lock") || lower.Contains("go.mod");
    }

    public static List<DeclaredDependency> Parse(string content, string sourceFile, string? ecosystem = null)
    {
        ecosystem ??= ResolveEcosystem(sourceFile) ?? "npm";
        var fileName = Path.GetFileName(sourceFile.Split('?')[0].Split('%')[0]).ToLowerInvariant();

        return fileName switch
        {
            "package.json" or "package-lock.json" => ParseNpm(content, sourceFile, ecosystem),
            "yarn.lock" => ParseYarnLock(content, sourceFile),
            "composer.json" => ParseComposerJson(content, sourceFile),
            "requirements.txt" => ParseRequirementsTxt(content, sourceFile),
            "pyproject.toml" => ParsePyProjectToml(content, sourceFile),
            _ when fileName.StartsWith("package.json", StringComparison.Ordinal) => ParseNpm(content, sourceFile, ecosystem),
            _ when fileName.Contains("package-lock", StringComparison.Ordinal) => ParseNpm(content, sourceFile, ecosystem),
            _ => ParseNpm(content, sourceFile, ecosystem)
        };
    }

    public static List<DeclaredDependency> Dedupe(IEnumerable<DeclaredDependency> deps, int max = 200)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<DeclaredDependency>();
        foreach (var d in deps)
        {
            if (string.IsNullOrWhiteSpace(d.Name)) continue;
            var key = $"{d.Ecosystem}|{d.Name}|{d.Version}";
            if (!seen.Add(key)) continue;
            list.Add(d);
            if (list.Count >= max) break;
        }
        return list;
    }

    private static List<DeclaredDependency> ParseNpm(string content, string sourceFile, string ecosystem)
    {
        try
        {
            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return [];

            var deps = new Dictionary<(string, string), DeclaredDependency>();

            foreach (var key in new[] { "dependencies", "devDependencies", "peerDependencies", "optionalDependencies" })
            {
                if (!root.TryGetProperty(key, out var section) || section.ValueKind != JsonValueKind.Object)
                    continue;
                foreach (var prop in section.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String)
                        AddDep(deps, prop.Name, StripVersionPrefix(prop.Value.GetString() ?? ""), ecosystem, sourceFile);
                }
            }

            if (root.TryGetProperty("dependencies", out var lockDeps) && lockDeps.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in lockDeps.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.Object
                        && prop.Value.TryGetProperty("version", out var verEl)
                        && verEl.ValueKind == JsonValueKind.String)
                        AddDep(deps, prop.Name, verEl.GetString() ?? "", ecosystem, sourceFile);
                }
            }

            if (root.TryGetProperty("packages", out var packages) && packages.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in packages.EnumerateObject())
                {
                    if (prop.Name == "" || prop.Value.ValueKind != JsonValueKind.Object) continue;
                    if (!prop.Value.TryGetProperty("version", out var verEl) || verEl.ValueKind != JsonValueKind.String)
                        continue;
                    var ver = verEl.GetString() ?? "";
                    if (prop.Value.TryGetProperty("name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String)
                        AddDep(deps, nameEl.GetString() ?? "", ver, ecosystem, sourceFile);
                    else if (prop.Name.StartsWith("node_modules/", StringComparison.Ordinal))
                        AddDep(deps, prop.Name.Split("node_modules/", 2)[^1], ver, ecosystem, sourceFile);
                }
            }

            return deps.Values.ToList();
        }
        catch
        {
            return [];
        }
    }

    private static List<DeclaredDependency> ParseYarnLock(string content, string sourceFile)
    {
        var deps = new Dictionary<(string, string), DeclaredDependency>();
        var blockRe = new Regex(@"^""(?<name>[^""]+)""(?:@[^:]*)?:\s*$", RegexOptions.Multiline);
        var verRe = new Regex(@"^\s+version\s+""(?<ver>[^""]+)""", RegexOptions.Multiline);
        foreach (Match m in blockRe.Matches(content))
        {
            var name = m.Groups["name"].Value;
            var start = m.Index + m.Length;
            var next = content.IndexOf("\n\n", start, StringComparison.Ordinal);
            var block = next >= 0 ? content[start..next] : content[start..];
            var vm = verRe.Match(block);
            if (vm.Success)
                AddDep(deps, name.Split('@')[0], vm.Groups["ver"].Value, "npm", sourceFile);
        }
        return deps.Values.ToList();
    }

    private static List<DeclaredDependency> ParseComposerJson(string content, string sourceFile)
    {
        try
        {
            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;
            var deps = new Dictionary<(string, string), DeclaredDependency>();
            foreach (var key in new[] { "require", "require-dev" })
            {
                if (!root.TryGetProperty(key, out var section) || section.ValueKind != JsonValueKind.Object)
                    continue;
                foreach (var prop in section.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String)
                        AddDep(deps, prop.Name, StripVersionPrefix(prop.Value.GetString() ?? ""), "Packagist", sourceFile);
                }
            }
            return deps.Values.ToList();
        }
        catch { return []; }
    }

    private static List<DeclaredDependency> ParseRequirementsTxt(string content, string sourceFile)
    {
        var deps = new Dictionary<(string, string), DeclaredDependency>();
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var parts = Regex.Split(line, @"==|>=|<=|~=|!=");
            if (parts.Length >= 2)
                AddDep(deps, parts[0].Trim(), parts[1].Trim(), "PyPI", sourceFile);
            else if (parts.Length == 1 && !string.IsNullOrWhiteSpace(parts[0]))
                AddDep(deps, parts[0].Trim(), "", "PyPI", sourceFile);
        }
        return deps.Values.ToList();
    }

    private static List<DeclaredDependency> ParsePyProjectToml(string content, string sourceFile)
    {
        var deps = new Dictionary<(string, string), DeclaredDependency>();
        var re = new Regex(@"(?<name>[a-zA-Z0-9_.-]+)\s*=\s*""(?<ver>[^""]+)""");
        foreach (Match m in re.Matches(content))
            AddDep(deps, m.Groups["name"].Value, m.Groups["ver"].Value, "PyPI", sourceFile);
        return deps.Values.ToList();
    }

    private static void AddDep(
        Dictionary<(string, string), DeclaredDependency> deps,
        string name, string version, string ecosystem, string sourceFile)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        var key = (name, version);
        deps.TryAdd(key, new DeclaredDependency
        {
            Name = name,
            Version = version,
            Ecosystem = ecosystem,
            SourceFile = sourceFile
        });
    }

    internal static string StripVersionPrefix(string ver)
    {
        ver = ver.Trim();
        while (ver.Length > 0 && "^~>=<".Contains(ver[0]))
            ver = ver[1..];
        if (ver.StartsWith('='))
            ver = ver[1..];
        return ver.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0].Trim();
    }
}
