using System.IO;
using System.Reflection;

namespace Trowser.Laws;

/// <summary>Embedded quicktests with parsed <c>@shadow</c> / <c>@effects</c> headers.</summary>
public static class QuicktestCatalog
{
    private static IReadOnlyList<QuicktestMetadata>? _cache;

    public static IReadOnlyList<QuicktestMetadata> Embedded
    {
        get
        {
            if (_cache != null)
                return _cache;
            _cache = LoadEmbeddedSync();
            return _cache;
        }
    }

    public static IEnumerable<QuicktestMetadata> ShadowLightEligible =>
        Embedded.Where(q => q.IsReadOnlyEffects && (q.ShadowLight || q.ShadowHeavy));

    /// <summary>
    /// Light quicktests run only when explicitly listed in <see cref="ShadowConfig.LightQuicktests"/>.
    /// <c>@shadow light</c> metadata is a hint for the UI/API — not an automatic run on every navigation.
    /// </summary>
    public static IEnumerable<QuicktestMetadata> ResolveLightRunList(IEnumerable<string>? configuredLeafNames)
    {
        if (configuredLeafNames == null)
            yield break;
        var configured = configuredLeafNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (configured.Count == 0)
            yield break;

        foreach (var q in Embedded)
        {
            if (!configured.Contains(q.Leaf))
                continue;
            if (!q.IsReadOnlyEffects)
                continue;
            yield return q;
        }
    }

    private static List<QuicktestMetadata> LoadEmbeddedSync()
    {
        const string prefix = "Trowser.Resources.Quicktests.";
        var assembly = Assembly.GetExecutingAssembly();
        var list = new List<QuicktestMetadata>();

        foreach (var name in assembly.GetManifestResourceNames())
        {
            if (!name.StartsWith(prefix, StringComparison.Ordinal) || !name.EndsWith(".csx"))
                continue;
            using var stream = assembly.GetManifestResourceStream(name);
            if (stream == null) continue;
            using var reader = new StreamReader(stream);
            var code = reader.ReadToEnd();
            var relative = name[prefix.Length..^4];
            var leaf = relative.Split('.')[^1];
            list.Add(QuicktestMetadata.Parse(code, name, leaf));
        }

        return list;
    }

    public static string? FindResourceName(string leafName) =>
        Embedded.FirstOrDefault(q => q.Leaf.Equals(leafName, StringComparison.OrdinalIgnoreCase))?.ResourceName;
}
