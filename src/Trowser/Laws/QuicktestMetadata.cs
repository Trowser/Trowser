namespace Trowser.Laws;

public sealed class QuicktestMetadata
{
    public string? Title { get; init; }
    public string ShadowMode { get; init; } = "never";
    public string Effects { get; init; } = "mutates";
    public string? See { get; init; }
    public string ResourceName { get; init; } = "";
    public string Leaf { get; init; } = "";

    public bool IsReadOnlyEffects => Effects.Equals("none", StringComparison.OrdinalIgnoreCase);
    public bool ShadowLight => ShadowMode.Equals("light", StringComparison.OrdinalIgnoreCase);
    public bool ShadowHeavy => ShadowMode.Equals("heavy", StringComparison.OrdinalIgnoreCase);

    public static QuicktestMetadata Parse(string code, string resourceName, string leaf)
    {
        string? title = null;
        var shadow = "never";
        var effects = "mutates";
        string? see = null;

        foreach (var line in code.Split('\n'))
        {
            var t = line.Trim();
            if (!t.StartsWith("//", StringComparison.Ordinal))
                continue;
            var body = t[2..].Trim();
            if (!body.StartsWith('@'))
                continue;
            var rest = body[1..].Trim();
            var space = rest.IndexOf(' ');
            var key = space < 0 ? rest : rest[..space];
            var value = space < 0 ? "" : rest[(space + 1)..].Trim();

            switch (key.ToLowerInvariant())
            {
                case "title": title = value; break;
                case "shadow": shadow = string.IsNullOrEmpty(value) ? "never" : value; break;
                case "effects": effects = string.IsNullOrEmpty(value) ? "mutates" : value; break;
                case "see": see = value; break;
            }
        }

        if (title == null)
            title = leaf;

        return new QuicktestMetadata
        {
            Title = title,
            ShadowMode = shadow,
            Effects = effects,
            See = see,
            ResourceName = resourceName,
            Leaf = leaf
        };
    }
}
