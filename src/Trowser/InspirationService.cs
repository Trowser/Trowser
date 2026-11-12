using System.IO;

namespace Trowser;

/// <summary>
/// Loads testing inspiration messages from a text file next to the exe
/// and resolves dynamic placeholders (XY_EQUATION, PO_STATEMENT).
/// </summary>
public class InspirationService
{
    private const string FileName = "inspiration_messages.txt";

    private static readonly Random Rng = new();

    /// <summary>
    /// X — a software quality characteristic. TesterPedal <c>x_terms</c>, plus standards.
    /// </summary>
    internal static readonly string[] XTerms =
    [
        "capability", "reliability", "usability", "charisma", "security",
        "performance", "IT-bility", "compatibility", "standards",
        "supportability", "testability", "maintainability", "portability"
    ];

    /// <summary>
    /// Y — a product element (SFDIPOT). Same list as TesterPedal <c>y_terms</c>.
    /// </summary>
    internal static readonly string[] YTerms =
    [
        "structure", "function", "data", "interfaces", "platform",
        "operations", "time"
    ];

    /// <summary>
    /// A PO is Edward de Bono's provocative operator: "PO: " plus one concrete word.
    /// Same list as TesterPedal <c>random_po_words</c>.
    /// </summary>
    internal static readonly string[] PoWords =
    [
        "boat", "bazooka", "cucumber", "elephant", "umbrella", "bicycle",
        "volcano", "penguin", "hammock", "kazoo", "coconut", "banjo",
        "cactus", "flamingo", "jellyfish", "kangaroo", "octopus", "zebra",
        "waffle", "tornado", "rainbow", "pillow", "guitar", "dolphin"
    ];

    private readonly List<string> _messages = [];

    public InspirationService()
        : this(Path.Combine(Path.GetDirectoryName(Environment.ProcessPath)!, FileName))
    {
    }

    internal InspirationService(string filePath) => Load(filePath);

    private void Load(string filePath)
    {
        _messages.Clear();

        if (!File.Exists(filePath))
            return;

        foreach (var line in File.ReadAllLines(filePath))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                continue;
            _messages.Add(trimmed);
        }
    }

    public string? GetRandom()
    {
        if (_messages.Count == 0)
            return null;

        var message = _messages[Rng.Next(_messages.Count)];
        return Resolve(message);
    }

    /// <summary>
    /// XY_EQUATION becomes "<c>x + y = ?</c>". PO_STATEMENT becomes "<c>PO: word</c>".
    /// Any other line is shown as written.
    /// </summary>
    internal static string Resolve(string message) => message switch
    {
        "XY_EQUATION" => $"{Pick(XTerms)} + {Pick(YTerms)} = ?",
        "PO_STATEMENT" => $"PO: {Pick(PoWords)}",
        _ => message
    };

    private static string Pick(string[] items) => items[Rng.Next(items.Length)];
}
