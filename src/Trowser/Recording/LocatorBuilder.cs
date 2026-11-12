using System.Text.Json;

namespace Trowser.Recording;

/// <summary>
/// The locator strategy chosen for an element, in priority order. Mirrors the
/// long-standing priority used by the script recorder and the peer mirror:
/// testid → label → placeholder → role+name → unique visible text → CSS selector.
/// </summary>
public enum LocatorKind
{
    None,
    TestId,
    Label,
    Placeholder,
    Role,
    Text,
    Selector
}

/// <summary>
/// A format-agnostic locator decision. <see cref="Primary"/> is the main value
/// (testId, label, placeholder, role, text, or CSS selector); <see cref="Name"/>
/// carries the accessible name when <see cref="Kind"/> is <see cref="LocatorKind.Role"/>.
/// </summary>
public readonly record struct LocatorChoice(LocatorKind Kind, string? Primary, string? Name)
{
    public static readonly LocatorChoice None = new(LocatorKind.None, null, null);

    public bool HasTarget => Kind != LocatorKind.None;
}

/// <summary>
/// Single source of truth for turning a recorded element's attributes into a durable
/// locator. Extracted from <c>ScriptRecorder.BuildLocator</c> and
/// <c>MirrorController.TryAddLocator</c>, which duplicated the same priority logic in two
/// different output shapes (C# script expression vs REST body fields). Pointers reuse it
/// so they get the same durable anchors for free.
/// </summary>
public static class LocatorBuilder
{
    /// <summary>
    /// Choose the best locator for an element given its attributes.
    /// The priority order matches the recorder/mirror exactly so behaviour is unchanged.
    /// </summary>
    public static LocatorChoice Choose(
        string? tag,
        string? testId,
        string? role,
        string? label,
        string? text,
        string? selector,
        string? placeholder,
        bool textUnique,
        bool isClickable)
    {
        // 1. data-testid is the most stable locator
        if (!string.IsNullOrEmpty(testId))
            return new LocatorChoice(LocatorKind.TestId, testId, null);

        // 2. Label for form inputs (label[for=...], aria-label, etc. -- generally unique)
        if (!string.IsNullOrEmpty(label) && label.Length <= 200 && !isClickable)
            return new LocatorChoice(LocatorKind.Label, label, null);

        // 3. Placeholder text for inputs without labels
        if (!string.IsNullOrEmpty(placeholder) && placeholder.Length <= 200 && !isClickable)
            return new LocatorChoice(LocatorKind.Placeholder, placeholder, null);

        // 4. ARIA role + accessible name -- ByRole is specific (matches by role AND name),
        // so it doesn't need the textUnique guard that ByText needs.
        if (!string.IsNullOrEmpty(role) && !string.IsNullOrEmpty(label) && label.Length <= 60)
            return new LocatorChoice(LocatorKind.Role, role, label);

        // 5. Infer role from tag for common elements
        if (isClickable && string.IsNullOrEmpty(role))
        {
            var inferredRole = tag switch
            {
                "button" => "button",
                "a" => "link",
                _ => null
            };
            if (inferredRole != null && !string.IsNullOrEmpty(label) && label.Length <= 60)
                return new LocatorChoice(LocatorKind.Role, inferredRole, label);
        }

        // 6. Visible text for clickable elements -- ByText matches any element, so it
        // needs the textUnique guard. Responsive designs often duplicate nav links
        // (e.g. mobile menu + desktop header), and ByText would find the hidden copy
        // first and fail on playback.
        if (textUnique && isClickable && !string.IsNullOrEmpty(text) && text.Length <= 60)
            return new LocatorChoice(LocatorKind.Text, text, null);

        // 7. Fallback: CSS selector (always unique to the actual clicked element)
        if (!string.IsNullOrEmpty(selector))
            return new LocatorChoice(LocatorKind.Selector, selector, null);

        return LocatorChoice.None;
    }

    /// <summary>
    /// Choose a locator from a recorded action JSON element (the shape produced by the
    /// recording injection script). Reads the same fields the recorder/mirror read.
    /// </summary>
    public static LocatorChoice ChooseFromJson(JsonElement action, bool isClickable) =>
        Choose(
            GetString(action, "tag"),
            GetString(action, "testId"),
            GetString(action, "role"),
            GetString(action, "label"),
            GetString(action, "text"),
            GetString(action, "selector"),
            GetString(action, "placeholder"),
            GetBool(action, "textUnique"),
            isClickable);

    /// <summary>
    /// Render the choice as a Trowser C# script locator expression
    /// (e.g. <c>ByTestId("submit")</c>). <paramref name="escape"/> is the caller's
    /// string-literal escaper. Returns <c>"unknown"</c> when there is no target.
    /// </summary>
    public static string ToScriptExpression(LocatorChoice choice, Func<string, string> escape) => choice.Kind switch
    {
        LocatorKind.TestId => $"ByTestId({escape(choice.Primary!)})",
        LocatorKind.Label => $"ByLabel({escape(choice.Primary!)})",
        LocatorKind.Placeholder => $"ByPlaceholder({escape(choice.Primary!)})",
        LocatorKind.Role => $"ByRole({escape(choice.Primary!)}, {escape(choice.Name!)})",
        LocatorKind.Text => $"ByText({escape(choice.Primary!)})",
        LocatorKind.Selector => escape(choice.Primary!),
        _ => "\"unknown\""
    };

    /// <summary>
    /// Fill a REST body dictionary with the locator fields the automation API understands.
    /// Returns true when a target was added. Mirrors the previous <c>TryAddLocator</c>.
    /// </summary>
    public static bool TryAddToBody(Dictionary<string, object?> body, LocatorChoice choice)
    {
        switch (choice.Kind)
        {
            case LocatorKind.TestId:
                body["testId"] = choice.Primary;
                return true;
            case LocatorKind.Label:
                body["label"] = choice.Primary;
                return true;
            case LocatorKind.Placeholder:
                body["placeholder"] = choice.Primary;
                return true;
            case LocatorKind.Role:
                body["role"] = choice.Primary;
                body["name"] = choice.Name;
                return true;
            case LocatorKind.Text:
                body["byText"] = choice.Primary;
                return true;
            case LocatorKind.Selector:
                body["selector"] = choice.Primary;
                return true;
            default:
                return false;
        }
    }

    /// <summary>
    /// A short human-readable description of the locator, e.g. <c>testId=submit</c> or
    /// <c>role=button "Save"</c>. Used for pointer captions and journal summaries.
    /// </summary>
    public static string Describe(LocatorChoice choice) => choice.Kind switch
    {
        LocatorKind.TestId => $"testId={choice.Primary}",
        LocatorKind.Label => $"label=\"{choice.Primary}\"",
        LocatorKind.Placeholder => $"placeholder=\"{choice.Primary}\"",
        LocatorKind.Role => $"role={choice.Primary} \"{choice.Name}\"",
        LocatorKind.Text => $"text=\"{choice.Primary}\"",
        LocatorKind.Selector => choice.Primary ?? "",
        _ => ""
    };

    private static string GetString(JsonElement el, string prop) =>
        el.ValueKind == JsonValueKind.Object
        && el.TryGetProperty(prop, out var val)
        && val.ValueKind == JsonValueKind.String
            ? val.GetString() ?? ""
            : "";

    private static bool GetBool(JsonElement el, string prop) =>
        el.ValueKind == JsonValueKind.Object
        && el.TryGetProperty(prop, out var val)
        && (val.ValueKind == JsonValueKind.True || val.ValueKind == JsonValueKind.False)
        && val.GetBoolean();
}
