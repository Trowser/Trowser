using System.Text.Json;
using Trowser.Recording;
using Xunit;

namespace Trowser.Tests;

/// <summary>
/// Parity tests for the shared <see cref="LocatorBuilder"/> extracted from
/// <c>ScriptRecorder.BuildLocator</c> and <c>MirrorController.TryAddLocator</c>. These pin the
/// exact priority order so the refactor cannot silently change recorded/mirrored locators.
/// </summary>
public class LocatorBuilderTests
{
    private static string Esc(string v) =>
        "\"" + v.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static string Script(LocatorChoice c) => LocatorBuilder.ToScriptExpression(c, Esc);

    [Fact]
    public void testid_wins_over_everything()
    {
        var c = LocatorBuilder.Choose(tag: "button", testId: "submit", role: "button", label: "Save",
            text: "Save", selector: "#s", placeholder: null, textUnique: true, isClickable: true);
        Assert.Equal(LocatorKind.TestId, c.Kind);
        Assert.Equal("ByTestId(\"submit\")", Script(c));
    }

    [Fact]
    public void label_used_for_non_clickable_inputs()
    {
        var c = LocatorBuilder.Choose(tag: "input", testId: null, role: null, label: "Email",
            text: null, selector: "#e", placeholder: null, textUnique: false, isClickable: false);
        Assert.Equal(LocatorKind.Label, c.Kind);
        Assert.Equal("ByLabel(\"Email\")", Script(c));
    }

    [Fact]
    public void label_not_used_for_clickable_falls_through_to_role()
    {
        // Clickable + role + label => ByRole (label is not used as ByLabel for clickables).
        var c = LocatorBuilder.Choose(tag: "button", testId: null, role: "button", label: "Save",
            text: "Save", selector: "#s", placeholder: null, textUnique: true, isClickable: true);
        Assert.Equal(LocatorKind.Role, c.Kind);
        Assert.Equal("ByRole(\"button\", \"Save\")", Script(c));
    }

    [Fact]
    public void placeholder_used_when_no_label()
    {
        var c = LocatorBuilder.Choose(tag: "input", testId: null, role: null, label: null,
            text: null, selector: "#e", placeholder: "you@example.com", textUnique: false, isClickable: false);
        Assert.Equal(LocatorKind.Placeholder, c.Kind);
        Assert.Equal("ByPlaceholder(\"you@example.com\")", Script(c));
    }

    [Fact]
    public void inferred_role_from_anchor_tag()
    {
        var c = LocatorBuilder.Choose(tag: "a", testId: null, role: null, label: "Home",
            text: "Home", selector: "a.home", placeholder: null, textUnique: true, isClickable: true);
        Assert.Equal(LocatorKind.Role, c.Kind);
        Assert.Equal("ByRole(\"link\", \"Home\")", Script(c));
    }

    [Fact]
    public void unique_text_for_clickable_without_role_or_label()
    {
        var c = LocatorBuilder.Choose(tag: "div", testId: null, role: null, label: null,
            text: "Click me", selector: "div.x", placeholder: null, textUnique: true, isClickable: true);
        Assert.Equal(LocatorKind.Text, c.Kind);
        Assert.Equal("ByText(\"Click me\")", Script(c));
    }

    [Fact]
    public void non_unique_text_falls_through_to_selector()
    {
        var c = LocatorBuilder.Choose(tag: "div", testId: null, role: null, label: null,
            text: "Menu", selector: "div.x", placeholder: null, textUnique: false, isClickable: true);
        Assert.Equal(LocatorKind.Selector, c.Kind);
        Assert.Equal("\"div.x\"", Script(c));
    }

    [Fact]
    public void nothing_yields_unknown()
    {
        var c = LocatorBuilder.Choose(tag: null, testId: null, role: null, label: null,
            text: null, selector: null, placeholder: null, textUnique: false, isClickable: false);
        Assert.Equal(LocatorKind.None, c.Kind);
        Assert.Equal("\"unknown\"", Script(c));
    }

    [Fact]
    public void from_json_matches_direct_choose()
    {
        var json = JsonDocument.Parse(
            """{"tag":"button","testId":"","role":"button","label":"Save","text":"Save","selector":"#s","placeholder":"","textUnique":true}""");
        var c = LocatorBuilder.ChooseFromJson(json.RootElement, isClickable: true);
        Assert.Equal(LocatorKind.Role, c.Kind);
        Assert.Equal("ByRole(\"button\", \"Save\")", Script(c));
    }

    [Fact]
    public void try_add_to_body_maps_role_and_name()
    {
        var c = new LocatorChoice(LocatorKind.Role, "button", "Save");
        var body = new Dictionary<string, object?>();
        Assert.True(LocatorBuilder.TryAddToBody(body, c));
        Assert.Equal("button", body["role"]);
        Assert.Equal("Save", body["name"]);
    }

    [Fact]
    public void try_add_to_body_maps_text_to_byText()
    {
        var c = new LocatorChoice(LocatorKind.Text, "Click me", null);
        var body = new Dictionary<string, object?>();
        Assert.True(LocatorBuilder.TryAddToBody(body, c));
        Assert.Equal("Click me", body["byText"]);
    }

    [Fact]
    public void try_add_to_body_returns_false_for_none()
    {
        var body = new Dictionary<string, object?>();
        Assert.False(LocatorBuilder.TryAddToBody(body, LocatorChoice.None));
        Assert.Empty(body);
    }
}
