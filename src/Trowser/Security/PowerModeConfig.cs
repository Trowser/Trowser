namespace Trowser.Security;

/// <summary>Settings for Trowser Power mode — reveal hidden/disabled UI for security testing.</summary>
public class PowerModeConfig
{
    /// <summary>Master switch. When off, injected styles/scripts are removed on next navigation.</summary>
    public bool Enabled { get; set; }

    /// <summary>Draw outlines and category labels on revealed elements, disabled controls, and hidden inputs.</summary>
    public bool ShowOverlays { get; set; } = true;
}
