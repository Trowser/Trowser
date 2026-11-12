namespace Trowser.Security;

/// <summary>Settings for Red Team Whisper — contextual clues after navigation and once per new domain.</summary>
public class WhisperConfig
{
    public bool Enabled { get; set; }

    /// <summary>Show toast-style messages in the Trowser chrome when new clues appear.</summary>
    public bool NotifyGui { get; set; } = true;
}
