// @title Toggle Screen Curtain
// @shadow never
// @effects mutates
// Toggle the screen curtain (blind testing mode). Press Ctrl+B in the GUI for the same effect.
// The page goes visually black; screen readers and keyboard navigation still work.

var enabled = await ToggleScreenCurtain();
Log($"Screen curtain: {(enabled ? "ON" : "OFF")}");
