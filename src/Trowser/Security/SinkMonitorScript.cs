using Trowser.Security.Runtime;

namespace Trowser.Security;

/// <summary>
/// Backward-compatible entry point for dangerous-sink hooks.
/// Delegates to <see cref="RuntimeSensorScript"/> (expanded sources/sinks/listeners).
/// </summary>
internal static class SinkMonitorScript
{
    internal static string Build() => RuntimeSensorScript.Build();
}
