namespace Trowser.Security.Runtime;

/// <summary>
/// <see cref="RuntimeSensorProfile.Ambient"/> — DOM/network sinks for browsing and client-surface (no eval/Function hooks).
/// <see cref="RuntimeSensorProfile.Active"/> — full sink set for trace-input, fuzz, and active audits.
/// </summary>
public enum RuntimeSensorProfile
{
    Ambient,
    Active
}
