using System.Security.Cryptography;

namespace Trowser;

/// <summary>Generates the REST API bearer token for the local Trowser server.</summary>
public static class TrowserApiKey
{
    public const string EnvironmentVariableName = "TROWSER_API_KEY";

    public static string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        return "trowser_" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// True when <see cref="EnvironmentVariableName"/> was injected for this process
    /// (PeerLauncher or a one-shot script environment) rather than inherited from a
    /// persistent User/Machine environment variable. Persistent env vars must not
    /// override Settings → Keep API key.
    /// Always clears the process-level copy so later child processes do not inherit a
    /// one-shot peer key.
    /// </summary>
    public static bool TryTakeProcessInjectedKey(out string? key)
    {
        key = Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.Process);
        if (string.IsNullOrEmpty(key))
            return false;

        var user = Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.User);
        var machine = Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.Machine);
        var inheritedFromUser = !string.IsNullOrEmpty(user) &&
                                string.Equals(key, user, StringComparison.Ordinal);
        var inheritedFromMachine = string.IsNullOrEmpty(user) &&
                                   !string.IsNullOrEmpty(machine) &&
                                   string.Equals(key, machine, StringComparison.Ordinal);

        Environment.SetEnvironmentVariable(EnvironmentVariableName, null, EnvironmentVariableTarget.Process);

        if (inheritedFromUser || inheritedFromMachine)
        {
            key = null;
            return false;
        }

        return true;
    }
}
