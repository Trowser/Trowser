namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A05c — login-sweep, deserialization, file-upload, parser-probe, prototype-pollution (~600s).
/// Run after <c>a05a</c>/<c>a05b</c>.
/// </summary>
public sealed class A05cInjectionAdvancedPlaybook : A05InjectionPlaybook
{
    public A05cInjectionAdvancedPlaybook()
        : base(A05ScanProfile.Advanced, "a05c-injection-advanced", "A05c Injection Advanced")
    {
    }
}
