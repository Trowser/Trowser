namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A05a — short LLM/agent slice: cmd-canary + XSS + SQLi (~300s recommended).
/// Continue with <c>a05b-injection-templates</c> then <c>a05c-injection-advanced</c>.
/// </summary>
public sealed class A05aInjectionCorePlaybook : A05InjectionPlaybook
{
    public A05aInjectionCorePlaybook()
        : base(A05ScanProfile.Core, "a05a-injection-core", "A05a Injection Core")
    {
    }
}
