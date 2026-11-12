namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A05b — SSTI / polyglot / CSTI / NoSQL / LDAP / path-traversal (~600s recommended).
/// Run after <c>a05a-injection-core</c>.
/// </summary>
public sealed class A05bInjectionTemplatesPlaybook : A05InjectionPlaybook
{
    public A05bInjectionTemplatesPlaybook()
        : base(A05ScanProfile.Templates, "a05b-injection-templates", "A05b Injection Templates")
    {
    }
}
