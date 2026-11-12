namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A05 is split so LLM/agent sessions can run a short core pass without skipping the harder
/// template/deser work forever — run a05a → a05b → a05c (or full a05-injection) as budget allows.
/// </summary>
public enum A05ScanProfile
{
    /// <summary>Full A05: cmd + xss + sqli + SSTI matrix + login sweep + deser/upload.</summary>
    Full,

    /// <summary>Core: cmd-canary + XSS + SQLi (injection-fast friendly, ~300s).</summary>
    Core,

    /// <summary>Templates: SSTI / polyglot / CSTI / NoSQL / LDAP / path (after core).</summary>
    Templates,

    /// <summary>Advanced: login sweep, deserialization, file upload, parser, prototype pollution.</summary>
    Advanced
}
