namespace Trowser.Automation;

/// <summary>
/// How REST/MCP automation picks a tab before the first interaction.
/// </summary>
public enum AgentTabPolicy
{
    /// <summary>
    /// Keep using whichever tab is active (typical human login + agent handoff).
    /// </summary>
    StayOnActive,

    /// <summary>
    /// On first mutation, open or switch to an agent-owned tab so automation does not clobber the tester page.
    /// </summary>
    PreferDedicatedAgentTab
}
