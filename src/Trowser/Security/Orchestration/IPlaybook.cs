namespace Trowser.Security.Orchestration;

/// <summary>
/// A single security playbook: one call, one OWASP category, one report.
/// Implementations live in the Playbooks/ subfolder and are discovered by <see cref="PlaybookRegistry"/>.
/// </summary>
public interface IPlaybook
{
    /// <summary>Short ID matching the OWASP category (e.g. "a01-access", "a02-misconfig").</summary>
    string Id { get; }

    /// <summary>Human-readable title (e.g. "A01 Access Control").</summary>
    string Title { get; }

    /// <summary>OWASP category tag for cross-referencing.</summary>
    string Category { get; }

    /// <summary>Ordered step descriptors for dry-run preview.</summary>
    IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request);

    /// <summary>
    /// Recommended minimum budget for this playbook at the given depth.
    /// Used as a floor when the caller provides a lower budget, and
    /// included in dry-run responses so callers know what to expect.
    /// </summary>
    BudgetLimits RecommendedBudget(PlaybookDepth depth) =>
        PlaybookBudgetPlanner.GetBaseRecommended(Id, depth);

    /// <summary>Execute the playbook end-to-end.</summary>
    Task<PlaybookResponse> RunAsync(PlaybookContext context, PlaybookRequest request, CancellationToken ct);
}
