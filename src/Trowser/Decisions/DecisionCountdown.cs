namespace Trowser.Decisions;

/// <summary>
/// Discrete countdown milestones for the decision card footer. Updates only at these thresholds
/// (5 min, 4, 3, 2, 1, 45 s, 30, 15) so the UI does not tick every second.
/// </summary>
public static class DecisionCountdown
{
    /// <summary>Seconds remaining at which the footer text changes, highest first.</summary>
    public static readonly int[] MilestonesSeconds = [300, 240, 180, 120, 60, 45, 30, 15];

    /// <summary>
    /// The milestone bucket for the current remaining time. Below the last milestone, keeps showing
    /// 15 seconds until the decision resolves.
    /// </summary>
    public static int MilestoneFor(int secondsRemaining)
    {
        foreach (var m in MilestonesSeconds)
        {
            if (secondsRemaining >= m)
                return m;
        }
        return MilestonesSeconds[^1];
    }

    public static string Format(int milestoneSeconds) =>
        milestoneSeconds >= 60
            ? milestoneSeconds == 60 ? "1 minute left" : $"{milestoneSeconds / 60} minutes left"
            : $"{milestoneSeconds} seconds left";
}
