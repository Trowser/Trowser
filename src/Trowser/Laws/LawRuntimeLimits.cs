namespace Trowser.Laws;

internal static class LawRuntimeLimits
{
    /// <summary>Per-law predicate evaluation budget (Shadow Light and manual check).</summary>
    public const int DefaultPredicateTimeoutMs = 5000;

    public const int HeavyPredicateTimeoutMs = 30_000;
}
