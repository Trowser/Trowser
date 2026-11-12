namespace Trowser.Security;

/// <summary>
/// When two-phase reach hits a sink with a safe execution oracle, run phase-2 confirmation
/// even if the caller omitted confirmExecution (avoids medium-only false negatives on real DOM XSS).
/// </summary>
internal static class TraceInputConfirmExecutionPolicy
{
    private static readonly string[] ConfirmableSinkFragments =
    [
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "document.writeln",
        "createContextualFragment", "setHTMLUnsafe", "shadowRoot.innerHTML",
        "eval", "Function", "setTimeout(string)", "setInterval(string)", "Function.constructor"
    ];

    public static bool EffectiveConfirmExecution(TraceInputOptions options, InputTraceResult? reachAfterPhase1)
    {
        if (options.ConfirmExecution)
            return true;
        if (options.ReachPhaseOnly || !options.MonitorSinks || !options.TwoPhase)
            return false;
        if (reachAfterPhase1 == null)
            return false;
        return ReachIndicatesConfirmableSink(reachAfterPhase1);
    }

    public static bool ReachIndicatesConfirmableSink(InputTraceResult reach)
    {
        if (reach.Sinks?.Hits.Any(h => SinkIsConfirmable(h.Sink)) == true)
            return true;

        if (reach.ReachMap?.Any(e => e.ContainsReachCanary && SinkIsConfirmable(e.Sink)) == true)
            return true;

        if (reach.Sinks is { PayloadReachedSink: true, MostDangerousSink: { } s } && SinkIsConfirmable(s))
            return true;

        if (ReachIndicatesNavigationSink(reach))
            return true;

        return false;
    }

    public static bool ReachIndicatesNavigationSink(InputTraceResult reach)
    {
        if (reach.Sinks?.Hits.Any(h => h.ContainsPayload && IsNavigationSink(h.Sink)) == true)
            return true;
        if (reach.ReachMap?.Any(e => e.ContainsReachCanary && IsNavigationSink(e.Sink)) == true)
            return true;
        return false;
    }

    public static bool TraceHasNavigationSinks(InputTraceResult trace)
    {
        if (trace.Sinks?.Hits.Any(h => IsNavigationSink(h.Sink)) == true)
            return true;
        if (trace.Sinks?.Instrumented.Any(IsNavigationSink) == true)
            return true;
        if (trace.Sinks?.SinksSeen.Any(IsNavigationSink) == true)
            return true;
        if (trace.ReachMap?.Any(e => IsNavigationSink(e.Sink)) == true)
            return true;
        return false;
    }

    private static bool SinkIsConfirmable(string sink) =>
        ConfirmableSinkFragments.Any(f => sink.Contains(f, StringComparison.OrdinalIgnoreCase));

    internal static bool IsNavigationSink(string sink) =>
        sink.Contains("location.", StringComparison.OrdinalIgnoreCase)
        || sink.Equals("window.open", StringComparison.OrdinalIgnoreCase)
        || sink.Contains("window.open", StringComparison.OrdinalIgnoreCase)
        || sink.Contains("location.assign", StringComparison.OrdinalIgnoreCase)
        || sink.Contains("location.replace", StringComparison.OrdinalIgnoreCase)
        || sink.Contains("location.href", StringComparison.OrdinalIgnoreCase);
}
