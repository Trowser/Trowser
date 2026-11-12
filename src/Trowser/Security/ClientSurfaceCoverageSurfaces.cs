namespace Trowser.Security;

/// <summary>
/// Independent coverage states for client-surface triage (what was actually observed vs inferred).
/// </summary>
public sealed class ClientSurfaceCoverageSurfaces
{
    public bool RuntimeObserved { get; init; }
    public bool InlineScriptScanned { get; init; }
    public int ExternalScriptEntriesInLog { get; init; }
    public int ExternalScriptBodiesScanned { get; init; }
    public bool DocumentHeadersFromNetwork { get; init; }
    public List<string> DomFrameworkHints { get; init; } = [];

    public bool ScriptSurfaceIncomplete =>
        !RuntimeObserved
        || ExternalScriptEntriesInLog > ExternalScriptBodiesScanned;

    public object ToApiObject() => new
    {
        runtimeObserved = RuntimeObserved,
        inlineScriptScanned = InlineScriptScanned,
        externalScriptEntriesInLog = ExternalScriptEntriesInLog,
        externalScriptBodiesScanned = ExternalScriptBodiesScanned,
        documentHeadersFromNetwork = DocumentHeadersFromNetwork,
        domFrameworkHints = DomFrameworkHints,
        scriptSurfaceIncomplete = ScriptSurfaceIncomplete
    };
}
