namespace Trowser.Laws;

/// <summary>
/// Restricted globals for Law file compilation. Only declarative helpers — no browser actions.
/// </summary>
public sealed class LawDeclarationContext
{
    private readonly LawRegistry _registry;
    private string? _siteFilter;
    private string? _siteDefaultPagePattern;
    private string? _sourceFile;

    public LawDeclarationContext(LawRegistry registry)
    {
        _registry = registry;
    }

    internal void BeginFile(string sourceFile)
    {
        _sourceFile = sourceFile;
        _siteFilter = null;
        _siteDefaultPagePattern = null;
    }

    public void Site(string hostPattern, string? defaultPagePathPattern = null)
    {
        _siteFilter = hostPattern;
        _siteDefaultPagePattern = defaultPagePathPattern;
    }

    public LawBuilder Law(string name) =>
        new LawBuilder(_registry, name, _siteFilter, _sourceFile, _siteDefaultPagePattern);

    /// <summary>No-op during Shadow load; real checks run via Script Console / <see cref="LawService.CheckLawsAsync"/>.</summary>
    public Task CheckLaws(string? nameFilter = null) => Task.CompletedTask;

    public Task AssertLaws(string? nameFilter = null) => Task.CompletedTask;
}
