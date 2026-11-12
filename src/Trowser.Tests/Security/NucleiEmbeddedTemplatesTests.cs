using Trowser.Security.Nuclei;
using Xunit;

namespace Trowser.Tests.Security;

public class NucleiEmbeddedTemplatesTests
{
    [Fact]
    public void All_embedded_resource_templates_parse()
    {
        var templates = NucleiRunner.GetAllTemplates(includeBuiltin: true, templatesDir: null);
        var load = NucleiRunner.GetAllTemplatesDetailed(includeBuiltin: true, templatesDir: null);

        Assert.Empty(load.Skipped);
        Assert.True(templates.Count >= 18, $"expected embedded pack templates, got {templates.Count}");
    }

    [Fact]
    public void Embedded_pack_includes_modern_exposure_ids()
    {
        var ids = NucleiRunner.GetAllTemplates(includeBuiltin: true)
            .Select(t => t.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("env-paths-exposure", ids);
        Assert.Contains("swagger-api-paths", ids);
        Assert.Contains("javascript-env-exposure", ids);
        Assert.Contains("frontend-config-json", ids);
    }
}
