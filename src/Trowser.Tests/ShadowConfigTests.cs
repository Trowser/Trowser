using Trowser.Chat;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class ShadowConfigTests
{
    [Fact]
    public void factory_defaults_include_headers_not_wcag()
    {
        var names = ShadowConfig.DefaultAuditNames;
        Assert.Contains("xss", names);
        Assert.Contains("retire-js", names);
        Assert.Contains("security-headers", names);
        Assert.Contains("network", names);
        Assert.Contains("console", names);
        Assert.DoesNotContain("wcag", names);
    }

    [Fact]
    public void new_config_uses_factory_audits()
    {
        var cfg = new ShadowConfig();
        Assert.False(cfg.Enabled);
        Assert.True(ShadowConfig.SameAuditSet(cfg.Audits, ShadowConfig.DefaultAuditNames));
    }

    [Fact]
    public void legacy_off_plus_all_migrates()
    {
        var cfg = new ShadowConfig
        {
            Enabled = false,
            Audits = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "all" }
        };
        Assert.True(cfg.LooksLikeLegacyFactoryDefault());
        Assert.True(cfg.ShouldApplyCurrentFactoryDefaults());
        cfg.ApplyCurrentFactoryDefaults();
        Assert.False(cfg.Enabled);
        Assert.True(ShadowConfig.SameAuditSet(cfg.Audits, ShadowConfig.DefaultAuditNames));
    }

    [Fact]
    public void previous_on_factory_with_wcag_migrates_off()
    {
        var cfg = new ShadowConfig
        {
            Enabled = true,
            Audits = new HashSet<string>(ShadowConfig.PreviousFactoryAuditNames, StringComparer.OrdinalIgnoreCase)
        };
        Assert.True(cfg.LooksLikePreviousFactoryDefault());
        cfg.ApplyCurrentFactoryDefaults();
        Assert.False(cfg.Enabled);
        Assert.DoesNotContain("wcag", cfg.Audits);
        Assert.Contains("security-headers", cfg.Audits);
    }

    [Fact]
    public void current_on_factory_migrates_off_once()
    {
        var cfg = new ShadowConfig
        {
            Enabled = true,
            Audits = ShadowConfig.CreateDefaultAudits()
        };
        Assert.True(cfg.LooksLikeCurrentOnFactoryDefault());
        Assert.True(cfg.ShouldApplyCurrentFactoryDefaults());
        cfg.ApplyCurrentFactoryDefaults();
        Assert.False(cfg.Enabled);
        Assert.Equal(ShadowConfig.CurrentFactoryGeneration, cfg.FactoryGeneration);

        cfg.Enabled = true;
        Assert.False(cfg.ShouldApplyCurrentFactoryDefaults());
    }

    [Fact]
    public void customized_wcag_on_is_left_alone()
    {
        var cfg = new ShadowConfig
        {
            Enabled = true,
            Audits = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "xss", "retire-js", "wcag", "network", "console", "cookies"
            }
        };
        Assert.False(cfg.LooksLikePreviousFactoryDefault());
        Assert.False(cfg.ShouldApplyCurrentFactoryDefaults());
    }

    [Fact]
    public void llm_settings_migration_updates_previous_factory()
    {
        var settings = new LlmSettings
        {
            Shadow = new ShadowConfig
            {
                Enabled = true,
                Audits = new HashSet<string>(ShadowConfig.PreviousFactoryAuditNames, StringComparer.OrdinalIgnoreCase)
            }
        };
        settings.MigrateShadowFactoryDefaults();
        Assert.False(settings.Shadow.Enabled);
        Assert.True(ShadowConfig.SameAuditSet(settings.Shadow.Audits, ShadowConfig.DefaultAuditNames));
    }

    [Fact]
    public void active_law_sources_null_means_all_loaded_files()
    {
        var cfg = new ShadowConfig();
        Assert.True(cfg.IsLawSourceActive("embedded:GenericWebLaws.csx"));
        Assert.True(cfg.IsLawSourceActive(@"C:\docs\Trowser Quicktests\Laws\contoso.csx"));
    }

    [Fact]
    public void active_law_sources_filters_explicit_set()
    {
        var cfg = new ShadowConfig
        {
            ActiveLawSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "embedded:GenericWebLaws.csx"
            }
        };
        Assert.True(cfg.IsLawSourceActive("embedded:GenericWebLaws.csx"));
        Assert.False(cfg.IsLawSourceActive("embedded:WebPhysics.csx"));
    }

    [Fact]
    public void set_law_source_active_materializes_from_all_known()
    {
        var cfg = new ShadowConfig();
        var known = new[] { "embedded:A.csx", "embedded:B.csx", @"C:\Laws\site.csx" };
        cfg.SetLawSourceActive("embedded:B.csx", false, known);
        Assert.NotNull(cfg.ActiveLawSources);
        Assert.True(cfg.IsLawSourceActive("embedded:A.csx"));
        Assert.False(cfg.IsLawSourceActive("embedded:B.csx"));
        Assert.True(cfg.IsLawSourceActive(@"C:\Laws\site.csx"));
    }

    [Fact]
    public void xss_hygiene_skips_sri_and_inline_noise()
    {
        Assert.Contains("cross-domain-script", SecurityShadowManager.XssHygieneCategories);
        Assert.Contains("cross-domain-script-summary", SecurityShadowManager.XssHygieneCategories);
        Assert.Contains("inline-script", SecurityShadowManager.XssHygieneCategories);
        Assert.Contains("inline-handler", SecurityShadowManager.XssHygieneCategories);
        Assert.Contains("dangerous-sink", SecurityShadowManager.XssHygieneCategories);
        Assert.DoesNotContain("javascript-url", SecurityShadowManager.XssHygieneCategories);
        Assert.DoesNotContain("data-uri-execution", SecurityShadowManager.XssHygieneCategories);
        Assert.DoesNotContain("base-tag-hijack", SecurityShadowManager.XssHygieneCategories);
        Assert.DoesNotContain("external-form-action", SecurityShadowManager.XssHygieneCategories);
        Assert.DoesNotContain("dom-xss-flow", SecurityShadowManager.XssHygieneCategories);
    }
}
