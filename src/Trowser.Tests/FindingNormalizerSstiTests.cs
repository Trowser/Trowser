using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.SessionLog;
using Xunit;

namespace Trowser.Tests;

public class FindingNormalizerSstiTests
{
    [Fact]
    public void Auto_scan_ssti_scanner_maps_to_suspected_not_confirmed()
    {
        var normalized = FindingNormalizer.NormalizeAutoScan(
        [
            new AutoScanPipeline.AutoScanFinding
            {
                Scanner = "ssti",
                Severity = "high",
                Title = "SSTI suspected (arithmetic reflection (49/56)) via 'q'",
                Endpoint = "https://app.example/search"
            }
        ]);

        var finding = Assert.Single(normalized);
        Assert.Equal("ssti-suspected", finding.Category);
    }

    [Fact]
    public void Journal_template_injection_mention_maps_to_suspected()
    {
        var normalized = FindingNormalizer.NormalizeJournal(
        [
            new SessionLogger.JournalEntry
            {
                Index = 1,
                Kind = NoteKinds.Bug,
                Summary = "Possible template injection in preview field",
                Details = "Needs manual confirm with second expression."
            }
        ]);

        var finding = Assert.Single(normalized);
        Assert.Equal("ssti-suspected", finding.Category);
    }
}
