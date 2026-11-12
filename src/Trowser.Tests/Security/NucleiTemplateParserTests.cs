using Trowser.Security.Nuclei;
using Xunit;

namespace Trowser.Tests.Security;

public class NucleiTemplateParserTests
{
    [Fact]
    public void Parses_embedded_style_template()
    {
        var yaml = """
            id: test-exposure
            info:
              name: Test
              severity: info
              tags: exposure
            http:
              - method: GET
                path:
                  - "{{BaseURL}}/.env"
                matchers:
                  - type: status
                    status:
                      - 200
            """;

        Assert.True(NucleiTemplateParser.TryParse(yaml, out var t, out var reason));
        Assert.Null(reason);
        Assert.NotNull(t);
        Assert.Single(t!.HttpRequests);
        Assert.Empty(t.HttpRequests[0].PathPayloadValues);
    }

    [Fact]
    public void Parses_paths_payload_and_stop_at_first_match()
    {
        var yaml = """
            id: swagger-api
            info:
              name: Swagger paths
              severity: info
            http:
              - method: GET
                path:
                  - "{{BaseURL}}{{paths}}"
                payloads:
                  paths:
                    - "/swagger.json"
                    - "/api-docs"
                stop-at-first-match: true
                matchers:
                  - type: word
                    words:
                      - "swagger"
                  - type: status
                    status:
                      - 200
            """;

        var ok = NucleiTemplateParser.TryParse(yaml, out var t, out var reason);
        Assert.True(ok, reason ?? "parse failed");
        Assert.NotNull(t);
        var req = t!.HttpRequests[0];
        Assert.Equal(2, req.PathPayloadValues.Count);
        Assert.True(req.StopAtFirstMatch);
    }

    [Fact]
    public void Accepts_hostname_variable()
    {
        var yaml = """
            id: host-var
            info:
              name: Host var
              severity: info
            http:
              - method: GET
                path:
                  - "{{Scheme}}://{{Hostname}}/robots.txt"
                matchers:
                  - type: status
                    status:
                      - 200
            """;

        Assert.True(NucleiTemplateParser.TryParse(yaml, out _, out var reason));
        Assert.Null(reason);
    }

    [Fact]
    public void Rejects_clusterbomb_payloads()
    {
        var yaml = """
            id: bad
            info:
              name: Bad
              severity: info
            http:
              - raw:
                  - "GET / HTTP/1.1"
                payloads:
                  user:
                    - admin
                attack: clusterbomb
                matchers:
                  - type: status
                    status:
                      - 200
            """;

        Assert.False(NucleiTemplateParser.TryParse(yaml, out _, out var reason));
        Assert.NotNull(reason);
    }

    [Fact]
    public void Target_variables_substitute_path_and_file()
    {
        var uri = new Uri("https://example.com:8443/app/page.php");
        var vars = NucleiTargetVariables.FromUri(uri);
        Assert.Equal("example.com:8443", vars.Hostname);
        Assert.Equal("example.com", vars.Host);
        Assert.Equal("/app", vars.Path);
        Assert.Equal("page.php", vars.File);
        var url = vars.Apply("{{RootURL}}{{paths}}", "/swagger.json");
        Assert.Equal("https://example.com:8443/swagger.json", url);
    }

    [Fact]
    public void Compatibility_summary_counts_skipped()
    {
        var load = new NucleiRunner.TemplateLoad(
            [new NucleiTemplate { Id = "ok" }],
            [new NucleiRunner.SkippedTemplate("skip.yaml", "raw HTTP blocks not supported", "user")]);
        var summary = NucleiCompatibilitySummary.FromLoad(load);
        Assert.Equal(1, summary.RunnableCount);
        Assert.Equal(1, summary.SkippedCount);
        Assert.Equal(2, summary.FilesScanned);
    }
}
