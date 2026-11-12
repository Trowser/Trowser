using Trowser.EndpointProbe;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class AuthControlIdentifierTests
{
    [Fact]
    public void tamper_one_char_flips_middle_alnum()
    {
        // "abcW" alnums 0..3, middle index 2 → 'c'→'d'
        Assert.Equal("abdW", AuthControlIdentifier.TamperOneChar("abcW"));
        // "token9" alnums 0..5, middle index 3 → 'e'→'f'
        Assert.Equal("tokfn9", AuthControlIdentifier.TamperOneChar("token9"));
        Assert.Equal("A", AuthControlIdentifier.TamperOneChar("Z"));
        Assert.Equal("---X", AuthControlIdentifier.TamperOneChar("---"));
        // Prefer middle over edge: "abcd" middle index 2 → 'c'→'d'
        Assert.Equal("abdd", AuthControlIdentifier.TamperOneChar("abcd"));
    }

    [Fact]
    public void collect_candidates_splits_cookies_and_filters_headers()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = "session=abc123; theme=dark; csrftoken=tok1",
            ["Authorization"] = "Bearer eyJhbGciOiJub25lIn0.e30.",
            ["RequestVerificationToken"] = "rvt-value",
            ["Accept"] = "application/json",
            ["Content-Type"] = "application/json",
            ["Host"] = "example.com"
        };
        var body = "{\"__RequestVerificationToken\":\"form-tok\",\"name\":\"alice\"}";
        var options = new AuthControlIdentifier.ProbeOptions
        {
            Endpoints = Array.Empty<EndpointProbeItem>(),
            AllHeaders = false
        };

        var candidates = AuthControlIdentifier.CollectCandidates(
            "https://example.com/api/me?access_token=qtok&page=1",
            headers,
            body,
            options);

        Assert.Contains(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Cookie && c.Name == "session");
        Assert.Contains(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Cookie && c.Name == "theme");
        Assert.Contains(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Cookie && c.Name == "csrftoken");
        Assert.Contains(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Header && c.Name == "Authorization");
        Assert.Contains(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Header && c.Name == "RequestVerificationToken");
        Assert.DoesNotContain(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Header && c.Name == "Accept");
        Assert.DoesNotContain(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Header && c.Name == "Host");
        Assert.Contains(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Body && c.Name == "__RequestVerificationToken");
        Assert.DoesNotContain(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Body && c.Name == "name");
        Assert.Contains(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Query && c.Name == "access_token");
        Assert.DoesNotContain(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.Query && c.Name == "page");
    }

    [Fact]
    public void collect_candidates_all_headers_includes_accept()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Accept"] = "application/json",
            ["X-Custom"] = "1"
        };
        var options = new AuthControlIdentifier.ProbeOptions
        {
            Endpoints = Array.Empty<EndpointProbeItem>(),
            AllHeaders = true
        };

        var candidates = AuthControlIdentifier.CollectCandidates(
            "https://example.com/",
            headers,
            null,
            options);

        Assert.Contains(candidates, c => c.Name == "Accept");
        Assert.Contains(candidates, c => c.Name == "X-Custom");
    }

    [Theory]
    [InlineData(true, true, true, AuthControlIdentifier.ControlVerdict.Enforced)]
    [InlineData(true, true, false, AuthControlIdentifier.ControlVerdict.PresenceOnly)]
    [InlineData(true, false, false, AuthControlIdentifier.ControlVerdict.Ignored)]
    [InlineData(true, false, true, AuthControlIdentifier.ControlVerdict.ValueCheckedButOptional)]
    [InlineData(false, true, true, AuthControlIdentifier.ControlVerdict.Inconclusive)]
    public void classify_verdicts(
        bool baselineOk,
        bool omitChanged,
        bool tamperChanged,
        AuthControlIdentifier.ControlVerdict expected)
    {
        var omit = new AuthControlIdentifier.MutationResult
        {
            Mutation = AuthControlIdentifier.MutationKind.Omit,
            Status = omitChanged ? 401 : 200,
            ResponseChanged = omitChanged,
            BodiesMatchBaseline = !omitChanged
        };
        var tamper = new AuthControlIdentifier.MutationResult
        {
            Mutation = AuthControlIdentifier.MutationKind.Tamper,
            Status = tamperChanged ? 401 : 200,
            ResponseChanged = tamperChanged,
            BodiesMatchBaseline = !tamperChanged
        };

        Assert.Equal(expected, AuthControlIdentifier.Classify(baselineOk, omit, tamper));
    }

    [Theory]
    [InlineData("X-XSRF-TOKEN", "X-XSRF-TOKEN", true)]
    [InlineData("XSRF-TOKEN", "X-XSRF-TOKEN", true)]
    [InlineData("X-XSRF-TOKEN", "XSRF-TOKEN", true)]
    [InlineData("session", "Session", true)]
    [InlineData("session", "Authorization", false)]
    public void cookie_header_pair_names_match(string cookieName, string headerName, bool expected)
    {
        Assert.Equal(expected, AuthControlIdentifier.CookieHeaderPairNamesMatch(cookieName, headerName));
    }

    [Fact]
    public void collect_candidates_adds_cookie_header_pair_when_values_match()
    {
        var token = "abc123def4567890";
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = $"session=s1; XSRF-TOKEN={token}",
            ["X-XSRF-TOKEN"] = token,
            ["Authorization"] = "Bearer x"
        };
        var options = new AuthControlIdentifier.ProbeOptions
        {
            Endpoints = Array.Empty<EndpointProbeItem>(),
            AllHeaders = false
        };

        var candidates = AuthControlIdentifier.CollectCandidates("https://example.com/api", headers, null, options);

        var pair = Assert.Single(candidates, c => c.Kind == AuthControlIdentifier.CandidateKind.CookieHeaderPair);
        Assert.Equal("XSRF-TOKEN + X-XSRF-TOKEN", pair.Name);
        Assert.Equal(token, pair.OriginalValue);
        Assert.Equal("XSRF-TOKEN", pair.PairedCookieName);
        Assert.Equal("X-XSRF-TOKEN", pair.PairedHeaderName);
    }

    [Fact]
    public void apply_mutation_cookie_header_pair_tampers_both_identically()
    {
        var token = "sameTokenValue9";
        var candidate = new AuthControlIdentifier.Candidate
        {
            Kind = AuthControlIdentifier.CandidateKind.CookieHeaderPair,
            Name = "X-XSRF-TOKEN",
            OriginalValue = token,
            PairedCookieName = "XSRF-TOKEN",
            PairedHeaderName = "X-XSRF-TOKEN"
        };
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = $"XSRF-TOKEN={token}",
            ["X-XSRF-TOKEN"] = token
        };

        AuthControlIdentifier.ApplyMutation(
            "https://example.com/", headers, null, candidate,
            AuthControlIdentifier.MutationKind.Tamper,
            out _, out var tamperedHeaders, out _, out var tamperedValue);

        Assert.NotNull(tamperedValue);
        Assert.Equal(tamperedValue, tamperedHeaders["X-XSRF-TOKEN"]);
        Assert.Contains($"{candidate.PairedCookieName}={tamperedValue}", tamperedHeaders["Cookie"]);
        Assert.NotEqual(token, tamperedValue);
    }

    [Fact]
    public void apply_mutation_cookie_header_pair_omits_both()
    {
        var candidate = new AuthControlIdentifier.Candidate
        {
            Kind = AuthControlIdentifier.CandidateKind.CookieHeaderPair,
            Name = "X-XSRF-TOKEN",
            OriginalValue = "tok",
            PairedCookieName = "X-XSRF-TOKEN",
            PairedHeaderName = "X-XSRF-TOKEN"
        };
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = "X-XSRF-TOKEN=tok; other=1",
            ["X-XSRF-TOKEN"] = "tok"
        };

        AuthControlIdentifier.ApplyMutation(
            "https://example.com/", headers, null, candidate,
            AuthControlIdentifier.MutationKind.Omit,
            out _, out var omitHeaders, out _, out _);

        Assert.False(omitHeaders.ContainsKey("X-XSRF-TOKEN"));
        Assert.Equal("other=1", omitHeaders["Cookie"]);
    }

    [Fact]
    public void interesting_header_and_field_names()
    {
        Assert.True(AuthControlIdentifier.IsInterestingHeaderName("Authorization"));
        Assert.True(AuthControlIdentifier.IsInterestingHeaderName("X-My-Api-Token"));
        Assert.False(AuthControlIdentifier.IsInterestingHeaderName("Accept-Language"));
        Assert.True(AuthControlIdentifier.IsInterestingFieldName("__RequestVerificationToken"));
        Assert.True(AuthControlIdentifier.IsInterestingFieldName("csrf_token"));
        Assert.False(AuthControlIdentifier.IsInterestingFieldName("username"));
    }

    [Fact]
    public void enforced_cookie_flags_warn_when_weak()
    {
        var jar = new List<Dictionary<string, object>>
        {
            new()
            {
                ["name"] = "session",
                ["httpOnly"] = false,
                ["secure"] = false,
                ["sameSite"] = "none",
                ["domain"] = "example.com"
            }
        };

        var warning = AuthControlIdentifier.EvaluateEnforcedCookieFlags("session", jar, "https://example.com/api");
        Assert.NotNull(warning);
        Assert.Contains("HttpOnly", warning);
        Assert.Contains("Secure", warning);
        Assert.Contains("SameSite", warning);
    }

    [Fact]
    public void enforced_cookie_flags_ok_when_httponly_secure_lax()
    {
        var jar = new List<Dictionary<string, object>>
        {
            new()
            {
                ["name"] = "session",
                ["httpOnly"] = true,
                ["secure"] = true,
                ["sameSite"] = "lax",
                ["domain"] = "example.com"
            }
        };

        Assert.Null(AuthControlIdentifier.EvaluateEnforcedCookieFlags("session", jar, "https://example.com/"));
        Assert.True(AuthControlIdentifier.IsSameSiteAtLeastLax("strict"));
        Assert.True(AuthControlIdentifier.IsSameSiteAtLeastLax("Lax"));
        Assert.False(AuthControlIdentifier.IsSameSiteAtLeastLax("none"));
        Assert.False(AuthControlIdentifier.IsSameSiteAtLeastLax(""));
    }
}
