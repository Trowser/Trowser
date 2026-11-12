namespace Trowser.Testing;

/// <summary>
/// Records the result of a single assertion.
/// </summary>
public class AssertionResult
{
    public bool Passed { get; init; }
    public string Description { get; init; } = "";
    public string? Details { get; init; }
    public string? Section { get; init; }
}

/// <summary>
/// Provides test assertion methods with pass/fail tracking and summary reporting.
/// Assertions do NOT throw on failure -- they log and continue, so all tests in a script run to completion.
/// Access via the Assert property in scripts: Assert.Equal(...), Assert.Contains(...), etc.
/// </summary>
public class TestAssert
{
    private readonly Action<string, string> _logColored;
    private readonly List<AssertionResult> _results = new();
    private string? _currentSection;

    public int PassCount => _results.Count(r => r.Passed);
    public int FailCount => _results.Count(r => !r.Passed);
    public int TotalCount => _results.Count;
    public bool AllPassed => _results.All(r => r.Passed);
    public IReadOnlyList<AssertionResult> Results => _results.AsReadOnly();

    /// <summary>The currently active test section name, or null.</summary>
    public string? CurrentSection => _currentSection;

    public TestAssert(Action<string, string> logColored)
    {
        _logColored = logColored;
    }

    /// <summary>
    /// Start a named test section. All subsequent assertions will be grouped under this section
    /// in the summary output. Prints a section header to the log.
    /// </summary>
    public void Section(string name)
    {
        _currentSection = name;
        _logColored("", "#666666");
        _logColored($"── {name} ──", "#569CD6");
    }

    /// <summary>
    /// Assert that a condition is true.
    /// </summary>
    public void True(bool condition, string? message = null)
    {
        var desc = message ?? "Expected: true";
        Record(condition, desc, condition ? null : "Got: false");
    }

    /// <summary>
    /// Assert that a condition is false.
    /// </summary>
    public void False(bool condition, string? message = null)
    {
        var desc = message ?? "Expected: false";
        Record(!condition, desc, !condition ? null : "Got: true");
    }

    /// <summary>
    /// Assert that two values are equal.
    /// </summary>
    public void Equal<T>(T expected, T actual, string? message = null)
    {
        var areEqual = EqualityComparer<T>.Default.Equals(expected, actual);
        var desc = message ?? $"Expected: {Format(expected)}";
        Record(areEqual, desc, areEqual ? null : $"Expected: {Format(expected)}\n     Got: {Format(actual)}");
    }

    /// <summary>
    /// Assert that two values are not equal.
    /// </summary>
    public void NotEqual<T>(T expected, T actual, string? message = null)
    {
        var areEqual = EqualityComparer<T>.Default.Equals(expected, actual);
        var desc = message ?? $"Expected not: {Format(expected)}";
        Record(!areEqual, desc, !areEqual ? null : $"Values are equal: {Format(actual)}");
    }

    /// <summary>
    /// Assert that a string contains the expected substring.
    /// </summary>
    public void Contains(string expectedSubstring, string actual, string? message = null)
    {
        var contains = actual.Contains(expectedSubstring, StringComparison.Ordinal);
        var desc = message ?? $"Contains: \"{Truncate(expectedSubstring, 60)}\"";
        Record(contains, desc, contains ? null :
            $"Expected to contain: \"{Truncate(expectedSubstring, 80)}\"\n     In: \"{Truncate(actual, 80)}\"");
    }

    /// <summary>
    /// Assert that a string does not contain the given substring.
    /// </summary>
    public void NotContains(string unexpectedSubstring, string actual, string? message = null)
    {
        var contains = actual.Contains(unexpectedSubstring, StringComparison.Ordinal);
        var desc = message ?? $"Does not contain: \"{Truncate(unexpectedSubstring, 60)}\"";
        Record(!contains, desc, !contains ? null :
            $"Expected NOT to contain: \"{Truncate(unexpectedSubstring, 80)}\"\n     In: \"{Truncate(actual, 80)}\"");
    }

    /// <summary>
    /// Assert that a string matches a regex pattern.
    /// </summary>
    public void Matches(string pattern, string actual, string? message = null)
    {
        var matches = System.Text.RegularExpressions.Regex.IsMatch(actual, pattern);
        var desc = message ?? $"Matches pattern: {Truncate(pattern, 60)}";
        Record(matches, desc, matches ? null :
            $"Expected to match: /{pattern}/\n     In: \"{Truncate(actual, 80)}\"");
    }

    /// <summary>
    /// Assert that a value is null.
    /// </summary>
    public void Null(object? value, string? message = null)
    {
        var desc = message ?? "Expected: null";
        Record(value is null, desc, value is null ? null : $"Got: {Format(value)}");
    }

    /// <summary>
    /// Assert that a value is not null.
    /// </summary>
    public void NotNull(object? value, string? message = null)
    {
        var desc = message ?? "Expected: not null";
        Record(value is not null, desc, value is not null ? null : "Got: null");
    }

    /// <summary>
    /// Assert that a string is not null or empty.
    /// </summary>
    public void NotEmpty(string? value, string? message = null)
    {
        var desc = message ?? "Expected: non-empty string";
        Record(!string.IsNullOrEmpty(value), desc,
            !string.IsNullOrEmpty(value) ? null : $"Got: {(value is null ? "null" : "empty string")}");
    }

    /// <summary>
    /// Assert that a numeric value is greater than the expected value.
    /// </summary>
    public void GreaterThan(double expected, double actual, string? message = null)
    {
        var desc = message ?? $"Greater than: {expected}";
        Record(actual > expected, desc, actual > expected ? null : $"Expected > {expected}, got: {actual}");
    }

    /// <summary>
    /// Assert that a numeric value is less than the expected value.
    /// </summary>
    public void LessThan(double expected, double actual, string? message = null)
    {
        var desc = message ?? $"Less than: {expected}";
        Record(actual < expected, desc, actual < expected ? null : $"Expected < {expected}, got: {actual}");
    }

    /// <summary>
    /// Assert that a collection has the expected count.
    /// </summary>
    public void CountEquals<T>(int expectedCount, IEnumerable<T> collection, string? message = null)
    {
        var actualCount = collection.Count();
        var desc = message ?? $"Count equals: {expectedCount}";
        Record(actualCount == expectedCount, desc,
            actualCount == expectedCount ? null : $"Expected count: {expectedCount}, got: {actualCount}");
    }

    /// <summary>
    /// Unconditionally fail with a message.
    /// </summary>
    public void Fail(string message)
    {
        Record(false, message, null);
    }

    /// <summary>
    /// Unconditionally fail with a message and details about why.
    /// </summary>
    public void Fail(string message, string details)
    {
        Record(false, message, details);
    }

    /// <summary>
    /// Unconditionally pass with a message.
    /// </summary>
    public void Pass(string message)
    {
        Record(true, message, null);
    }

    /// <summary>
    /// Print a test summary with pass/fail counts, grouped by section.
    /// </summary>
    public void Summary()
    {
        _logColored("", "#666666");
        _logColored("─── Test Summary ───────────────────────────────", "#666666");

        if (TotalCount == 0)
        {
            _logColored("  No assertions were made.", "#CCCCCC");
            _logColored("────────────────────────────────────────────────", "#666666");
            return;
        }

        var sections = _results.GroupBy(r => r.Section ?? "(ungrouped)").ToList();
        if (sections.Count > 1 || sections[0].Key != "(ungrouped)")
        {
            foreach (var section in sections)
            {
                var sPass = section.Count(r => r.Passed);
                var sTotal = section.Count();
                var sFail = sTotal - sPass;
                var color = sFail > 0 ? "#F44747" : "#4EC9B0";
                var status = sFail > 0 ? $"{sPass}/{sTotal} passed, {sFail} FAILED" : $"{sPass}/{sTotal} passed";
                _logColored($"  {section.Key}: {status}", color);
            }
            _logColored("", "#666666");
        }

        if (AllPassed)
        {
            _logColored($"  ALL PASSED: {PassCount}/{TotalCount} assertions", "#4EC9B0");
        }
        else
        {
            _logColored($"  PASSED: {PassCount}/{TotalCount}", "#4EC9B0");
            _logColored($"  FAILED: {FailCount}/{TotalCount}", "#F44747");
        }

        _logColored("────────────────────────────────────────────────", "#666666");
    }

    /// <summary>
    /// Reset all assertion results (useful between test runs).
    /// </summary>
    public void Reset()
    {
        _results.Clear();
        _currentSection = null;
    }

    #region Helpers

    private void Record(bool passed, string description, string? details)
    {
        _results.Add(new AssertionResult
        {
            Passed = passed,
            Description = description,
            Details = details,
            Section = _currentSection
        });

        if (passed)
        {
            _logColored($"  PASS  {description}", "#4EC9B0");
        }
        else
        {
            _logColored($"  FAIL  {description}", "#F44747");
            if (!string.IsNullOrEmpty(details))
            {
                _logColored($"     {details}", "#F44747");
            }
        }
    }

    private static string Format(object? value)
    {
        if (value is null) return "null";
        if (value is string s) return $"\"{Truncate(s, 80)}\"";
        return value.ToString() ?? "null";
    }

    private static string Truncate(string value, int maxLength)
    {
        if (value.Length <= maxLength) return value;
        return value[..(maxLength - 3)] + "...";
    }

    #endregion
}
