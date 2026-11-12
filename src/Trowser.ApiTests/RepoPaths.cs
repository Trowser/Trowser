namespace Trowser.ApiTests;

internal static class RepoPaths
{
    public static string Root()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Trowser.sln")))
            dir = dir.Parent;
        if (dir == null)
            throw new InvalidOperationException("Could not locate repo root (Trowser.sln).");
        return dir.FullName;
    }

    public static string TrowserExe()
    {
        var env = Environment.GetEnvironmentVariable("TROWSER_EXE");
        if (!string.IsNullOrWhiteSpace(env))
        {
            var full = Path.GetFullPath(env.Trim());
            if (File.Exists(full)) return full;
            throw new FileNotFoundException($"TROWSER_EXE points to a missing file: {full}", full);
        }

        var root = Root();
        var candidates = new[]
        {
            Path.Combine(root, "src", "Trowser", "bin", "Release", "net8.0-windows", "win-x64", "Trowser.exe"),
            Path.Combine(root, "src", "Trowser", "bin", "Debug", "net8.0-windows", "win-x64", "Trowser.exe"),
            Path.Combine(root, "dist", "Trowser.exe")
        };
        foreach (var c in candidates)
            if (File.Exists(c)) return Path.GetFullPath(c);
        throw new FileNotFoundException(
            "Build Trowser.exe first (Release or Debug), or set TROWSER_EXE to the exe path.",
            candidates[0]);
    }
}
