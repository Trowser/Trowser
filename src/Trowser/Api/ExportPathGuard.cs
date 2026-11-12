using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Trowser.Api;

/// <summary>
/// Guards caller-supplied file paths used by "export to disk" endpoints (journal/HAR/report export)
/// and by endpoints that read a caller-named local file (imports, bodyFile, screenshot compare).
/// These endpoints are authenticated, but they are reachable even in safe mode (some are GET) and,
/// unlike <c>execute-script</c>, an unrestricted <c>Path.GetFullPath</c> write is a persistence
/// primitive (e.g. dropping an .hta or .url into a Startup folder). Writes are narrowed to a
/// known document extension outside auto-run locations, and disabled entirely in safe mode.
/// Both reads and writes refuse UNC and device paths: merely probing <c>\\host\share</c> makes
/// Windows authenticate to that host with the user's NTLM credentials.
/// </summary>
public static class ExportPathGuard
{
    private static readonly HashSet<string> AllowedExportExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "", ".json", ".har", ".html", ".htm", ".md", ".markdown", ".txt", ".log", ".csv", ".xml",
        ".yaml", ".yml", ".sarif", ".csx", ".trw", ".png", ".jpg", ".jpeg", ".pdf"
    };

    /// <summary>
    /// Validates and canonicalises <paramref name="requestedPath"/>. Returns false with a
    /// caller-facing <paramref name="error"/> when the write must be refused.
    /// </summary>
    public static bool TryResolve(string? requestedPath, bool safeMode, out string fullPath, out string? error)
    {
        fullPath = "";
        error = null;

        if (string.IsNullOrWhiteSpace(requestedPath))
        {
            error = "No output path provided.";
            return false;
        }

        if (safeMode)
        {
            error = "Safe mode: writing exported files to disk is disabled. Read the content from the response body instead.";
            return false;
        }

        if (!TryResolveLocal(requestedPath, out var full, out error))
            return false;

        var ext = Path.GetExtension(full);
        if (!AllowedExportExtensions.Contains(ext))
        {
            error = $"Refusing to write export with extension '{ext}'. Use a document extension such as .json, .html, .md, .txt, .har, .csx or .trw.";
            return false;
        }

        if (IsInAutoRunLocation(full))
        {
            error = "Refusing to write export into a startup/auto-run location.";
            return false;
        }

        fullPath = full;
        return true;
    }

    /// <summary>
    /// Validates a caller-supplied path that Trowser will read. Only local drive paths are accepted.
    /// </summary>
    public static bool TryResolveRead(string? requestedPath, out string fullPath, out string? error)
    {
        fullPath = "";
        if (string.IsNullOrWhiteSpace(requestedPath))
        {
            error = "No input path provided.";
            return false;
        }
        if (!TryResolveLocal(requestedPath, out var full, out error))
            return false;
        fullPath = full;
        return true;
    }

    /// <summary>Reads a caller-named local text file; throws <see cref="UnauthorizedAccessException"/> for rejected paths.</summary>
    public static Task<string> ReadLocalTextAsync(string requestedPath)
    {
        if (!TryResolveRead(requestedPath, out var full, out var error))
            throw new UnauthorizedAccessException(error);
        return File.ReadAllTextAsync(full);
    }

    /// <summary>
    /// True when <paramref name="value"/> is an existing local file. Never touches the file system for
    /// UNC/device values, so parameters that accept "path or base64" cannot trigger an SMB connection.
    /// </summary>
    public static bool IsExistingLocalFile(string value) =>
        !IsRemoteOrDevicePath(value) && File.Exists(value);

    /// <summary>True when <paramref name="path"/> names a UNC share, a device namespace, or an alternate data stream.</summary>
    public static bool IsRemoteOrDevicePath(string path)
    {
        var p = path.Trim();
        if (p.StartsWith(@"\\", StringComparison.Ordinal) || p.StartsWith("//", StringComparison.Ordinal)
            || p.StartsWith(@"\/", StringComparison.Ordinal) || p.StartsWith(@"/\", StringComparison.Ordinal))
            return true;
        if (p.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            return true;
        // A colon is only legal as the drive separator; anything later is an NTFS stream (file.txt:evil).
        return p.IndexOf(':', p.Length >= 2 && p[1] == ':' ? 2 : 0) >= 0;
    }

    private static bool TryResolveLocal(string requestedPath, out string full, out string? error)
    {
        full = "";
        error = null;
        if (IsRemoteOrDevicePath(requestedPath))
        {
            error = "Only local file paths are accepted (no UNC shares, device paths, file: URLs or alternate data streams).";
            return false;
        }

        try { full = Path.GetFullPath(requestedPath); }
        catch (Exception ex) { error = $"Invalid path: {ex.Message}"; return false; }

        if (IsRemoteOrDevicePath(full))
        {
            error = "Only local file paths are accepted (no UNC shares, device paths, file: URLs or alternate data streams).";
            return false;
        }
        return true;
    }

    private static bool IsInAutoRunLocation(string fullPath)
    {
        foreach (var dir in AutoRunDirs())
        {
            if (string.IsNullOrEmpty(dir)) continue;
            var prefix = dir.TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static IEnumerable<string> AutoRunDirs()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
    }
}
