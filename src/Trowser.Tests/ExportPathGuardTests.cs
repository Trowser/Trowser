using System;
using System.Collections.Generic;
using System.IO;
using Trowser.Api;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class ExportPathGuardTests
{
    [Theory]
    [InlineData(@"\\attacker\share\x.json")]
    [InlineData(@"//attacker/share/x.json")]
    [InlineData(@"\\?\C:\temp\x.json")]
    [InlineData(@"\\.\pipe\x")]
    [InlineData(@"file://attacker/x.json")]
    [InlineData(@"C:\temp\x.json:evil")]
    [InlineData(@"x.txt:Zone.Identifier")]
    public void RemoteDeviceAndStreamPaths_AreRejected(string path)
    {
        Assert.True(ExportPathGuard.IsRemoteOrDevicePath(path));
        Assert.False(ExportPathGuard.TryResolveRead(path, out _, out var readError));
        Assert.NotNull(readError);
        Assert.False(ExportPathGuard.TryResolve(path, safeMode: false, out _, out var writeError));
        Assert.NotNull(writeError);
    }

    [Theory]
    [InlineData("report.hta")]
    [InlineData("report.url")]
    [InlineData("report.exe")]
    [InlineData("report.settingcontent-ms")]
    [InlineData("report.hta.")]
    public void NonDocumentExtensions_AreRejectedForWrites(string name)
    {
        var path = Path.Combine(Path.GetTempPath(), name);
        Assert.False(ExportPathGuard.TryResolve(path, safeMode: false, out _, out var error));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("journal.json")]
    [InlineData("journal.md")]
    [InlineData("recording.csx")]
    [InlineData("checkout.trw")]
    [InlineData("traffic.har")]
    public void DocumentExtensions_AreAllowedOutsideSafeMode(string name)
    {
        var path = Path.Combine(Path.GetTempPath(), name);
        Assert.True(ExportPathGuard.TryResolve(path, safeMode: false, out var full, out _));
        Assert.Equal(Path.GetFullPath(path), full);
        Assert.False(ExportPathGuard.TryResolve(path, safeMode: true, out _, out _));
    }

    [Fact]
    public void StartupFolder_IsRejected()
    {
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (string.IsNullOrEmpty(startup)) return;
        Assert.False(ExportPathGuard.TryResolve(Path.Combine(startup, "x.html"), safeMode: false, out _, out _));
    }

    [Fact]
    public void Base64LookingValues_AreNotProbedAsFiles()
    {
        Assert.False(ExportPathGuard.IsExistingLocalFile("//8AAAAA"));
        Assert.False(ExportPathGuard.IsExistingLocalFile(@"\\attacker\share\a.png"));
    }
}

public class DirectFetchRedirectHeaderTests
{
    [Fact]
    public void CrossOriginHop_DropsCredentialHeaders()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Authorization"] = "Bearer secret",
            ["X-Api-Key"] = "k",
            ["X-CSRF-Token"] = "t",
            ["Cookie"] = "sid=1",
            ["Accept"] = "application/json",
            ["X-Requested-With"] = "XMLHttpRequest",
        };

        var kept = DirectFetchHelper.WithoutCredentialHeaders(headers)!;

        Assert.Equal(new[] { "Accept", "X-Requested-With" }, kept.Keys);
    }

    [Theory]
    [InlineData("https://a.example/x", "https://a.example/y", true)]
    [InlineData("https://a.example/x", "http://a.example/x", false)]
    [InlineData("https://a.example/x", "https://b.example/x", false)]
    [InlineData("https://a.example/x", "https://a.example:8443/x", false)]
    public void SameOrigin_ComparesSchemeHostPort(string a, string b, bool expected) =>
        Assert.Equal(expected, DirectFetchHelper.IsSameOrigin(a, b));
}
