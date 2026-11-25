// @title Browser Compatibility Scan
// @shadow light
// @effects none
// Backward compatibility: scan JavaScript for modern features that may break older browsers
// Target browsers: iOS 16 (Safari 16.0), Android 13 (Chrome 107), vanilla versions when OS was shipped (most users have newer browser on Android)
// Change minIos/minAndroid to match your project's supported versions

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Backward compatibility scan: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Backward Compatibility");
await AssertCompatible(minIos: 16, minAndroid: 13);
await PrintCompatibilityReport(minIos: 16, minAndroid: 13);
