// @title Browser Compatibility Scan
// @shadow light
// @effects none
// Backward compatibility: scan JavaScript for modern features that may break older browsers
// Target browsers: iOS 15 (Safari 15.0), Android 10 (Chrome 74), vanilla versions when OS was shipped (most users have newer browser on Android)
// Change minIos/minAndroid to match your project's supported versions

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Backward compatibility scan: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Backward Compatibility");
await AssertCompatible(minIos: 15, minAndroid: 10);
await PrintCompatibilityReport(minIos: 15, minAndroid: 10);
