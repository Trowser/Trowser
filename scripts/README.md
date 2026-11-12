# Build Scripts

## Code signing (for releases)

Trowser uses a self-signed certificate so users can avoid Windows SmartScreen warnings by installing the certificate once.

### First-time setup

1. **Run as Administrator** (required for certificate creation):
   ```powershell
   .\scripts\create-cert.ps1
   ```
2. Enter a password when prompted. Store it securely — you'll need it for each signed build.
3. The certificate is saved to `.cert/` (gitignored). **Never commit the .pfx file.**

### Building a signed release

```powershell
.\build-zip.ps1 -Sign -Version 1.0
```

You'll be prompted for the certificate password. To avoid the prompt (e.g. in CI):

```powershell
.\build-zip.ps1 -Sign -CertPassword "your-password" -Version 1.0
```

The output ZIP will include:
- Signed `Trowser.exe`
- `Trowser.cer` — certificate for users to install
- `SMARTScreen.md` — instructions for users

### Manual signing only

To sign an existing build without repackaging:

```powershell
.\scripts\sign-exe.ps1 -ExePath "path\to\Trowser.exe" -Password "your-password"
```

### Requirements

- **Windows SDK** — `signtool.exe` must be available. Install via Visual Studio or [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/). Ensure "Windows SDK Signing Tools for Desktop Apps" is selected.

## Bundled WebView2 distribution

By default, `build-zip.ps1` creates one ZIP that requires WebView2 to be installed on the user's machine. To also produce a second ZIP with WebView2 bundled (for users who don't have it):

### One-time: Download the WebView2 runtime

```powershell
.\scripts\download-webview2-runtime.ps1
```

This downloads the latest WebView2 Fixed Version Runtime (~300MB) from NuGet and extracts it to `webview2-runtime/` (gitignored). Re-run to update to a newer version.

### Build

```powershell
.\build-zip.ps1 -Version 1.0
```

When `webview2-runtime/` exists, the script automatically produces two ZIPs:

| File | Description |
|------|-------------|
| `Trowser-1.0.zip` | Lightweight (~50MB). Requires WebView2 installed. |
| `Trowser-1.0-webview2.zip` | Standalone (~350MB). Includes WebView2, works offline. |

Trowser automatically detects the bundled runtime — if a `WebView2Runtime/` folder exists next to `Trowser.exe`, it uses that instead of the system-installed one.
