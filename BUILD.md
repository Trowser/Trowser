# Building Trowser

Trowser is a Windows desktop app (WPF + WebView2) on **.NET 8**.

## Machine

- **Windows 10 or 11, x64.** The project targets `net8.0-windows` and `win-x64`.
- **.NET 8 SDK** — https://dotnet.microsoft.com/download/dotnet/8.0
  The Windows installer includes the desktop (WPF) targeting pack. Confirm with `dotnet --list-sdks` (an `8.0.x` entry).
- **WebView2 Runtime** (Evergreen), to launch the browser after a build. Current Windows 10/11 installs include it. If `Trowser.exe` reports that WebView2 is missing: https://developer.microsoft.com/microsoft-edge/webview2/
- **Network access on the first build**, so `dotnet` can restore NuGet packages (WebView2, Roslyn scripting, and the other packages in `src/Trowser/Trowser.csproj`).
- **PowerShell 7** (`pwsh`) — https://aka.ms/powershell. Windows ships Windows PowerShell 5.1, which can run the build and test scripts, but the API index generator (`scripts/generate-api-index.ps1`, also run by `scripts/test.ps1`) needs `pwsh`.
- **Python 3** (standard library only), only if you add or rename API routes: `scripts/regen-docs.ps1` uses it to sync the OpenAPI file.

Visual Studio 2022 is optional. Open `Trowser.sln` if you want the IDE; the commands below are enough.

## Build and run

From the repository root:

```powershell
dotnet build Trowser.sln
```

The solution builds the app and the unit-test project. Start:

```text
src\Trowser\bin\Debug\net8.0-windows\win-x64\Trowser.exe
```

Release build:

```powershell
dotnet build Trowser.sln -c Release
```

```text
src\Trowser\bin\Release\net8.0-windows\win-x64\Trowser.exe
```

The project is self-contained for `win-x64`, so the machine you run that exe on does not need a separate .NET runtime install. It does need the WebView2 Runtime.

## Tests

Unit tests live in `src\Trowser.Tests`:

```powershell
dotnet test Trowser.sln
```

CI (`.github/workflows/build.yml`) builds with warnings as errors, runs these tests, and checks that `trowserkit/trowser-api-index.md` is current. `.\scripts\test.ps1 -Level quick` runs the same build, unit tests, and index check locally; `-Level smoke` adds the browser tests CI runs. After an API change, `.\scripts\regen-docs.ps1` regenerates the index and the OpenAPI file.

After a build, the offline regression suite runs the exe against in-memory pages:

```powershell
.\tests\regression\run-regression.ps1
```

Details: `tests/regression/README.md`.

## Distribution

For a zip release to the public:
```powershell
build-zip.ps1 -Sign
```

Public releases are done on Thursdays. This is from the beginning of Trowser, and the purpose is to not rush things.
