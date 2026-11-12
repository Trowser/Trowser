# Trowser

Trowser is a Windows browser for testing web applications. It is a real [WebView2](https://developer.microsoft.com/microsoft-edge/webview2/) browser with automation built in, so a person and an agent can explore the same session: click through the product, run a check, and keep the evidence.

It is an exploratory tester's companion. Accessibility, performance, robustness, and security checks sit next to the page, along with C# scripting, a localhost REST API, and [MCP](https://modelcontextprotocol.io/).

Project site: [trowser.github.io](https://trowser.github.io/) · Issues: [github.com/Trowser/Trowser/issues](https://github.com/Trowser/Trowser/issues)

## Start here

| You want to… | Read |
|--------------|------|
| Understand what Trowser is, and where it is going | [VISION.md](VISION.md) |
| Build and run it | [BUILD.md](BUILD.md) |
| Find a guide (API, scripting, security testing) | [DOCUMENTATION.md](DOCUMENTATION.md) |
| Use the product | [trowserkit/README.md](trowserkit/README.md) |
| Contribute | [CONTRIBUTING.md](CONTRIBUTING.md), then [ARCHITECTURE.md](ARCHITECTURE.md) |
| Point an AI coding agent at the code | [AGENTS.md](AGENTS.md) |
| Report a vulnerability in Trowser itself | [SECURITY.md](SECURITY.md) |

Trowser runs on Windows 10 or 11 (x64) with the .NET 8 SDK. Current Windows installs include the WebView2 Runtime.

```powershell
dotnet build Trowser.sln
```

The executable is `src\Trowser\bin\Debug\net8.0-windows\win-x64\Trowser.exe`. Details, tests, and the release build are in [BUILD.md](BUILD.md).

## What you are trusting

Trowser is a local testing tool. It does not collect telemetry. The API listens on localhost and requires a bearer key (except `GET /api/ping`). Use it on systems you are allowed to test. The threat model is [trowserkit/SECURITY.md](trowserkit/SECURITY.md).

Settings and the diagnostic log stay under `%APPDATA%\Trowser\`.

## License

Copyright (c) 2026 Trowser contributors.

Trowser is released under the [MIT License](LICENSE).

Third-party libraries bundled with the app are listed in [licenses/THIRD_PARTY_LICENSES.md](licenses/THIRD_PARTY_LICENSES.md).

## Contact

Rikard Edgren — [thetesteye.com](https://thetesteye.com/), or rikard.edgren@thetesteye.com.
Credits for the people who shaped the work are in [trowserkit/README.md](trowserkit/README.md).
