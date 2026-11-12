# XS-Leaks calibration probes

Re-run after **WebView2 runtime upgrades** or when isolation-related regressions are suspected.

| Script | Purpose |
|--------|---------|
| `xsleak-browser-model.csx` | Records `browserModel` attacker origin and baseline scan |
| `xsleak-corp-mock.csx` | CORP on **mocked** victim; expect mitigated/downgraded `img-error` |
| `xsleak-coop-mock.csx` | COOP on mocked HTML; logs popup oracle + mitigation |
| `xsleak-isolation-http.csx` | CORP/COOP/COEP via **HttpListener** (real response headers, not WebResourceRequested) |

If mock and HttpListener calibrations diverge, prefer HttpListener results for COOP/CORP/COEP claims and document the gap in `browserModel.isolationEnforcement`.
