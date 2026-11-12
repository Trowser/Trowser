# XS-Leaks leak-matrix calibration (Phase 2)

This folder will hold versioned calibration fixtures: mocked victim response differences
(status, redirects, framing headers, body length, and so on) crossed with inclusion methods
in WebView2. The technique planner will read the matrix instead of hand-written ranking rules.

Until the matrix exists, use `observeMode: true` on `POST /api/security/xs-leaks` for
AutoLeak-style observation vectors in `details.observe`.
