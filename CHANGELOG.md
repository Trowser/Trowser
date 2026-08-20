Trowser change log

1.0.12 2026-03-12
First release of a browser for exploratory testers:
WebView2 browser with scope limitation
Script Console with C# Roslyn
Record/Playback with C# scripting
Quicktests for fast, technical testing
Lightweight security testing including retire.js
Lightweight accessibility testing with axe-core (including viewport resize)
Lightweight browser compatibility scan
Lightweight performance testing with web-vitals
Lightweight robustness testing with gremlins.js and Smart Monkey
HTML validation with html-validate
Watch mode for continuous passive scanning
REST API and MCP for browser interaction
trowserkit for LLM context
AI Assistant with Chat, Economical and Full mode
Lightweight mocking, intercept, load and proxy routing 
Documentation

1.0.14 2026-03-19
Session logging with API recording, annotations, screenshots, and messages
Made read-only endpoints gate-free so they can be consumed without queueing
Added examples LLM_Prompt_PairTesting.txt and LLM_Prompt_Coach.txt
API improvements: rich editor support, API find/history/notes, visible:true as default
Improved endpoints for security discovery
Changed missing HSTS from High to Medium severity
Mocks and intercepts is remembered and can be toggled on/off

1.0.16 2026-03-26
Quicktest LinkCheck to find broken links
Quicktest GUIAudit to check on different styles, image optimization
Quicktest ThirdPartyInventory, important for GDPR compliance
Quicktest SecurityScan additions: Cookies and Mixed content 
Quicktest FullSiteHealth using all relevant audit endpoints
API Structured Text Extraction makes it easier for LLMs to proof-read
api/screenshot improvements
Export/Import för mocks and breakpoints
Added prompt examples for specification-based testing and LLM as developer

1.0.17 2026-04-02
Quicktest FaultInjection, more an experiment at the moment
api/fetch to make it easer for POST, PUT, PATCH etc.
Swagger documentation of REST API

1.0.19 2026-04-09
Quicktests GetAllPageStrings and ScreenReaderText
Configurable random test data with Ctrl+D
Testing inspiration with Ctrl+I
Right-click Run Script on selected element (ClickFrenzy example)

1.1.1 2026-04-16
Improvements to Trowser for security and robustness testing
Shadow mode for LLM real-time collaboration
Power mode to see hidden elements
API usage and LLM notes in journal

1.1.4 2026-04-23
Structured logging with api/journal
api/test-scenario and .trw files (with JSON schema) for AI/human hand-off
Support for client certificates
New Quicktest RequiredForbiddenStrings
Further security API enhancements, including ability to verify an exploit

1.1.6 2026-04-30
Remember API Key settings, and New button (user's responsibility)
Ability to start several Trowsers with standalone sessions
Addition to adress bar so any request parameter can be tampered
Added Trowser to User-Agent
Further security API enhancements, including peers and authorization enablers

1.1.7 2026-05-07
Better security quicktests for human testers
Further security API enhancements, including OIDC support and request smuggling.

1.1.8 2026-05-14
Added check box to toggle stream true or false for embedded AI
Further security API enhancements, including better API discovery and less false positives

1.1.9 2026-05-21
Further security API enhancements, including WAF, SSRF Scanner and attack chain engine

1.1.12 2026-05-28
Further security API enhancements, including proof-chaining and VPX support.

1.2.2 2026-06-04
Security orchestration for humans and LLMs with Trowser Twelve.

1.2.3 2026-06-11
Endpoint probe dialog with quicktest integration.

1.2.5 2026-06-25
Ctrl+B (and a Quicktest) to toggle screen curtain to simulate blind user
TabOrderCheck as API and Quicktest
Payloads available as randomized test data
Quicktest ResourceLeakProbe to find leaks of memory or resources
Pause and resume functions for scripts

1.3.1 2026-07-09 
Refactored and unified REST and MCP API
Support for sending requests and elements to AI Chat
Added support in Request Editor for QUERY, TRACE, CONNECT and M-SEARCH
SurpriseMe quicktest that runs a random quicktest, recommended in Watch Mode
Persistence of user settings between runs
GUI for peer sessions and BOLA testing

1.3.3 2026-07-23
Miscellaneous security API enhancements
Editable system prompt in AI Assistant
OpenRouter free as default AI integration (just add your API key)

1.3.4 2026-07-30
Markdown support in AI Assistant window and Show as HTML
Security API improvements; less false positives, better testing on LLMs
Ability for users to add their own quicktests to menu
Journal Panel to see notes from the session log
Experimental quicktests AttackForm, RequiredFieldProbe, ReloadStatePersistence, ErrorMessageMarathon and CopyPasteVsType
Richer bug capture abilities
Coverage lens that informs on functionality and quality characteristics

1.3.5 2026-08-13
Better support for frames, downloads, drag & drop
API support for environment/permission emulation, and HAR Export
3rd party updates for axe and web-vitals, added Nuclei, tltds, csp-evaluator
Better integration so AI assistant kan write C# scripts
Support for agent MCP connection with improved token efficiency

1.3.7 2026-08-20
Better support for Github Copilot as AI Assistant
Token efficiency improvements in MCP
!? button to get AI help when something interesting happens
Overhaul of the Journal Panel including edit and delete


All releases also include minor bug fixes and enhancements.
