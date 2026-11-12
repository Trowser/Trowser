# What Trowser is

Trowser is a testing browser for humans and AI, and in collaboration.
Main goals are to enable better software testing, and show examples of responsible AI usage.

It is a real Chromium browser (WebView2 on Windows) with built-in test tools and a versatile API. It is targeted for exploratory testing: learn the application, run quicktests, run specific tests, log your findings.

## What it is for

- A skilled tester that want to reach further and faster, with AI-in-the-loop.
- A new tester that want to learn testing by looking at functionality, usability, security, reliability etc.
- An AI agent driving that same browser, then handing findings back.
- A security tester who wants evidence from a live session

Use it only against systems you are authorized to test.

## What it is not

- A daily browser. The API can run script and alter the session. Safe mode and a navigation scope exist because the tool is powerful.
- The primary penetration testing tool, other specialized tool do most things better.
- Primary interface for test automation, other tools integrate better in a development team environment.

## How the product is shaped

One automation engine, several ways in:

| Way in | Entry |
|--------|--------|
| The window | Browse, Quicktests, script console, journal, request editor |
| REST | `http://localhost:6923` |
| MCP | `POST http://localhost:6923/mcp` |
| C# scripts | `Trowser.exe --run test.csx` |

Security work follows the same shape. Browse the flows that matter, then run playbooks with a scope and a safety mode (`passive`, `safe`, `active`, `aggressive`). Findings are meant to be triaged, proved, and exported. VPX, in `securitykit/VPX/`, is the format for carrying those findings between tools.
Trowser is a local program. There is no account, no telemetry, and no hosted scanner. Configuration, journals, and logs stay on the machine. The API binds to localhost.

Two habits are part of the design, not extras:

- Prefer a warning, or silence, to a confident false positive.
- Keep a trail: journal, decisions, recordings, and exported findings, so a person and an agent can pick up the same investigation.

## Where we are

Trowser is a working Windows application, in active use, with a public documentation set and a changelog, [CHANGELOG.md](CHANGELOG.md).

It supports most things you want to test on a web application, and users who start using it can't stop. It has few unique things, it is the combination of speed and versatility that make it stand out.
It is not easy to get started with, and the main reason is that testing is difficult, each application has unique things, and each application has unknown things that matter. 
The competitors for exploratory testing are:
* Standard browser with extensions - too little specialized tooling, scattered functionality and GUI.
* Playwright - LLMs can explore, and easier to swith to automated tests. No support for humans.
* Agentic solutions - in the sense that they want to remove humans from the loop.

Honest quality assessment 2026-10-24:
The main engine is solid, and Trowser can be used for any web testing.
Many quicktests are big time-savers, some are more experimental and can be improved.
Automation is more for reproducing and time-saving, and don't compete with standard automation. With broader usage it is expected that bugs and missing capabilities will be identified.
Journal needs more usage in different situations, and workflows can probably be improved.
Security is scattered, has been built while learning pentesting and have really strong and weaker parts.
AI integration works good enough and will improve when models get better. An LLM that already knows Trowser API would be something!


## Quality goals

The purpose of Trowser is to make it easier for humans and AI to do good testing, especially exploratory testing.
- **Capability**: Trowser API should support common actions a tester want to control in web services
- **Accuracy**: Trowser functionality should be reliable and rather warn than give false positives
- **Reliability**: Trowser should be stable and consistent in behaviour
- **Usability**: Trowser should be fast to use for testing experts; it will be difficult for new testers, but should enable learning opportunities
- **Charisma**: Trowser should not interfere with test object, and the tester should feel in control
- **Security**: Trowser is only intended for test services, but should not be vulnerable to escalated attacks on the local machine
- **Performance**: Trowser should be, and feel, as fast as other browsers and comparable test tools
- **Installability**: Distributable should be complete, and does not have to be officially signed
- **Compatibility**: Trowser should work on Windows 64-bit, including virtual machines and emulators
- **Supportability**: Trowser can log the user actions, and Trowser problems encountered
- **Testability**: Trowser should be usable for testing of all web services
- **Maintainability**: It should be easy to add features to Trowser and fix bugs
- **Portability**: Trowser does not support translation or porting to other environments


Design principles:
**Human in control** - The tester decides when to start, what to do, what to report, and how. AI-in-the-loop.
**LLM-first** - The APIs are from scratch designed towards LLM usage.
**Speed** - Offer quicktests for fast testing when that is possible. Offer leads over comprehensive scanning.
**Extendability** - Avoid building too much into the tool, rather have generic API:s providing freedom for humans and LLMs to use the latest and greates of skills and tools.
**one-size-does-not-fit-all** - No ambition to make a generic tool for all OS and situations. Trowser is Windows all the way, with C# scripting and only usable for web services.
**Humour** - Testers need some fun to survive, so the software name is important, the splash screen is intended to barely be seen, and the beautiful easter egg is pointless.

The direction that is visible in the product:
1. **Keep one engine.** A new capability should be reachable by a person in the window and by an agent over the API, unless there is a clear reason not to.
2. **Stay in the exploratory loop.** Tools should make the next question easier: what just happened, what is worth keeping, what should a human decide.
3. **Security testing with evidence.** Playbooks and scanners are useful when a tester can tell a real finding from noise, and can show the proof. VPX is how findings leave the session without losing that structure.
4. **Handoff between human and agent.** Journal, decisions, recordings, and exports are the product, as much as any single scanner.
5. **Accuracy over volume.** New checks should state what they actually observed.
6. **Remain local.** No telemetry. The trust boundary stays on the machine: localhost, an API key, and safe mode.


## Where we are heading

There are (at least) seven different paths to take, not mutually exclusive:
- Human tester tool (test idea collection, more quicktests and features that help)
- LLM tester tool (API enhancements, abilities to integrate in other workflows)
- Security testing (endless possibilities, already strong for human/AI collaboration)
- API/Scripting additions, advanced .trw files, Selenium/Playwright import/export
- User Experience, but probably wait for LLMs get a lot better at this
- Learning platform, we could embed a school of testing with planted bugs and walkthrough of how to think
- Unexpected feedback from community

Continuous bug fixing and smaller enhancements is also important.
An active community sharing their quicktests would be wonderful.


## For contributors

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Read [trowserkit/SECURITY.md](trowserkit/SECURITY.md) before treating the API as a sandbox. It is a full-trust local tool with a localhost lock and a key, not a confinement boundary.
