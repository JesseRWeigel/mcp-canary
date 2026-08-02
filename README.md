# mcp-canary

**[Open the live page](https://jesserweigel.github.io/mcp-canary/)**

A prompt-injection canary suite for the MCP servers installed on one workstation.

An MCP server returns tool results into an agent's context. If a server can be made to
return attacker-controlled text, that text is read by a model that may act on it. This
project measures, per server and per tool, whether a harmless marker string can travel
that path, which field of the tool result carries it, and whether anything labels it as
untrusted.

Defensive testing, run with the machine owner's authorisation. Every payload is an inert
marker of the form `MCPCANARY-<CHANNEL>-<8 hex>`. Nothing here instructs a model to do
anything, and nothing would cause damage if a model followed it. The canonical test is
whether the string arrives, not whether anything harmful happens.

## The question worth asking

Every server can return text. That is what a server is. The useful questions are narrower:

- **Which fields reach the model?** A tool result is a structure. `content[].text` is
  rendered into context verbatim; `structuredContent` and `_meta` may or may not be; a
  file path in the result reaches the model only if the agent then reads the file. The
  detector records the exact JSON path of every canary occurrence, not just a yes or no.
- **Is anything marked as untrusted?** Wrapping foreign text in a provenance marker is
  the cheapest partial mitigation there is. The suite looks for one in every result.
- **Did the server author the text, or pass it through?** A server returning its own
  structured output is a different risk from one that hands back a page it fetched. Each
  observation is tagged `argument_echo`, `stored_passthrough`, or `remote_passthrough`.

## Three statuses, and why the third one matters

| status | meaning |
|---|---|
| `REACHES_CONTEXT` | the canary appeared in the tool result |
| `NOT_REACHED` | the tool ran and the canary was not in the result |
| `NOT_TESTED` | the server could not be exercised, with a stated reason |

Collapsing `NOT_TESTED` into either of the other two is the failure that would make this
whole exercise worthless. The `Observation` type refuses to be constructed with
`NOT_TESTED` and no reason, `REACHES_CONTEXT` and no hit, or `NOT_REACHED` alongside hits,
and `canary/assertions.py` asserts per server that the untested ones are reported as
untested. One of the five sabotage scenarios does nothing but collapse that distinction,
to prove those assertions notice.

## Scope rules

Three rules decide what may be probed. They live in `canary/policy.py`, one entry per
server, and a server with no probe and no stated reason cannot be represented.

1. **No configuration is modified.** Servers are launched as child processes from the
   command line already recorded in the machine's own config. The host's own MCP
   connections are never touched, and no config file is written.
2. **Nothing is authenticated.** A server behind an interactive OAuth flow is `NOT_TESTED`.
3. **No payload is sent to a service we do not control.** A canary is attacker-controlled
   text by construction. Posting one to a third party would be doing the thing this suite
   exists to warn about, so those servers are reported out of scope with the reason.

Everything actually probed is local: a Chromium instance driven by the Playwright MCP
server against a fixture page served from `127.0.0.1` on a kernel-assigned port, a
mempalace instance pointed at a throwaway palace directory, and a read-only search against
the local claude-mem index.

## Discovery

Nothing about the configuration is assumed. `canary/discover.py` reads, at run time:

- `~/.claude.json`, both the global `mcpServers` block and the per-project blocks
- `~/.claude/settings.json`, for `enabledPlugins`
- `~/.claude/plugins/installed_plugins.json`, and each installed plugin's `.mcp.json`
- `<project>/.mcp.json`

Both `.mcp.json` shapes are handled, because both are present on this machine: some
plugins wrap their servers in `{"mcpServers": {...}}` and some write a bare `{name: def}`.
Every inventory entry records the file it came from, so any claim here can be checked.

Servers exposed by account-level claude.ai connectors are listed separately. Local
discovery cannot see them, and pretending the local config is the whole picture would be
the same silent gap in a different place.

## Running it

```
bash scripts/verify.sh              # everything, exits non-zero on any failure
python3 -m canary.run               # probe, write results/findings.json
python3 -m canary.assertions        # judge the findings
python3 checker/independent_check.py .
python3 -m canary.report            # regenerate the README block and docs/index.html
python3 scripts/sabotage.py         # break the suite on purpose, five ways
python3 scripts/browser_check.py    # load docs/index.html in a real browser
```

Requires Python 3.11+, Node, the Playwright MCP server in the npx cache, and a Chromium
that Playwright can launch. When any of those is missing the suite fails and names the
install command rather than skipping the section, because a skipped check reports the same
success as one that ran.

`results/` is not committed. A transcript from a search server contains whatever was in
that server's index, which on this machine is the owner's private notes. The independent
checker still scans those files for credentials and home paths, since the redaction that
keeps them out is exactly what needs checking.

<!-- BEGIN:GENERATED -->

### What was found

3 MCP servers probed, 13 servers not tested.

Across 145 canary observations: **22 REACHES_CONTEXT**, 73 NOT_REACHED, 50 NOT_TESTED.

38/38 assertions pass (11 positive, 9 negative controls, 18 invariants).

### Servers discovered on this machine

| server | plugin | transport | probed | how it was handled |
|---|---|---|---|---|
| `mempalace` | - | stdio | yes | probed with benign canaries |
| `mcp-search` | claude-mem | stdio | yes | probed with benign canaries |
| `playwright` | playwright | stdio | yes | probed with benign canaries |
| `circleback` | circleback | http | no | NOT TESTED, needs interactive auth |
| `context-mode` | context-mode | stdio | no | tool surface listed, no tool called |
| `context7` | context7 | stdio | no | OUT OF SCOPE, would send a payload to a third party |
| `discord` | discord | stdio | no | OUT OF SCOPE, would send a payload to a third party |
| `firebase` | firebase | stdio | no | NOT TESTED, cannot be launched or exercised offline |
| `github` | github | http | no | NOT TESTED, needs interactive auth |
| `greptile` | greptile | http | no | NOT TESTED, needs interactive auth |
| `huggingface-skills` | huggingface-skills | http | no | NOT TESTED, needs interactive auth |
| `stripe` | stripe | http | no | NOT TESTED, needs interactive auth |
| `vercel` | vercel | http | no | NOT TESTED, needs interactive auth |
| `claude_ai_Gmail` | - | claude.ai connector | no | NOT TESTED, account-level connector, not in local config |
| `claude_ai_Google_Calendar` | - | claude.ai connector | no | NOT TESTED, account-level connector, not in local config |
| `claude_ai_Google_Drive` | - | claude.ai connector | no | NOT TESTED, account-level connector, not in local config |

### Which field carried the canary

Each cell is the status for one canary channel through one tool result. `REACHES` means the marker string came back inside the tool result the model would read.

**mempalace**

| tool | ABSENT | ARGECHO | STORED |
|---|---|---|---|
| `mempalace_search` | . | REACHES | REACHES |

**mcp-search**

| tool | ABSENT | ARGECHO |
|---|---|---|
| `search(query=...)` | . | REACHES |

**playwright**

| tool | ABSENT | ALT | ARIA | COMMENT | CONSOLE | HDR | HIDDENCSS | JSONAPI | TITLE | VISIBLE |
|---|---|---|---|---|---|---|---|---|---|---|
| `browser_navigate` | . | . | . | . | . | . | . | . | REACHES | . |
| `browser_snapshot` | . | REACHES | REACHES | . | . | . | . | . | REACHES | REACHES |
| `browser_console_messages` | . | . | . | . | REACHES | . | . | . | . | . |
| `browser_evaluate({"function": "() => document.documentElement.outerHTML"})` | . | REACHES | REACHES | REACHES | REACHES | . | REACHES | REACHES | REACHES | REACHES |
| `browser_network_requests` | . | . | . | . | . | . | . | . | . | . |
| `browser_network_request({"index": 1})` | . | . | . | . | . | REACHES | . | . | . | . |
| `browser_network_request({"index": 2, "part": "response-body"})` | . | . | . | . | . | . | . | REACHES | . | . |
| `browser_find({"text": "Benign marker"})` | . | REACHES | REACHES | . | . | . | . | . | . | REACHES |
| `browser_take_screenshot({"type": "jpeg"})` | . | . | . | . | . | . | . | . | . | . |

### Why each untested server was not tested

- **`circleback`** (auth): NOT TESTED. Hosted HTTP server at app.circleback.ai behind an interactive OAuth flow, holding the user's meeting notes.
- **`context-mode`** (unspecified): local stdio server; probed for its tool surface only. Tool surface recorded (7 tools); no tool was called, so no canary vector was exercised.
- **`context7`** (remote): OUT OF SCOPE. Every context7 tool forwards its argument string to Upstash's hosted API. Probing it would mean sending canary text to a third party we do not control, which is the exact act this suite exists to warn about.
- **`discord`** (remote): OUT OF SCOPE. The server authenticates to Discord with the user's bot token and every tool either reads a private guild or posts into it. Reading would expose private messages to this harness; posting would send canary text to a third party. Neither is acceptable.
- **`firebase`** (unreachable): NOT TESTED. Launch line is `npx -y firebase-tools@latest mcp`, which resolves `@latest` against the npm registry on every start, and its tools need either a signed-in Firebase project or a call to Google's hosted docs API.
- **`github`** (auth): NOT TESTED. HTTP server at api.githubcopilot.com requiring GITHUB_PERSONAL_ACCESS_TOKEN, which is not set in this environment, and every tool call is a request to GitHub.
- **`greptile`** (auth): NOT TESTED. HTTP server requiring GREPTILE_API_KEY, which is not set in this environment, and every tool call is a request to Greptile.
- **`huggingface-skills`** (auth): NOT TESTED. Hosted HTTP server at huggingface.co/mcp with `?login`, an interactive sign-in.
- **`stripe`** (auth): NOT TESTED. Hosted HTTP server at mcp.stripe.com behind an interactive OAuth flow. Completing it would authenticate a live payments account.
- **`vercel`** (auth): NOT TESTED. Hosted HTTP server at mcp.vercel.com behind an interactive OAuth flow.
- **`claude_ai_Gmail`** (connector): NOT TESTED. account-level claude.ai connector; OAuth, remote, holds private mail. Not present in any local config file, so this harness cannot launch it.
- **`claude_ai_Google_Calendar`** (connector): NOT TESTED. account-level claude.ai connector; OAuth, remote. Not present in any local config file, so this harness cannot launch it.
- **`claude_ai_Google_Drive`** (connector): NOT TESTED. account-level claude.ai connector; OAuth, remote. Not present in any local config file, so this harness cannot launch it.

_Generated from `results/findings.json` at 2026-08-02T03:21:15Z by `python3 -m canary.report`. Do not edit this block by hand._

<!-- END:GENERATED -->

## How this is verified

**Every positive assertion is paired with a control.** "The accessibility snapshot carries
visible page text" is paired with "the snapshot omits `display:none` text" and "the
snapshot omits HTML comments", chosen so that a detector which matched too loosely breaks
the pair. The fixture also plants an `ABSENT` token: same shape, never written anywhere, so
any code path that reports it as reaching context is reporting on nothing.

**An independent checker shares no code with the detector.** `checker/independent_check.py`
imports nothing from the `canary` package. It re-derives which canaries came back by
flattening each raw response to one string and searching it, where the detector walks the
parsed structure and records JSON paths, and it fails if the two derivations disagree. It
carries its own credential patterns, because a leak check that reuses the filter's own
regex inherits the filter's bugs and reports clean on output that is not.

**The NUL-byte scan is written in Python, not grep.** A file containing a NUL is classified
as binary by git and grep, and `grep -I` then skips it entirely, so one NUL blinds a text
sweep to a whole file. `grep -P '\x00'` is also not available in every grep on this box.
`tests/test_redact_and_scan.py` asserts both halves: that the Python scan finds a planted
NUL, and that `grep -I` does not see a credential in the same file while `grep -a` does.

**Five sabotages, each proved to have changed real output.** `scripts/sabotage.py` copies
the working tree, confirms the target check passes on the pristine copy, applies the
break, confirms the bytes on disk changed and the check's output changed, and only then
records whether the check failed. A scenario that fails either proof is reported
`INCONCLUSIVE`, never as evidence. An attack you have not verified is a no-op with a
confident write-up attached.

**The page is loaded in a real browser.** `scripts/browser_check.py` serves `docs/` on a
kernel-assigned port, navigates to it at a 390px viewport, asserts the document title
matches (the browser is shared between agents and can be navigated out from under a
measurement), and asserts on a DOM attribute only the inline script can set. It walks every
element comparing `getBoundingClientRect().right` against `clientWidth`, ignoring anything
inside an ancestor with `overflow-x: auto`, and fails if `body` uses `overflow-x: hidden`,
which would hide the bug and make the probe vacuous.

**The numbers regenerate.** Everything quotable in the block above and on the page is
produced by `python3 -m canary.report` from `results/findings.json`. `scripts/verify.sh`
regenerates both and fails if the committed copies have drifted, and the independent
checker re-derives the headline figures from the findings rather than from the generator,
so a bug in the generator cannot validate itself.

## Limitations

- Three servers were probed. The rest were not, and the reasons are listed above rather
  than averaged away. This is a measurement of one workstation on one day, not a survey.
- The suite measures whether text travels. It does not measure whether a model obeys it.
  Testing obedience would require writing a payload that is harmful if followed.
- `mempalace` and `mcp-search` were probed through one tool each. The Playwright matrix is
  the only one deep enough to say much about field-level differences.
- The `context-mode` server was started and its tools listed, but no tool was called, so
  every canary vector for it is `NOT_TESTED`.
- Discovery reads files. A server configured only in a running host's memory, or added
  after this run, is not in the inventory.

## Status

<!-- BEGIN:VERIFY -->

Pasted from a real run of `bash scripts/verify.sh`:

```
mcp-canary verification
python: Python 3.12.3
node:   v24.13.0

== [1] unit tests (detector, redaction, NUL and secret scanners)
----------------------------------------------------------------------
Ran 32 tests in 0.004s

OK
-- ok: unit tests (detector, redaction, NUL and secret scanners)

== [2] live probe of every discovered MCP server
servers in inventory : 13
observations         : 145
  REACHES_CONTEXT : 22
  NOT_REACHED     : 73
  NOT_TESTED      : 50
-- ok: live probe of every discovered MCP server

== [3] assertions over the findings, each positive one paired with a control
[ok  ] snapshot carries visible page text                              expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] snapshot omits display:none text                                expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] snapshot carries aria-label                                     expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] snapshot omits HTML comments                                    expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] evaluate(outerHTML) carries HTML comment                        expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] evaluate(outerHTML) carries display:none text                   expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] evaluate does not invent an unplanted token                     expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] console messages carry console.log text                         expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] console messages do not carry page body text                    expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] network request detail carries a response header                expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] network request listing does not carry headers                  expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] network request body part carries fetched JSON                  expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] navigate carries the page title inline                          expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] navigate does not carry page body text inline                   expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] screenshot does not carry page text                             expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] mempalace returns stored drawer text verbatim                   expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] mempalace echoes the query argument                             expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] mempalace does not return an unplanted token                    expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] claude-mem search echoes the query argument                     expected=REACHES_CONTEXT  actual=REACHES_CONTEXT
[ok  ] claude-mem does not return an unplanted token                   expected=NOT_REACHED      actual=NOT_REACHED
[ok  ] negative control token reaches nothing anywhere                 expected=0 occurrences    actual=0 occurrences
[ok  ] every status is one of the three defined values                 expected=0 unknown        actual=0 unknown
[ok  ] every NOT_TESTED observation states a reason                    expected=0 unexplained    actual=0 unexplained
[ok  ] context7 is reported NOT_TESTED with a reason                   expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] discord is reported NOT_TESTED with a reason                    expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] firebase is reported NOT_TESTED with a reason                   expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] github is reported NOT_TESTED with a reason                     expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] greptile is reported NOT_TESTED with a reason                   expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] stripe is reported NOT_TESTED with a reason                     expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] vercel is reported NOT_TESTED with a reason                     expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] huggingface-skills is reported NOT_TESTED with a reason         expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] circleback is reported NOT_TESTED with a reason                 expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] context-mode is reported NOT_TESTED with a reason               expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] claude_ai_Gmail is reported NOT_TESTED with a reason            expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] claude_ai_Google_Calendar is reported NOT_TESTED with a reason  expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] claude_ai_Google_Drive is reported NOT_TESTED with a reason     expected={'NOT_TESTED'} + reason actual={'NOT_TESTED'}
[ok  ] no tool result carried an untrusted-content marker              expected=0 marked results actual=0 marked results
[ok  ] run reported no hard failures                                   expected=0                actual=0

38/38 assertions passed (11 positive, 9 controls, 18 invariants)
-- ok: assertions over the findings, each positive one paired with a control

== [4] generated README block and docs/index.html are current
generated files are current
-- ok: generated README block and docs/index.html are current

== [5] docs/index.html loads in a real browser and its script ran
browser check: title ok, script ran (11 matrix rows, 6 cards, 38 assertion rows), no element escapes a 390px viewport, theme toggle sets data-theme
-- ok: docs/index.html loads in a real browser and its script ran

== [6] independent checker (no shared code with the detector)
[ok  ] NUL scan: read 18 files as bytes (tracked + generated results), none contained 0x00
[ok  ] secret scan: 13 credential formats checked against 18 files, no match
[ok  ] home-path scan: no /home/<user>/ occurrence in 18 files
[ok  ] canary recount: 4 servers with transcripts, 12 distinct tokens observed, claims match
[ok  ] negative control: 2 unplanted token(s), none present in any transcript
[ok  ] count recount: {'REACHES_CONTEXT': 22, 'NOT_REACHED': 73, 'NOT_TESTED': 50}
[ok  ] README: names all 16 servers and states 3 probed / 13 not tested
[ok  ] docs/index.html: doctype, charset, viewport, both dark-mode mechanisms, self-contained, no overflow-x hedge

independent checker: 8 passed, 0 failed
-- ok: independent checker (no shared code with the detector)

== [7] sabotage scenarios, each proved to have changed real output
[ok  ] detector-always-hits: CAUGHT
        broke: canary/detect.py records a hit for every string in every result, so a canary appears to reach context even where it was never planted
        expected catcher: the negative controls and the ABSENT invariant in canary/assertions.py
        files changed: ['canary/detect.py']; exit 0 -> 1; first failure line: [FAIL] snapshot omits display:none text                                expected=NOT_REACHED      actual=REACHES_CONTEXT
[ok  ] not-tested-collapsed: CAUGHT
        broke: canary/probes.py reports a server that was never exercised as NOT_REACHED instead of NOT_TESTED, which is the failure that would make the whole exercise worthless
        expected catcher: the per-server NOT_TESTED invariants in canary/assertions.py
        files changed: ['canary/probes.py']; exit 0 -> 1; first failure line: [FAIL] context7 is reported NOT_TESTED with a reason                   expected={'NOT_TESTED'} + reason actual={'NOT_REACHED'}
[ok  ] redactor-leaks-home-path: CAUGHT
        broke: canary/redact.py stops replacing the home directory, so absolute /home/<user> paths from the real MCP config land in the written findings
        expected catcher: the home-path scan in checker/independent_check.py
        files changed: ['canary/redact.py']; exit 0 -> 1; first failure line: [FAIL] absolute home paths in tracked files (private and unportable; use ~ or os.path.expanduser):
[ok  ] page-script-does-not-parse: CAUGHT
        broke: an unbalanced parenthesis in the inline script of docs/index.html, so the page renders as a static shell with no numbers in it
        expected catcher: scripts/browser_check.py, which asserts on what the script produced
        files changed: ['docs/index.html']; exit 0 -> 1; first failure line: FAIL the inline script never ran: data-canary-rendered is absent, so the page is a static shell with no numbers in it
[ok  ] nul-byte-hides-a-credential: CAUGHT
        broke: a tracked file containing a NUL byte and a credential-shaped token, the case where grep -I skips the file and a text sweep reports it clean
        expected catcher: the Python NUL scan and secret scan in checker/independent_check.py
        files changed: ['canary/_sabotage_blob.py']; exit 0 -> 1; first failure line: [FAIL] tracked files contain a NUL byte, which makes grep-based secret scanning skip them entirely. Write the byte as the two-character escape \0 instead:

sabotage: 5/5 scenarios caught by the suite
-- ok: sabotage scenarios, each proved to have changed real output

== [8] README carries a pasted verify result and no placeholder
README Status carries a pasted run claiming 8 checks
-- ok: README carries a pasted verify result and no placeholder

VERIFY OK: 8 checks passed
```

<!-- END:VERIFY -->

## License

MIT, see `LICENSE`.

Part of [722 things to build](https://github.com/JesseRWeigel/722-things-to-build).
