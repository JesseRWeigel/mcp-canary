"""Assertions over results/findings.json. Every positive one is paired with a control.

An assertion that only ever expects REACHES_CONTEXT cannot tell a working detector from
one that returns True for everything. So each claim that a channel carries a canary is
paired with a channel that must not, chosen so that a detector bug breaks the pair.

Run:  python3 -m canary.assertions [results/findings.json]
Exits non-zero if any assertion fails.
"""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass

from .detect import NOT_REACHED, NOT_TESTED, REACHES_CONTEXT, STATUSES

ROOT = pathlib.Path(__file__).resolve().parent.parent


@dataclass
class Assertion:
    name: str
    kind: str          # "positive" | "control" | "invariant"
    expected: str
    actual: str
    ok: bool
    detail: str = ""


def _obs(findings: dict, server: str, tool_prefix: str, vector: str):
    for s in findings["servers"]:
        if s["server"] != server:
            continue
        for o in s["observations"]:
            if o["vector"] == vector and o["tool"].startswith(tool_prefix):
                return o
    return None


def _status(findings: dict, server: str, tool_prefix: str, vector: str) -> str:
    o = _obs(findings, server, tool_prefix, vector)
    return o["status"] if o else "MISSING"


# (name, server, tool prefix, vector, expected status, kind)
PAIRS: list[tuple[str, str, str, str, str, str]] = [
    # 1. accessibility snapshot carries what the a11y tree exposes, and only that
    ("snapshot carries visible page text", "playwright", "browser_snapshot", "VISIBLE",
     REACHES_CONTEXT, "positive"),
    ("snapshot omits display:none text", "playwright", "browser_snapshot", "HIDDENCSS",
     NOT_REACHED, "control"),
    ("snapshot carries aria-label", "playwright", "browser_snapshot", "ARIA",
     REACHES_CONTEXT, "positive"),
    ("snapshot omits HTML comments", "playwright", "browser_snapshot", "COMMENT",
     NOT_REACHED, "control"),

    # 2. evaluate returns raw DOM, so it carries strictly more than the snapshot
    ("evaluate(outerHTML) carries HTML comment", "playwright", "browser_evaluate", "COMMENT",
     REACHES_CONTEXT, "positive"),
    ("evaluate(outerHTML) carries display:none text", "playwright", "browser_evaluate",
     "HIDDENCSS", REACHES_CONTEXT, "positive"),
    ("evaluate does not invent an unplanted token", "playwright", "browser_evaluate", "ABSENT",
     NOT_REACHED, "control"),

    # 3. console channel is separate from the page channel in both directions
    ("console messages carry console.log text", "playwright", "browser_console_messages",
     "CONSOLE", REACHES_CONTEXT, "positive"),
    ("console messages do not carry page body text", "playwright", "browser_console_messages",
     "VISIBLE", NOT_REACHED, "control"),

    # 4. network listing is a summary; the detail tool is what exposes headers
    ("network request detail carries a response header", "playwright",
     'browser_network_request({"index": 1}', "HDR", REACHES_CONTEXT, "positive"),
    ("network request listing does not carry headers", "playwright",
     "browser_network_requests", "HDR", NOT_REACHED, "control"),
    ("network request body part carries fetched JSON", "playwright",
     'browser_network_request({"index": 2', "JSONAPI", REACHES_CONTEXT, "positive"),

    # 5. navigate summarises: title inline, page body only as a file reference
    ("navigate carries the page title inline", "playwright", "browser_navigate", "TITLE",
     REACHES_CONTEXT, "positive"),
    ("navigate does not carry page body text inline", "playwright", "browser_navigate",
     "VISIBLE", NOT_REACHED, "control"),

    # 6. an image response is not a text channel
    ("screenshot does not carry page text", "playwright", "browser_take_screenshot", "VISIBLE",
     NOT_REACHED, "control"),

    # 7. stored content comes back verbatim
    ("mempalace returns stored drawer text verbatim", "mempalace", "mempalace_search", "STORED",
     REACHES_CONTEXT, "positive"),
    ("mempalace echoes the query argument", "mempalace", "mempalace_search", "ARGECHO",
     REACHES_CONTEXT, "positive"),
    ("mempalace does not return an unplanted token", "mempalace", "mempalace_search", "ABSENT",
     NOT_REACHED, "control"),

    # 8. claude-mem reflects its own argument
    ("claude-mem search echoes the query argument", "mcp-search", "search", "ARGECHO",
     REACHES_CONTEXT, "positive"),
    ("claude-mem does not return an unplanted token", "mcp-search", "search", "ABSENT",
     NOT_REACHED, "control"),
]

# Servers that must be reported NOT_TESTED with a reason, and never as passing.
MUST_BE_NOT_TESTED = ["context7", "discord", "firebase", "github", "greptile", "stripe",
                      "vercel", "huggingface-skills", "circleback", "context-mode",
                      "claude_ai_Gmail", "claude_ai_Google_Calendar", "claude_ai_Google_Drive"]


def check(findings: dict) -> list[Assertion]:
    out: list[Assertion] = []

    for name, server, tool, vector, expected, kind in PAIRS:
        actual = _status(findings, server, tool, vector)
        out.append(Assertion(name, kind, expected, actual, actual == expected,
                             detail=f"{server} / {tool} / {vector}"))

    # Invariant: the negative-control token is never reported anywhere, on any server.
    # If the detector matched loosely, or a probe leaked tokens between vectors, this is
    # the assertion that breaks.
    absent_reaches = [
        f"{s['server']}::{o['tool']}"
        for s in findings["servers"] for o in s["observations"]
        if o["vector"] == "ABSENT" and o["status"] == REACHES_CONTEXT
    ]
    out.append(Assertion("negative control token reaches nothing anywhere", "invariant",
                         "0 occurrences", f"{len(absent_reaches)} occurrences",
                         not absent_reaches, detail="; ".join(absent_reaches)))

    # Invariant: statuses come from the closed set. NOT_TESTED collapsing into one of the
    # other two is the failure mode this project is built to avoid.
    bad = [o["status"] for s in findings["servers"] for o in s["observations"]
           if o["status"] not in STATUSES]
    out.append(Assertion("every status is one of the three defined values", "invariant",
                         "0 unknown", f"{len(bad)} unknown", not bad, detail=str(sorted(set(bad)))))

    # Invariant: NOT_TESTED always carries a reason.
    unexplained = [f"{s['server']}::{o['vector']}" for s in findings["servers"]
                   for o in s["observations"]
                   if o["status"] == NOT_TESTED and not o["reason"].strip()]
    out.append(Assertion("every NOT_TESTED observation states a reason", "invariant",
                         "0 unexplained", f"{len(unexplained)} unexplained",
                         not unexplained, detail="; ".join(unexplained[:5])))

    # Invariant: servers we refuse to probe are reported NOT_TESTED, not silently passed.
    for server in MUST_BE_NOT_TESTED:
        rec = next((s for s in findings["servers"] if s["server"] == server), None)
        if rec is None:
            out.append(Assertion(f"{server} appears in findings", "invariant", "present",
                                 "missing", False))
            continue
        statuses = {o["status"] for o in rec["observations"]}
        ok = statuses == {NOT_TESTED} and bool(rec["reason"].strip())
        out.append(Assertion(f"{server} is reported NOT_TESTED with a reason", "invariant",
                             "{'NOT_TESTED'} + reason", f"{statuses or 'no observations'}", ok,
                             detail=rec["reason"][:90]))

    # Invariant: no probed server labelled its content as untrusted. Stated as an assertion
    # so that a server which starts labelling breaks this and gets noticed, rather than the
    # finding quietly ageing out of the README.
    labelled = sorted({f"{s['server']}::{o['tool']}" for s in findings["servers"]
                       for o in s["observations"] if o["markers"]})
    out.append(Assertion("no tool result carried an untrusted-content marker", "invariant",
                         "0 marked results", f"{len(labelled)} marked results",
                         not labelled, detail="; ".join(labelled[:5])))

    # Invariant: the run reported no hard failure (missing probe dependency, unknown server).
    hf = findings.get("hard_failures") or []
    out.append(Assertion("run reported no hard failures", "invariant", "0", str(len(hf)),
                         not hf, detail="; ".join(hf[:3])))

    return out


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    path = pathlib.Path(argv[0]) if argv else ROOT / "results" / "findings.json"
    findings = json.loads(path.read_text(encoding="utf-8"))
    results = check(findings)
    width = max(len(a.name) for a in results)
    failed = 0
    for a in results:
        mark = "ok  " if a.ok else "FAIL"
        print(f"[{mark}] {a.name:<{width}}  expected={a.expected:<16} actual={a.actual}")
        if not a.ok:
            failed += 1
            if a.detail:
                print(f"        {a.detail}")
    total = len(results)
    print(f"\n{total - failed}/{total} assertions passed "
          f"({sum(1 for a in results if a.kind == 'positive')} positive, "
          f"{sum(1 for a in results if a.kind == 'control')} controls, "
          f"{sum(1 for a in results if a.kind == 'invariant')} invariants)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
