#!/usr/bin/env python3
"""Independent checker. Imports nothing from the canary package, by design.

A leak check that reuses the filter's own regex inherits the filter's bugs and reports
clean on output that is not. So this file re-implements everything it needs:

  * its own credential patterns, not canary/redact.py's
  * its own canary recount, derived from the raw transcripts by a different method than
    canary/detect.py uses (flat serialisation and substring search, rather than a
    recursive walk over string leaves)
  * its own home-path rule
  * a NUL-byte scan written in Python, because `grep -P '\\x00'` is not available in
    every grep on this box and silently returned no matches while Python found the byte
    immediately, and because git and grep classify a file containing a NUL as binary and
    then skip it entirely, so one NUL blinds a text-based secret scan to a whole file

Usage:  python3 checker/independent_check.py [repo_root]
Exit 0 only if every check passes.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys

FAILURES: list[str] = []
NOTES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)


def note(msg: str) -> None:
    NOTES.append(msg)


# --------------------------------------------------------------------- tracked files

def tracked_files(root: pathlib.Path) -> list[pathlib.Path]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                         capture_output=True, text=True, check=True).stdout
    return [root / p for p in out.split("\0") if p]


def scanned_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Tracked files plus the generated results.

    results/ is gitignored because a transcript from a search server contains whatever was
    in that server's index, which here is the user's private notes. Gitignored is not the
    same as unexamined: the redaction that keeps credentials and home paths out of those
    files is exactly what needs checking, and checking only the tracked tree would leave
    the redactor's real output untested.
    """
    extra = []
    results = root / "results"
    if results.is_dir():
        extra = sorted(p for p in results.rglob("*") if p.is_file())
    return tracked_files(root) + extra


# ------------------------------------------------------------------- NUL byte scan

def scan_nul_bytes(paths: list[pathlib.Path]) -> None:
    """Read every tracked file as bytes and look for 0x00 directly.

    A file with a NUL is skipped by `grep -I` and `git grep -I`, so a credential inside
    one is invisible to the usual sweep. Finding the byte is therefore a finding in its
    own right, independent of whether that file also holds a secret.
    """
    offenders = []
    for p in paths:
        try:
            data = p.read_bytes()
        except OSError as exc:
            fail(f"NUL scan could not read {p}: {exc}")
            continue
        if b"\x00" in data:
            idx = data.index(b"\x00")
            offenders.append(f"{p} (first NUL at byte {idx})")
    if offenders:
        fail("tracked files contain a NUL byte, which makes grep-based secret scanning "
             "skip them entirely. Write the byte as the two-character escape \\0 instead:\n  "
             + "\n  ".join(offenders))
    else:
        note(f"NUL scan: read {len(paths)} files as bytes (tracked + generated results), none contained 0x00")


# ------------------------------------------------------------------- secret scan

# Written from the credential formats themselves, not copied from canary/redact.py.
# Case-sensitive wherever the real format is: an AKIA rule matched case-insensitively
# hits ordinary base64 and turns every embedded image into a false alarm.
SECRET_RULES: list[tuple[str, re.Pattern[bytes]]] = [
    ("github personal access token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("github fine-grained token", re.compile(rb"github_pat_[A-Za-z0-9_]{40,}")),
    ("slack token", re.compile(rb"xox[abprs]-[A-Za-z0-9-]{20,}")),
    ("stripe secret key", re.compile(rb"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("openai key", re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{40,}")),
    ("openrouter key", re.compile(rb"sk-or-v1-[0-9a-f]{40,}")),
    ("anthropic key", re.compile(rb"sk-ant-[A-Za-z0-9_-]{30,}")),
    ("google api key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("aws access key id", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("huggingface token", re.compile(rb"hf_[A-Za-z0-9]{34,}")),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}")),
    ("private key block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("discord bot token", re.compile(rb"[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}")),
]


def scan_secrets(paths: list[pathlib.Path]) -> None:
    hits = []
    for p in paths:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        for label, pat in SECRET_RULES:
            m = pat.search(data)
            if m:
                hits.append(f"{p}: {label} near byte {m.start()}")
    if hits:
        fail("credential-shaped strings in tracked files:\n  " + "\n  ".join(hits))
    else:
        note(f"secret scan: {len(SECRET_RULES)} credential formats checked against "
             f"{len(paths)} files, no match")


# ------------------------------------------------------------------- home path scan

HOME_PATH = re.compile(rb"/home/[a-z_][a-z0-9_-]{0,30}/")


def scan_home_paths(paths: list[pathlib.Path]) -> None:
    hits = []
    for p in paths:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        for m in HOME_PATH.finditer(data):
            line = data.count(b"\n", 0, m.start()) + 1
            hits.append(f"{p}:{line}: {m.group(0).decode('utf-8', 'replace')}")
    if hits:
        fail("absolute home paths in tracked files (private and unportable; use ~ or "
             "os.path.expanduser):\n  " + "\n  ".join(hits[:20]))
    else:
        note(f"home-path scan: no /home/<user>/ occurrence in {len(paths)} files")


# ------------------------------------------------------- independent canary recount

TOKEN = re.compile(r"MCPCANARY-[A-Z0-9]{2,12}-[0-9a-f]{8}")


def recount_from_raw(root: pathlib.Path) -> None:
    """Re-derive, per server, the set of canary tokens that came back in a response.

    Different method from the detector on purpose. The detector walks the parsed
    structure and records a JSON path; this flattens each response back to one string and
    searches it. If the two agree the reach claim rests on two independent derivations,
    and if they disagree the run fails rather than quietly preferring one.
    """
    _base = len(FAILURES)
    findings_path = root / "results" / "findings.json"
    raw_dir = root / "results" / "raw"
    if not findings_path.is_file():
        fail(f"{findings_path} is missing; run `python3 -m canary.run` first")
        return
    findings = json.loads(findings_path.read_text(encoding="utf-8"))

    claimed: dict[str, set[str]] = {}
    for s in findings["servers"]:
        for o in s["observations"]:
            if o["status"] == "REACHES_CONTEXT":
                claimed.setdefault(s["server"], set()).add(o["token"])

    observed: dict[str, set[str]] = {}
    all_tokens_seen: set[str] = set()
    if not raw_dir.is_dir():
        fail(f"{raw_dir} is missing; the recount has nothing to read")
        return
    for f in sorted(raw_dir.glob("*.json")):
        server = f.stem
        entries = json.loads(f.read_text(encoding="utf-8"))
        found: set[str] = set()
        for entry in entries:
            if entry.get("method") != "tools/call":
                continue
            flat = json.dumps(entry.get("response"), ensure_ascii=False)
            for tok in TOKEN.findall(flat):
                found.add(tok)
        observed[server] = found
        all_tokens_seen |= found

    servers = sorted(set(claimed) | set(observed))
    if not servers:
        fail("recount found no server with either a claim or a transcript")
    for server in servers:
        c, o = claimed.get(server, set()), observed.get(server, set())
        if c != o:
            fail(f"recount mismatch for {server}: findings claim REACHES_CONTEXT for "
                 f"{sorted(c)}, independent recount of the raw transcript found {sorted(o)}")
    if len(FAILURES) == _base:
        note(f"canary recount: {len(servers)} servers with transcripts, "
             f"{len(all_tokens_seen)} distinct tokens observed, claims match")

    # The negative-control token is generated with the same shape as every other and is
    # never planted. Seeing it in any transcript means a probe leaked it.
    absent_tokens = {o["token"] for s in findings["servers"] for o in s["observations"]
                     if o["vector"] == "ABSENT" and o["token"] != "(none)"}
    leaked = sorted(t for t in absent_tokens if t in all_tokens_seen)
    if leaked:
        fail(f"negative-control token(s) appeared in a real transcript: {leaked}")
    else:
        note(f"negative control: {len(absent_tokens)} unplanted token(s), none present in "
             "any transcript")

    # Counts in findings.json must equal a recount of its own observation list. Cheap, and
    # it catches a summary that drifted from the detail it claims to summarise.
    recount = {"REACHES_CONTEXT": 0, "NOT_REACHED": 0, "NOT_TESTED": 0}
    for s in findings["servers"]:
        for o in s["observations"]:
            if o["status"] not in recount:
                fail(f"unknown status {o['status']!r} in findings")
                continue
            recount[o["status"]] += 1
    if recount != findings["counts"]:
        fail(f"findings.json counts {findings['counts']} disagree with a recount {recount}")
    else:
        note(f"count recount: {recount}")


# ------------------------------------------------------------------- README numbers

def check_readme(root: pathlib.Path) -> None:
    """The README's numbers are claims. Re-derive them from findings.json, not from the
    report generator, so a bug in the generator cannot validate itself."""
    _base = len(FAILURES)
    readme = root / "README.md"
    if not readme.is_file():
        fail("README.md is missing")
        return
    text = readme.read_text(encoding="utf-8")
    if "## Status" not in text:
        fail("README.md has no ## Status section")
    findings_path = root / "results" / "findings.json"
    if not findings_path.is_file():
        return
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    probed = sorted(s["server"] for s in findings["servers"] if s["probed"])
    not_probed = sorted(s["server"] for s in findings["servers"] if not s["probed"])
    expectations = [
        (f"{len(probed)} probed", re.compile(rf"\b{len(probed)}\b\s+(?:server|MCP server)s?\s+probed")),
        (f"{len(not_probed)} not tested",
         re.compile(rf"\b{len(not_probed)}\b\s+(?:server|MCP server)s?\s+(?:were\s+)?(?:not tested|NOT TESTED)")),
    ]
    for label, pat in expectations:
        if not pat.search(text):
            fail(f"README.md does not state the current figure: expected a phrase matching "
                 f"{pat.pattern!r} ({label}). Regenerate with `python3 -m canary.report`.")
    for server in probed + not_probed:
        if server not in text:
            fail(f"README.md never mentions discovered server {server!r}")
    if len(FAILURES) == _base:
        note(f"README: names all {len(probed) + len(not_probed)} servers and states "
             f"{len(probed)} probed / {len(not_probed)} not tested")


# ------------------------------------------------------------------- docs page

def check_docs(root: pathlib.Path) -> None:
    _base = len(FAILURES)
    page = root / "docs" / "index.html"
    if not page.is_file():
        fail("docs/index.html is missing")
        return
    html = page.read_text(encoding="utf-8")
    required = [
        ("doctype", re.compile(r"^<!doctype html>", re.I)),
        ("charset meta", re.compile(r'<meta[^>]+charset=', re.I)),
        ("viewport meta", re.compile(r'<meta[^>]+name=["\']viewport["\']', re.I)),
        ("prefers-color-scheme dark", re.compile(r"prefers-color-scheme:\s*dark")),
        ("data-theme dark selector", re.compile(r':root\[data-theme=["\']?dark')),
        ("data-theme light selector", re.compile(r':root\[data-theme=["\']?light')),
    ]
    for label, pat in required:
        if not pat.search(html):
            fail(f"docs/index.html is missing {label}")
    if re.search(r"overflow-x\s*:\s*hidden", html):
        fail("docs/index.html uses overflow-x: hidden, which masks real overflow and makes "
             "the scrollWidth probe vacuous. Find the element that overflows instead.")
    if re.search(r'<(script|link|img)[^>]+(src|href)=["\']https?://', html, re.I):
        fail("docs/index.html references an external resource; the page must be self-contained")
    if len(FAILURES) == _base:
        note("docs/index.html: doctype, charset, viewport, both dark-mode mechanisms, "
             "self-contained, no overflow-x hedge")


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if not (root / ".git").exists():
        print(f"not a git repo: {root}", file=sys.stderr)
        return 2
    paths = scanned_files(root)
    if not paths:
        print("no files to scan", file=sys.stderr)
        return 2
    scan_nul_bytes(paths)
    scan_secrets(paths)
    scan_home_paths(paths)
    recount_from_raw(root)
    check_readme(root)
    check_docs(root)

    for n in NOTES:
        print(f"[ok  ] {n}")
    for f in FAILURES:
        print(f"[FAIL] {f}")
    print(f"\nindependent checker: {len(NOTES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
