#!/usr/bin/env python3
"""Break this suite on purpose, and prove the break was real before drawing a conclusion.

Three times in one session in this workspace an attack "passed" because the attack itself
did nothing: `KNOWN = [] or [...]` never emptied the list, a patch landed on a field the
rendered output did not read, and a value was set that the code path never consulted. Each
time the honest-looking conclusion was "the verify has a gap", and each time the verify was
fine.

So every scenario here must clear four bars before its verdict counts:

  1. the target check passes on the pristine copy
  2. the edit actually changed the bytes of a file
  3. the output of the target check is different afterwards
  4. the target check now exits non-zero

A scenario that fails bar 2 or 3 is reported as INCONCLUSIVE, never as evidence. Everything
happens in a throwaway copy of the working tree, so a scenario that dies half way cannot
leave the real project broken.

    python3 scripts/sabotage.py [--only NAME]
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parent.parent

RUN_AND_ASSERT = "python3 -m canary.run --out results && python3 -m canary.assertions results/findings.json"
RUN_AND_CHECK = "python3 -m canary.run --out results && python3 checker/independent_check.py ."
BROWSER = "python3 scripts/browser_check.py"
CHECKER = "python3 checker/independent_check.py ."


def edit(rel: str, old: str, new: str) -> Callable[[pathlib.Path], None]:
    def apply(root: pathlib.Path) -> None:
        p = root / rel
        text = p.read_text(encoding="utf-8")
        if old not in text:
            raise RuntimeError(f"sabotage anchor not found in {rel}; the patch would be a no-op")
        p.write_text(text.replace(old, new, 1), encoding="utf-8")
    return apply


def plant_nul_and_credential(root: pathlib.Path) -> None:
    """Write a tracked file holding a NUL byte and a credential-shaped string.

    Assembled from fragments at run time. A complete credential-shaped literal committed
    anywhere gets a GitHub push rejected, and that scan reads full history, so a later fix
    does not help. This file only ever exists inside a temporary copy.
    """
    blob = root / "canary" / "_sabotage_blob.py"
    token = "gh" + "p_" + ("Z" * 36)
    blob.write_bytes(b'SEP = "\x00"  # a real NUL, planted on purpose\nTOKEN = "'
                     + token.encode() + b'"\n')
    subprocess.run(["git", "-C", str(root), "add", "-f", str(blob.relative_to(root))],
                   check=True, capture_output=True)


@dataclass
class Scenario:
    name: str
    what: str            # what is being broken
    should_catch: str    # which check is expected to notice
    target: str          # shell command whose exit code is the verdict
    apply: Callable[[pathlib.Path], None]


SCENARIOS: list[Scenario] = [
    Scenario(
        name="detector-always-hits",
        what="canary/detect.py records a hit for every string in every result, so a canary "
             "appears to reach context even where it was never planted",
        should_catch="the negative controls and the ABSENT invariant in canary/assertions.py",
        target=RUN_AND_ASSERT,
        apply=edit("canary/detect.py",
                   "    hits: list[Hit] = []\n    for path, s in walk_strings(result):\n",
                   "    hits: list[Hit] = []\n    for path, s in walk_strings(result):\n"
                   "        hits.append(Hit(token=token, label=\"\", json_path=path,\n"
                   "                        field_kind=field_kind(path), context=\"SABOTAGE\"))\n"),
    ),
    Scenario(
        name="not-tested-collapsed",
        what="canary/probes.py reports a server that was never exercised as NOT_REACHED "
             "instead of NOT_TESTED, which is the failure that would make the whole "
             "exercise worthless",
        should_catch="the per-server NOT_TESTED invariants in canary/assertions.py",
        target=RUN_AND_ASSERT,
        apply=edit("canary/probes.py",
                   "provenance=\"remote_passthrough\", status=NOT_TESTED, reason=reason)",
                   "provenance=\"remote_passthrough\", status=\"NOT_REACHED\", reason=reason)"),
    ),
    Scenario(
        name="redactor-leaks-home-path",
        what="canary/redact.py stops replacing the home directory, so absolute "
             "/home/<user> paths from the real MCP config land in the written findings",
        should_catch="the home-path scan in checker/independent_check.py",
        target=RUN_AND_CHECK,
        apply=edit("canary/redact.py",
                   '        out = out.replace(HOME, "~")',
                   '        out = out  # sabotage: home directory left in place'),
    ),
    Scenario(
        name="page-script-does-not-parse",
        what="an unbalanced parenthesis in the inline script of docs/index.html, so the "
             "page renders as a static shell with no numbers in it",
        should_catch="scripts/browser_check.py, which asserts on what the script produced",
        target=BROWSER,
        apply=edit("docs/index.html",
                   "const DATA = ",
                   "const SABOTAGE = ((;\nconst DATA = "),
    ),
    Scenario(
        name="nul-byte-hides-a-credential",
        what="a tracked file containing a NUL byte and a credential-shaped token, the case "
             "where grep -I skips the file and a text sweep reports it clean",
        should_catch="the Python NUL scan and secret scan in checker/independent_check.py",
        target=CHECKER,
        apply=plant_nul_and_credential,
    ),
]


def copy_tree(dest: pathlib.Path) -> None:
    def ignore(_dir, names):
        return [n for n in names if n in ("__pycache__", ".pytest_cache")]
    shutil.copytree(ROOT, dest, ignore=ignore, symlinks=True)


def run(cmd: str, cwd: pathlib.Path) -> tuple[int, str]:
    # shell=True is deliberate and takes no external input. Every command executed here is
    # one of the module-level constants above, which need `&&` to express "run the suite
    # then judge it". Nothing from a file, a network response, or a tool result reaches it.
    p = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=900)
    return p.returncode, (p.stdout + p.stderr)


def run_scenario(s: Scenario) -> tuple[str, str]:
    """Return (verdict, detail). Verdict is CAUGHT, MISSED, or INCONCLUSIVE."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix=f"sabotage-{s.name}-"))
    work = tmp / "repo"
    try:
        copy_tree(work)
        before_rc, before_out = run(s.target, work)
        if before_rc != 0:
            return ("INCONCLUSIVE",
                    f"the target check already failed on the pristine copy (exit {before_rc}); "
                    f"nothing can be concluded from breaking it further.\n{before_out[-800:]}")

        digest_before = {p: (work / p).read_bytes()
                         for p in _files_of_interest(work)}
        try:
            s.apply(work)
        except Exception as exc:  # noqa: BLE001 - a patch that did not apply is the finding
            return ("INCONCLUSIVE", f"the sabotage did not apply: {exc}")
        changed = [p for p, b in digest_before.items() if (work / p).read_bytes() != b]
        new_files = [p for p in _files_of_interest(work) if p not in digest_before]
        if not changed and not new_files:
            return ("INCONCLUSIVE",
                    "the sabotage changed no file on disk, so it proves nothing. An attack "
                    "you have not verified is a no-op with a confident write-up attached.")

        after_rc, after_out = run(s.target, work)
        if after_out == before_out:
            return ("INCONCLUSIVE",
                    "the target check produced byte-identical output before and after, so the "
                    "sabotage never reached the code path under test")
        if after_rc == 0:
            return ("MISSED",
                    f"output changed but the check still passed. Files changed: {changed + new_files}\n"
                    f"{after_out[-800:]}")
        first = next((ln for ln in after_out.splitlines()
                      if "FAIL" in ln or "fail" in ln or "Error" in ln), after_out.splitlines()[-1]
                     if after_out.splitlines() else "")
        return ("CAUGHT",
                f"files changed: {sorted(changed + new_files)}; exit {before_rc} -> {after_rc}; "
                f"first failure line: {first.strip()[:160]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _files_of_interest(root: pathlib.Path) -> list[str]:
    out = []
    for pat in ("canary/*.py", "checker/*.py", "docs/*.html", "scripts/*.py"):
        for p in sorted(root.glob(pat)):
            out.append(str(p.relative_to(root)))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", default="")
    a = ap.parse_args(argv)
    chosen = [s for s in SCENARIOS if not a.only or s.name == a.only]
    if not chosen:
        print(f"no scenario named {a.only!r}", file=sys.stderr)
        return 2

    bad = 0
    for s in chosen:
        verdict, detail = run_scenario(s)
        mark = {"CAUGHT": "ok  ", "MISSED": "FAIL", "INCONCLUSIVE": "FAIL"}[verdict]
        print(f"[{mark}] {s.name}: {verdict}")
        print(f"        broke: {s.what}")
        print(f"        expected catcher: {s.should_catch}")
        print(f"        {detail}")
        if verdict != "CAUGHT":
            bad += 1
    print(f"\nsabotage: {len(chosen) - bad}/{len(chosen)} scenarios caught by the suite")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
