#!/usr/bin/env python3
"""Paste a real verify run into the README's Status section.

A Status section describing what the output would look like is worth nothing, so this runs
the verify script and pastes what it actually printed. Three passes, because the verify
script itself checks that the README carries a pasted result:

  1. bootstrap pass, with the README self-check stood down, so there is something to paste
  2. full pass, whose output is the one that lands in the README
  3. full pass again, confirming the README as pasted still verifies

Home directory paths are replaced with `~` in Python. The bash idiom `${var/#$HOME/~}`
tilde-expands its replacement, so the unescaped form substitutes $HOME for $HOME and
silently does nothing, and an absolute /home/<user> path in a committed README is both
private and unportable.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BEGIN = "<!-- BEGIN:VERIFY -->"
END = "<!-- END:VERIFY -->"
HOME = os.path.expanduser("~")


def run_verify(bootstrap: bool) -> tuple[int, str]:
    env = dict(os.environ)
    env["MCP_CANARY_BOOTSTRAP"] = "1" if bootstrap else "0"
    # stderr is merged into stdout rather than appended after it, so the pasted block
    # reads in the order the run actually happened. Concatenating the two streams puts
    # unittest's summary at the bottom, under the final verdict, which reads as though a
    # later step produced it.
    p = subprocess.run(["bash", "scripts/verify.sh"], cwd=ROOT, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                       timeout=1800)
    return p.returncode, p.stdout


def sanitise(text: str) -> str:
    out = text.replace(HOME, "~")
    # Temp directories carry a random suffix that would make the pasted block churn on
    # every run; the path itself is not the evidence.
    out = re.sub(r"/tmp/(sabotage|mcp-canary)-[A-Za-z0-9_.-]+", r"/tmp/\1-<tmp>", out)
    return out


def paste(text: str) -> None:
    readme = ROOT / "README.md"
    current = readme.read_text(encoding="utf-8")
    if BEGIN not in current or END not in current:
        sys.exit(f"README.md is missing the {BEGIN} / {END} markers")
    block = (f"{BEGIN}\n\nPasted from a real run of `bash scripts/verify.sh`:\n\n"
             f"```\n{sanitise(text).strip()}\n```\n\n{END}")
    head = current.split(BEGIN)[0]
    tail = current.split(END, 1)[1]
    readme.write_text(head + block + tail, encoding="utf-8")


def main() -> int:
    rc, out = run_verify(bootstrap=True)
    if rc != 0:
        print(out)
        print("verify failed on the bootstrap pass; nothing pasted", file=sys.stderr)
        return 1
    # Pass 1's output only exists so the README carries something for pass 2's self-check
    # to read. It is replaced immediately, so the block a reader sees is always a full run.
    paste(out)

    # Iterate to a fixed point. The README self-check reports what the *previous* paste
    # claimed, so the first full pass would enshrine the bootstrap pass's step count.
    # Repeat until the pasted output stops changing, then confirm once more.
    previous = ""
    for attempt in range(1, 5):
        rc, out = run_verify(bootstrap=False)
        if rc != 0:
            print(out)
            print(f"verify failed on full pass {attempt}; README left as it was",
                  file=sys.stderr)
            return 1
        paste(out)
        if sanitise(out) == previous:
            print(f"Status section refreshed from a passing run "
                  f"(stable after {attempt} passes)")
            return 0
        previous = sanitise(out)
    print("verify output never stabilised across four passes; the pasted block would be "
          "one generation stale", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
