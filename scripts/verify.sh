#!/usr/bin/env bash
# Full verification. Exits non-zero on any failure.
#
# Nothing is skipped. When an optional dependency is missing the step that needed it
# fails and names the install command, because a skipped check reports the same success
# as one that ran, and "could not verify" is not "verified".
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
export PYTHONDONTWRITEBYTECODE=1

STEPS=0
FAILED=0

step() {
  local label="$1"; shift
  STEPS=$((STEPS + 1))
  echo
  echo "== [$STEPS] $label"
  if "$@"; then
    echo "-- ok: $label"
  else
    echo "-- FAILED: $label"
    FAILED=$((FAILED + 1))
  fi
}

echo "mcp-canary verification"
echo "python: $(python3 --version 2>&1)"
echo "node:   $(node --version 2>&1 || echo 'MISSING - install Node 20+')"

step "unit tests (detector, redaction, NUL and secret scanners)" \
  python3 -m unittest discover -s tests -q

step "live probe of every discovered MCP server" \
  python3 -m canary.run

step "assertions over the findings, each positive one paired with a control" \
  python3 -m canary.assertions results/findings.json

step "generated README block and docs/index.html are current" \
  python3 -m canary.report --check

step "docs/index.html loads in a real browser and its script ran" \
  python3 scripts/browser_check.py

step "independent checker (no shared code with the detector)" \
  python3 checker/independent_check.py "$ROOT"

step "sabotage scenarios, each proved to have changed real output" \
  python3 scripts/sabotage.py

# The README is a claim like any other. Twelve verify scripts in this workspace pass
# without ever looking at theirs, so a project can report green while its README still
# says TODO.
readme_self_check() {
  python3 - "$ROOT" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
text = (root / "README.md").read_text(encoding="utf-8")
problems = []
if "## Status" not in text:
    problems.append("no ## Status section")
body = text.split("## Status", 1)[1] if "## Status" in text else ""
if "VERIFY OK:" not in body:
    problems.append("the Status section holds no pasted 'VERIFY OK:' line from a real run; "
                    "regenerate it with `python3 scripts/refresh_status.py`")
if re.search(r"TODO|FIXME|replace with a real", text):
    problems.append("README still contains a placeholder")
if problems:
    for p in problems:
        print(f"FAIL {p}")
    sys.exit(1)
m = re.search(r"VERIFY OK: (\d+) checks passed", body)
print(f"README Status carries a pasted run claiming {m.group(1)} checks" if m
      else "README Status carries a pasted VERIFY OK line")
PY
}

if [ "${MCP_CANARY_BOOTSTRAP:-0}" = "1" ]; then
  echo
  echo "== [skipped] README self-check (bootstrap run; refresh_status.py will paste this output)"
else
  step "README carries a pasted verify result and no placeholder" readme_self_check
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "VERIFY FAILED: $FAILED of $STEPS checks failed"
  exit 1
fi
echo "VERIFY OK: $STEPS checks passed"
