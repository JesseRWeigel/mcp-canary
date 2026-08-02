"""Run the canary suite and write results/findings.json plus raw transcripts.

    python3 -m canary.run [--seed SEED] [--out results]

Everything written here has been through canary/redact.py. checker/independent_check.py
re-reads the written files with its own patterns and shares no code with this package.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import sys
import time
from dataclasses import asdict

from . import probes
from .detect import NOT_TESTED, REACHES_CONTEXT, NOT_REACHED, STATUSES
from .discover import discover, launch_specs
from .policy import POLICY, SESSION_ONLY
from .probes import ProbeUnavailable, result_as_dict

ROOT = pathlib.Path(__file__).resolve().parent.parent

ALL_VECTORS_FOR_UNTESTED = ["ARGECHO", "STORED", "REMOTE", "ABSENT"]


def run(seed: str, out_dir: pathlib.Path, project_dir: str) -> dict:
    inventory = discover(project_dir)
    specs = launch_specs(project_dir)
    results = []
    hard_failures: list[str] = []

    for srec in inventory["servers"]:
        name = srec["name"]
        pol = POLICY.get(name)
        if pol is None:
            reason = (f"NOT TESTED. No policy entry for {name!r}. A server discovered on this "
                      "machine with no probe and no stated reason is a gap, not a pass.")
            results.append(probes.not_tested(name, reason, ALL_VECTORS_FOR_UNTESTED))
            hard_failures.append(f"no policy for discovered server {name!r}")
            continue
        if pol.kind is None:
            results.append(probes.not_tested(name, pol.reason, ALL_VECTORS_FOR_UNTESTED))
            continue

        spec = specs.get(name)
        if spec is None:
            reason = (f"NOT TESTED. {name} has a probe policy but no launchable stdio command "
                      "was resolved from the config.")
            results.append(probes.not_tested(name, reason, ALL_VECTORS_FOR_UNTESTED))
            hard_failures.append(f"policy expects to probe {name!r} but no launch spec resolved")
            continue

        try:
            if pol.kind == "playwright":
                res = probes.probe_playwright(name, pol.reason, seed)
            elif pol.kind == "mempalace":
                res = probes.probe_mempalace(name, pol.reason, spec["command"], spec["args"], seed)
            elif pol.kind == "echo_search":
                res = probes.probe_echo_search(name, pol.reason, spec["command"], spec["args"], seed)
            elif pol.kind == "tools_list_only":
                res = probes.probe_tools_list_only(name, pol.reason, spec["command"], spec["args"])
            else:  # pragma: no cover - policy table is closed
                raise ProbeUnavailable(f"unknown probe kind {pol.kind!r}")
        except ProbeUnavailable as exc:
            # An unavailable dependency is a failure, not a skip. A skipped check reports
            # the same success as one that ran.
            reason = f"NOT TESTED. Probe could not run: {exc}"
            results.append(probes.not_tested(name, reason, ALL_VECTORS_FOR_UNTESTED))
            hard_failures.append(f"{name}: probe unavailable: {str(exc).splitlines()[0]}")
            continue
        results.append(res)

    for name, why in SESSION_ONLY.items():
        results.append(probes.not_tested(
            name, f"NOT TESTED. {why}. Not present in any local config file, so this harness "
                  "cannot launch it.", ALL_VECTORS_FOR_UNTESTED))

    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for old in raw_dir.glob("*.json"):
        old.unlink()
    for res in results:
        if res.transcript:
            safe = res.server.replace("/", "_")
            (raw_dir / f"{safe}.json").write_text(
                json.dumps(res.transcript, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    counts = {s: 0 for s in STATUSES}
    for res in results:
        for o in res.observations:
            counts[o.status] += 1

    findings = {
        "schema": "mcp-canary/1",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": seed,
        "host": {"python": platform.python_version(), "system": platform.system()},
        "inventory": inventory,
        "session_only_servers": SESSION_ONLY,
        "counts": counts,
        "servers": [result_as_dict(r) for r in results],
        "hard_failures": hard_failures,
    }
    (out_dir / "findings.json").write_text(
        json.dumps(findings, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", default="mcp-canary-v1")
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--project-dir", default=str(ROOT))
    a = ap.parse_args(argv)
    findings = run(a.seed, pathlib.Path(a.out), a.project_dir)
    c = findings["counts"]
    print(f"servers in inventory : {len(findings['inventory']['servers'])}")
    print(f"observations         : {sum(c.values())}")
    print(f"  {REACHES_CONTEXT:<16}: {c[REACHES_CONTEXT]}")
    print(f"  {NOT_REACHED:<16}: {c[NOT_REACHED]}")
    print(f"  {NOT_TESTED:<16}: {c[NOT_TESTED]}")
    for hf in findings["hard_failures"]:
        print(f"HARD FAILURE: {hf}", file=sys.stderr)
    return 1 if findings["hard_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
