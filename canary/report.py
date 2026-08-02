"""Regenerate the generated parts of README.md and the whole of docs/index.html.

Everything a reader might quote as a number is produced here from results/findings.json,
so `scripts/verify.sh` can regenerate both files and fail if the committed copies have
drifted. A pasted "38 assertions passed" goes stale the moment someone adds an assertion,
and a README that still says TODO while the code works is the gap this closes.

    python3 -m canary.report            # rewrite in place
    python3 -m canary.report --check    # exit 1 if the files on disk are not current
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .assertions import check
from .detect import NOT_REACHED, NOT_TESTED, REACHES_CONTEXT
from .fixtures import VECTORS
from .policy import POLICY, SESSION_ONLY

ROOT = pathlib.Path(__file__).resolve().parent.parent
BEGIN = "<!-- BEGIN:GENERATED -->"
END = "<!-- END:GENERATED -->"


def summarise(findings: dict) -> dict:
    assertions = check(findings)
    servers = findings["servers"]
    probed = [s["server"] for s in servers if s["probed"]]
    not_probed = [s["server"] for s in servers if not s["probed"]]

    # Field matrix: for each probed server, tool -> vector -> status
    matrix = []
    for s in servers:
        if not s["probed"]:
            continue
        tools: dict[str, dict] = {}
        for o in s["observations"]:
            row = tools.setdefault(o["tool"], {"tool": o["tool"], "cells": {}})
            row["cells"][o["vector"]] = {
                "status": o["status"],
                "fields": sorted({h["field_kind"] for h in o["hits"]}),
                "provenance": o["provenance"],
            }
        matrix.append({"server": s["server"], "tools": list(tools.values())})

    reasons = []
    for s in servers:
        if s["probed"]:
            continue
        pol = POLICY.get(s["server"])
        reasons.append({
            "server": s["server"],
            "category": (pol.category if pol else "") or
                        ("connector" if s["server"] in SESSION_ONLY else "unspecified"),
            "reason": s["reason"],
        })

    return {
        "generated_utc": findings["generated_utc"],
        "counts": findings["counts"],
        "probed": probed,
        "not_probed": not_probed,
        "matrix": matrix,
        "reasons": reasons,
        "inventory": findings["inventory"]["servers"],
        "config_sources": findings["inventory"]["config_sources_checked"],
        "vectors": [{"name": n, "desc": d} for n, d in VECTORS],
        "assertions": [
            {"name": a.name, "kind": a.kind, "expected": a.expected,
             "actual": a.actual, "ok": a.ok} for a in assertions
        ],
        "assertion_totals": {
            "total": len(assertions),
            "passed": sum(1 for a in assertions if a.ok),
            "positive": sum(1 for a in assertions if a.kind == "positive"),
            "control": sum(1 for a in assertions if a.kind == "control"),
            "invariant": sum(1 for a in assertions if a.kind == "invariant"),
        },
    }


# ------------------------------------------------------------------------- README

def readme_block(s: dict) -> str:
    lines = [BEGIN, "", "### What was found", ""]
    c = s["counts"]
    at = s["assertion_totals"]
    lines += [
        f"{len(s['probed'])} MCP servers probed, {len(s['not_probed'])} servers not tested.",
        "",
        f"Across {sum(c.values())} canary observations: **{c[REACHES_CONTEXT]} "
        f"{REACHES_CONTEXT}**, {c[NOT_REACHED]} {NOT_REACHED}, {c[NOT_TESTED]} {NOT_TESTED}.",
        "",
        f"{at['passed']}/{at['total']} assertions pass "
        f"({at['positive']} positive, {at['control']} negative controls, "
        f"{at['invariant']} invariants).",
        "",
        "### Servers discovered on this machine",
        "",
        "| server | plugin | transport | probed | how it was handled |",
        "|---|---|---|---|---|",
    ]
    reason_by_server = {r["server"]: r for r in s["reasons"]}
    inv = {i["name"]: i for i in s["inventory"]}
    for name in s["probed"] + s["not_probed"]:
        i = inv.get(name, {})
        plugin = (i.get("plugin") or "").split("@")[0] or "-"
        transport = i.get("transport") or "claude.ai connector"
        probed = "yes" if name in s["probed"] else "no"
        if name in reason_by_server:
            cat = reason_by_server[name]["category"]
            how = {"auth": "NOT TESTED, needs interactive auth",
                   "remote": "OUT OF SCOPE, would send a payload to a third party",
                   "side-effect": "NOT TESTED, unacceptable side effect",
                   "unreachable": "NOT TESTED, cannot be launched or exercised offline",
                   "connector": "NOT TESTED, account-level connector, not in local config",
                   "unspecified": "NOT TESTED"}.get(cat, "NOT TESTED")
            if name == "context-mode":
                how = "tool surface listed, no tool called"
        else:
            how = "probed with benign canaries"
        lines.append(f"| `{name}` | {plugin} | {transport} | {probed} | {how} |")

    lines += ["", "### Which field carried the canary", "",
              "Each cell is the status for one canary channel through one tool result. "
              "`REACHES` means the marker string came back inside the tool result the "
              "model would read.", ""]
    for entry in s["matrix"]:
        vectors = sorted({v for t in entry["tools"] for v in t["cells"]})
        lines += [f"**{entry['server']}**", "",
                  "| tool | " + " | ".join(vectors) + " |",
                  "|---|" + "---|" * len(vectors)]
        for t in entry["tools"]:
            cells = []
            for v in vectors:
                st = t["cells"].get(v, {}).get("status", "-")
                cells.append({REACHES_CONTEXT: "REACHES", NOT_REACHED: ".",
                              NOT_TESTED: "n/t"}.get(st, "-"))
            tool = t["tool"].replace("|", "\\|")
            lines.append(f"| `{tool}` | " + " | ".join(cells) + " |")
        lines.append("")

    lines += ["### Why each untested server was not tested", ""]
    for r in s["reasons"]:
        lines.append(f"- **`{r['server']}`** ({r['category']}): {r['reason']}")
    lines += ["", f"_Generated from `results/findings.json` at {s['generated_utc']} by "
                  "`python3 -m canary.report`. Do not edit this block by hand._", "", END]
    return "\n".join(lines)


def render_readme(existing: str, s: dict) -> str:
    block = readme_block(s)
    if BEGIN in existing and END in existing:
        head = existing.split(BEGIN)[0]
        tail = existing.split(END, 1)[1]
        return head + block + tail
    return existing.rstrip() + "\n\n" + block + "\n"


# ------------------------------------------------------------------------- docs page

def render_page(s: dict) -> str:
    data = json.dumps(s, indent=1, sort_keys=True)
    return PAGE_TEMPLATE.replace("__DATA__", data)


PAGE_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP prompt-injection canary suite</title>
<style>
:root{
  --bg:#fbfaf7; --fg:#1b1a17; --muted:#6b6862; --line:#ddd8cd; --card:#ffffff;
  --reach:#8c2f1c; --reach-bg:#f7e6e1; --clear:#2f5d3a; --clear-bg:#e6efe7;
  --nt:#5a4a1f; --nt-bg:#f5eed8; --accent:#3a4a7a;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#14151a; --fg:#e8e6e1; --muted:#9a968e; --line:#2c2e36; --card:#1b1d23;
    --reach:#f0a08c; --reach-bg:#3a1f19; --clear:#8fd0a2; --clear-bg:#16291c;
    --nt:#e0cd8e; --nt-bg:#2e2716; --accent:#9db2e8;
  }
}
:root[data-theme="dark"]{
  --bg:#14151a; --fg:#e8e6e1; --muted:#9a968e; --line:#2c2e36; --card:#1b1d23;
  --reach:#f0a08c; --reach-bg:#3a1f19; --clear:#8fd0a2; --clear-bg:#16291c;
  --nt:#e0cd8e; --nt-bg:#2e2716; --accent:#9db2e8;
}
:root[data-theme="light"]{
  --bg:#fbfaf7; --fg:#1b1a17; --muted:#6b6862; --line:#ddd8cd; --card:#ffffff;
  --reach:#8c2f1c; --reach-bg:#f7e6e1; --clear:#2f5d3a; --clear-bg:#e6efe7;
  --nt:#5a4a1f; --nt-bg:#f5eed8; --accent:#3a4a7a;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--fg);
  font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
.wrap{max-width:64rem;margin:0 auto;padding:2rem 1rem 4rem}
h1{font-size:1.65rem;line-height:1.25;margin:0 0 .35rem;letter-spacing:-.01em}
h2{font-size:1.15rem;margin:2.5rem 0 .6rem;letter-spacing:-.01em}
h3{font-size:.95rem;margin:1.5rem 0 .4rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
p{margin:.5rem 0}
.sub{color:var(--muted);margin:0 0 1.5rem;max-width:52rem}
code,kbd{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
a{color:var(--accent)}
.cards{display:grid;gap:.75rem;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));margin:1.25rem 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:.6rem;padding:.8rem .9rem;min-width:0}
.card .n{font-size:1.5rem;font-weight:650;letter-spacing:-.02em;display:block}
.card .l{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:.6rem;background:var(--card)}
table{border-collapse:collapse;width:100%;min-width:0}
th,td{padding:.4rem .6rem;text-align:left;border-bottom:1px solid var(--line);font-size:.85rem;
      white-space:nowrap;vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:.74rem;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:none}
.tag{display:inline-block;padding:.05rem .4rem;border-radius:.3rem;font-size:.74rem;font-weight:600}
.reach{background:var(--reach-bg);color:var(--reach)}
.clear{background:var(--clear-bg);color:var(--clear)}
.nt{background:var(--nt-bg);color:var(--nt)}
.why{background:var(--card);border:1px solid var(--line);border-radius:.6rem;padding:.75rem .9rem;margin:.5rem 0}
.why b{font-family:ui-monospace,Menlo,monospace;font-size:.85rem}
.why p{margin:.3rem 0 0;color:var(--muted);font-size:.88rem}
.note{border-left:3px solid var(--accent);padding:.3rem 0 .3rem .8rem;color:var(--muted);margin:1rem 0}
footer{margin-top:3rem;color:var(--muted);font-size:.8rem;border-top:1px solid var(--line);padding-top:1rem}
#themeToggle{position:absolute;top:1rem;right:1rem;background:var(--card);color:var(--fg);
  border:1px solid var(--line);border-radius:.4rem;padding:.3rem .6rem;font-size:.8rem;cursor:pointer}
.wrap{position:relative}
</style>
</head>
<body>
<div class="wrap">
<button id="themeToggle" type="button">theme</button>
<h1>MCP prompt-injection canary suite</h1>
<p class="sub">Defensive measurement, run with the machine owner's authorisation. For every MCP
server configured on one workstation, the question asked is narrow and checkable: can a
harmless marker string reach a model's context through a tool result, which field of the
result carries it, and does anything label it as untrusted. Payloads are inert markers.
Nothing here tests whether a model obeys an instruction.</p>

<div class="cards" id="cards"></div>

<h2>Servers discovered</h2>
<div class="scroll"><table id="inventory"></table></div>

<h2>Which field carried the canary</h2>
<p class="sub">One row per tool call, one column per delivery channel planted in the fixture.
<span class="tag reach">REACHES</span> means the marker came back inside the tool result.
<code>ABSENT</code> is the negative control: a token of the same shape that was never
planted, so any column marking it as reaching is a detector reporting on nothing.</p>
<div id="matrix"></div>

<h2>Why each untested server was not tested</h2>
<p class="sub">A server that could not be exercised is reported as NOT TESTED. Collapsing it
into either "reaches" or "does not reach" is what would make this exercise worthless.</p>
<div id="reasons"></div>

<h2>Assertions</h2>
<p class="sub">Every positive claim is paired with a control chosen so that a detector bug
breaks the pair.</p>
<div class="scroll"><table id="assertions"></table></div>

<footer id="foot"></footer>
</div>
<script>
const DATA = __DATA__;

function el(tag, attrs, ...kids){
  const n = document.createElement(tag);
  for (const k in (attrs||{})) {
    if (k === "class") n.className = attrs[k]; else n.setAttribute(k, attrs[k]);
  }
  for (const kid of kids) n.append(kid instanceof Node ? kid : document.createTextNode(kid));
  return n;
}
function tag(status){
  if (status === "REACHES_CONTEXT") return el("span", {class:"tag reach"}, "REACHES");
  if (status === "NOT_REACHED") return el("span", {class:"tag clear"}, "no");
  if (status === "NOT_TESTED") return el("span", {class:"tag nt"}, "NOT TESTED");
  return el("span", {}, "-");
}

const c = DATA.counts, at = DATA.assertion_totals;
const cards = [
  [DATA.probed.length, "servers probed"],
  [DATA.not_probed.length, "servers not tested"],
  [c.REACHES_CONTEXT, "reaches context"],
  [c.NOT_REACHED, "not reached"],
  [c.NOT_TESTED, "not tested"],
  [at.passed + "/" + at.total, "assertions pass"],
];
const cardsEl = document.getElementById("cards");
for (const [n, l] of cards) {
  cardsEl.append(el("div", {class:"card"}, el("span", {class:"n"}, String(n)),
                                            el("span", {class:"l"}, l)));
}

const inv = document.getElementById("inventory");
inv.append(el("thead", {}, ["server","plugin","transport","probed"].reduce(
  (tr, h) => (tr.append(el("th", {}, h)), tr), el("tr"))));
const invBody = el("tbody");
const byName = {};
for (const i of DATA.inventory) byName[i.name] = i;
for (const name of DATA.probed.concat(DATA.not_probed)) {
  const i = byName[name] || {};
  const tr = el("tr");
  tr.append(el("td", {}, el("code", {}, name)));
  tr.append(el("td", {}, (i.plugin || "").split("@")[0] || "-"));
  tr.append(el("td", {}, i.transport || "claude.ai connector"));
  tr.append(el("td", {}, DATA.probed.includes(name)
    ? el("span", {class:"tag clear"}, "probed")
    : el("span", {class:"tag nt"}, "NOT TESTED")));
  invBody.append(tr);
}
inv.append(invBody);

const matrix = document.getElementById("matrix");
for (const entry of DATA.matrix) {
  matrix.append(el("h3", {}, entry.server));
  const vectors = Array.from(new Set(entry.tools.flatMap(t => Object.keys(t.cells)))).sort();
  const table = el("table");
  const head = el("tr");
  head.append(el("th", {}, "tool"));
  for (const v of vectors) head.append(el("th", {}, v));
  table.append(el("thead", {}, head));
  const body = el("tbody");
  for (const t of entry.tools) {
    const tr = el("tr");
    tr.append(el("td", {}, el("code", {}, t.tool)));
    for (const v of vectors) {
      const cell = t.cells[v];
      tr.append(el("td", {}, cell ? tag(cell.status) : "-"));
    }
    body.append(tr);
  }
  table.append(body);
  matrix.append(el("div", {class:"scroll"}, table));
}

const reasons = document.getElementById("reasons");
for (const r of DATA.reasons) {
  reasons.append(el("div", {class:"why"},
    el("b", {}, r.server), " ",
    el("span", {class:"tag nt"}, r.category),
    el("p", {}, r.reason)));
}

const at2 = document.getElementById("assertions");
at2.append(el("thead", {}, ["result","kind","assertion","expected","actual"].reduce(
  (tr, h) => (tr.append(el("th", {}, h)), tr), el("tr"))));
const ab = el("tbody");
for (const a of DATA.assertions) {
  const tr = el("tr");
  tr.append(el("td", {}, el("span", {class: a.ok ? "tag clear" : "tag reach"}, a.ok ? "pass" : "FAIL")));
  tr.append(el("td", {}, a.kind));
  tr.append(el("td", {}, a.name));
  tr.append(el("td", {}, a.expected));
  tr.append(el("td", {}, a.actual));
  ab.append(tr);
}
at2.append(ab);

document.getElementById("foot").textContent =
  "Generated " + DATA.generated_utc + " from results/findings.json. " +
  DATA.matrix.reduce((n, m) => n + m.tools.length, 0) + " tool calls measured across " +
  DATA.probed.length + " probed servers.";

document.getElementById("themeToggle").addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme");
  const sysDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const next = cur ? (cur === "dark" ? "light" : "dark") : (sysDark ? "light" : "dark");
  document.documentElement.setAttribute("data-theme", next);
});

// A marker the browser check asserts on. If the script above failed to parse, this
// attribute never appears and the page silently renders as an empty shell.
document.documentElement.setAttribute("data-canary-rendered",
  String(document.querySelectorAll("#matrix table tbody tr").length));
</script>
</body>
</html>
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if README.md or docs/index.html is out of date")
    ap.add_argument("--findings", default=str(ROOT / "results" / "findings.json"))
    a = ap.parse_args(argv)

    findings = json.loads(pathlib.Path(a.findings).read_text(encoding="utf-8"))
    s = summarise(findings)

    readme_path = ROOT / "README.md"
    page_path = ROOT / "docs" / "index.html"
    page_path.parent.mkdir(parents=True, exist_ok=True)

    current_readme = readme_path.read_text(encoding="utf-8") if readme_path.is_file() else ""
    new_readme = render_readme(current_readme, s)
    new_page = render_page(s)

    if a.check:
        stale = []
        if new_readme != current_readme:
            stale.append("README.md")
        if not page_path.is_file() or page_path.read_text(encoding="utf-8") != new_page:
            stale.append("docs/index.html")
        # The generation timestamp changes on every run and is not evidence of drift.
        stale = [f for f in stale if not _only_timestamp_differs(f, readme_path, page_path,
                                                                new_readme, new_page)]
        if stale:
            print("stale generated files: " + ", ".join(stale), file=sys.stderr)
            print("regenerate with: python3 -m canary.report", file=sys.stderr)
            return 1
        print("generated files are current")
        return 0

    readme_path.write_text(new_readme, encoding="utf-8")
    page_path.write_text(new_page, encoding="utf-8")
    print(f"wrote README.md and docs/index.html from {a.findings}")
    return 0


def _strip_ts(text: str) -> str:
    import re
    return re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "<TS>", text)


def _only_timestamp_differs(which: str, readme_path, page_path, new_readme, new_page) -> bool:
    if which == "README.md":
        old = readme_path.read_text(encoding="utf-8") if readme_path.is_file() else ""
        return _strip_ts(old) == _strip_ts(new_readme)
    old = page_path.read_text(encoding="utf-8") if page_path.is_file() else ""
    return _strip_ts(old) == _strip_ts(new_page)


if __name__ == "__main__":
    raise SystemExit(main())
