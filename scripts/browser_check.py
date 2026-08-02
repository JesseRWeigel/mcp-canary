#!/usr/bin/env python3
"""Load docs/index.html in a real browser and assert on what its script produced.

A page's entire script can fail to parse while every unit test passes, and the page then
renders as a static shell with no numbers in it. So this does not check that the file
exists or that the modules import. It loads the page, at a 390px viewport, and asserts on
a DOM attribute that only the inline script can set.

It reuses the Playwright MCP server the canary suite already drives, over a local HTTP
server bound to a kernel-assigned port, because binding a fixed port risks measuring some
other agent's page. Page identity is asserted inside the evaluation for the same reason:
the browser is a shared resource and a concurrent agent can navigate it out from under a
measurement taken as two separate steps.
"""

from __future__ import annotations

import functools
import http.server
import json
import pathlib
import socketserver
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from canary.mcpclient import StdioServer          # noqa: E402
from canary.probes import find_playwright_cli, ProbeUnavailable  # noqa: E402

EXPECTED_TITLE = "MCP prompt-injection canary suite"
VIEWPORT = (390, 844)

# Runs inside the page. Returns a JSON-serialisable verdict, including the page identity
# it measured, so a navigation race shows up as a title mismatch rather than as a silent
# pass against the wrong document.
PROBE_JS = r"""
() => {
  const rendered = document.documentElement.getAttribute("data-canary-rendered");
  const offenders = [];
  const docWidth = document.documentElement.clientWidth;
  const inScroller = (node) => {
    for (let p = node.parentElement; p; p = p.parentElement) {
      const ov = getComputedStyle(p).overflowX;
      if (ov === "auto" || ov === "scroll") return true;
    }
    return false;
  };
  for (const el of document.querySelectorAll("*")) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    if (r.right > docWidth + 0.5 || r.left < -0.5) {
      if (inScroller(el)) continue;
      offenders.push(el.tagName.toLowerCase() +
        (el.id ? "#" + el.id : "") +
        (el.className && typeof el.className === "string" ? "." + el.className.split(" ")[0] : "") +
        " right=" + Math.round(r.right) + " left=" + Math.round(r.left));
    }
  }
  return {
    title: document.title,
    renderedRows: rendered === null ? null : Number(rendered),
    cardCount: document.querySelectorAll("#cards .card").length,
    cardText: Array.from(document.querySelectorAll("#cards .card .n")).map(n => n.textContent),
    matrixTables: document.querySelectorAll("#matrix table").length,
    assertionRows: document.querySelectorAll("#assertions tbody tr").length,
    reasonCards: document.querySelectorAll("#reasons .why").length,
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: docWidth,
    bodyOverflowX: getComputedStyle(document.body).overflowX,
    themeAfterToggle: null,
    offenders: offenders,
  };
}
"""

TOGGLE_JS = r"""
() => {
  document.getElementById("themeToggle").click();
  return document.documentElement.getAttribute("data-theme");
}
"""


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass


def serve(directory: pathlib.Path):
    handler = functools.partial(_Quiet, directory=str(directory))
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def text_of(result) -> str:
    return "\n".join(c.get("text", "") for c in (result or {}).get("content", []))


def main() -> int:
    page = ROOT / "docs" / "index.html"
    if not page.is_file():
        print("FAIL docs/index.html does not exist", file=sys.stderr)
        return 1
    findings_path = ROOT / "results" / "findings.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    expected_matrix_tables = sum(1 for s in findings["servers"] if s["probed"])
    expected_rows = sum(
        len({o["tool"] for o in s["observations"]}) for s in findings["servers"] if s["probed"])

    try:
        cli = find_playwright_cli()
    except ProbeUnavailable as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1

    outdir = tempfile.mkdtemp(prefix="mcp-canary-browser-")
    httpd, port = serve(page.parent)
    srv = StdioServer("playwright", "node",
                      [cli, "--headless", "--isolated", "--no-sandbox",
                       "--output-mode", "stdout", "--output-dir", outdir])
    failures: list[str] = []
    try:
        srv.start(timeout=120)
        srv.call_tool("browser_resize", {"width": VIEWPORT[0], "height": VIEWPORT[1]})
        ex = srv.call_tool("browser_navigate", {"url": f"http://127.0.0.1:{port}/index.html"})
        if not ex.ok:
            print(f"FAIL navigate: {ex.error}", file=sys.stderr)
            return 1
        # Resize again after navigation: the tool applies to the current page and a fresh
        # navigation is where a stale viewport would otherwise go unnoticed.
        srv.call_tool("browser_resize", {"width": VIEWPORT[0], "height": VIEWPORT[1]})
        ev = srv.call_tool("browser_evaluate", {"function": PROBE_JS})
        raw = text_of(ev.response)
        # The result text wraps the returned value in Markdown sections that themselves
        # contain braces, so scanning to the last "}" swallows the echoed JS. Decode from
        # the first "{" and stop where the value ends.
        start = raw.find("{")
        if start < 0:
            print(f"FAIL could not parse evaluate result:\n{raw[:600]}", file=sys.stderr)
            return 1
        try:
            v, _ = json.JSONDecoder().raw_decode(raw[start:])
        except json.JSONDecodeError as exc:
            print(f"FAIL could not parse evaluate result ({exc}):\n{raw[:600]}", file=sys.stderr)
            return 1

        if v["title"] != EXPECTED_TITLE:
            failures.append(f"page identity: expected title {EXPECTED_TITLE!r}, got {v['title']!r} "
                            "(the browser may have been navigated by another agent)")
        if v["renderedRows"] is None:
            failures.append("the inline script never ran: data-canary-rendered is absent, so the "
                            "page is a static shell with no numbers in it")
        elif v["renderedRows"] != expected_rows:
            failures.append(f"script rendered {v['renderedRows']} matrix rows, findings.json "
                            f"implies {expected_rows}")
        if v["cardCount"] != 6:
            failures.append(f"expected 6 summary cards, script produced {v['cardCount']}")
        if v["matrixTables"] != expected_matrix_tables:
            failures.append(f"expected {expected_matrix_tables} matrix tables, got {v['matrixTables']}")
        if v["assertionRows"] != len(findings["servers"]) * 0 + _assertion_count(findings):
            failures.append(f"assertion table has {v['assertionRows']} rows, expected "
                            f"{_assertion_count(findings)}")
        if v["reasonCards"] != sum(1 for s in findings["servers"] if not s["probed"]):
            failures.append(f"reason cards {v['reasonCards']} does not match untested server count")
        if v["bodyOverflowX"] == "hidden":
            failures.append("body has overflow-x: hidden, which masks real overflow and makes "
                            "the scrollWidth probe vacuous")
        if v["offenders"]:
            failures.append("elements overflow the 390px viewport outside any scroll container:\n  "
                            + "\n  ".join(v["offenders"][:10]))
        if v["scrollWidth"] > v["clientWidth"] + 1:
            failures.append(f"document scrolls sideways: scrollWidth={v['scrollWidth']} "
                            f"clientWidth={v['clientWidth']}")

        tog = srv.call_tool("browser_evaluate", {"function": TOGGLE_JS})
        toggled = text_of(tog.response)
        if '"dark"' not in toggled and '"light"' not in toggled:
            failures.append(f"theme toggle did not set data-theme; returned {toggled[:120]!r}")
    finally:
        srv.stop()
        httpd.shutdown()
        httpd.server_close()

    if failures:
        for f in failures:
            print(f"FAIL {f}", file=sys.stderr)
        return 1
    print(f"browser check: title ok, script ran ({v['renderedRows']} matrix rows, "
          f"{v['cardCount']} cards, {v['assertionRows']} assertion rows), no element escapes "
          f"a {VIEWPORT[0]}px viewport, theme toggle sets data-theme")
    return 0


def _assertion_count(findings: dict) -> int:
    from canary.assertions import check
    return len(check(findings))


if __name__ == "__main__":
    raise SystemExit(main())
