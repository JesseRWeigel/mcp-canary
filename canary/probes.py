"""Probe implementations, one per policy kind.

Each probe launches the server from its recorded command line, exercises tools with
benign canary strings, and returns raw exchanges plus Observations. No probe writes to a
user data store it did not create, and no probe contacts a third party.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field, asdict

from .detect import NOT_TESTED, Observation, observe
from .fixtures import VECTORS, Fixture, FixtureServer
from .mcpclient import StdioServer
from .redact import redact_obj


class ProbeUnavailable(RuntimeError):
    """A probe could not run. Carries an actionable message; never silently downgraded."""


@dataclass
class ProbeResult:
    server: str
    probed: bool
    reason: str
    tools_listed: list[str] = field(default_factory=list)
    server_info: dict = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    transcript: list[dict] = field(default_factory=list)


def _record(transcript: list[dict], ex) -> None:
    transcript.append(redact_obj({
        "method": ex.method,
        "params": ex.params,
        "ok": ex.ok,
        "error": ex.error,
        "elapsed_s": ex.elapsed_s,
        "response": ex.response,
    }))


def not_tested(server: str, reason: str, vectors: list[str]) -> ProbeResult:
    obs = [Observation(server=server, tool="(none)", vector=v, token="(none)",
                       provenance="remote_passthrough", status=NOT_TESTED, reason=reason)
           for v in vectors]
    return ProbeResult(server=server, probed=False, reason=reason, observations=obs)


# --------------------------------------------------------------------------- playwright

def find_playwright_cli() -> str:
    """Resolve the Playwright MCP entry point without hardcoding a path.

    A hardcoded path to a sibling project is a repeat failure in this workspace: the check
    only ever works in the directory it was written in. Resolution order is an explicit
    override, then whatever npx already cached, and a miss is a hard failure with the
    command that fixes it.
    """
    override = os.environ.get("PLAYWRIGHT_MCP_CLI")
    if override:
        if not os.path.isfile(override):
            raise ProbeUnavailable(f"PLAYWRIGHT_MCP_CLI={override} does not exist")
        return override
    pattern = os.path.expanduser("~/.npm/_npx/*/node_modules/@playwright/mcp/cli.js")
    hits = sorted(glob.glob(pattern))
    if hits:
        return hits[-1]
    raise ProbeUnavailable(
        "Playwright MCP not found in the npx cache. Install it with:\n"
        "    npx -y @playwright/mcp@latest --version\n"
        "    npx -y playwright install chromium\n"
        "Without it the Playwright field matrix cannot run. The rest of the suite still "
        "covers config discovery, redaction, the detector unit tests, the local stdio "
        "servers, and the independent checker."
    )


PLAYWRIGHT_CALLS = [
    ("browser_navigate", None),          # url filled in at run time
    ("browser_snapshot", {}),
    ("browser_console_messages", {}),
    ("browser_evaluate", {"function": "() => document.documentElement.outerHTML"}),
    ("browser_network_requests", {}),
    ("browser_network_request", {"index": 1}),
    ("browser_network_request", {"index": 2, "part": "response-body"}),
    ("browser_find", {"text": "Benign marker"}),
    ("browser_take_screenshot", {"type": "jpeg"}),
]


def probe_playwright(server_name: str, reason: str, seed: str) -> ProbeResult:
    cli = find_playwright_cli()
    if not shutil.which("node"):
        raise ProbeUnavailable("node is not on PATH; install Node 20+ to run the Playwright probe")
    outdir = tempfile.mkdtemp(prefix="mcp-canary-pw-")
    fixture = Fixture(seed=seed)
    tokens = fixture.tokens()
    transcript: list[dict] = []
    observations: list[Observation] = []
    srv = StdioServer(server_name, "node",
                      [cli, "--headless", "--isolated", "--no-sandbox",
                       "--output-mode", "stdout", "--output-dir", outdir])
    try:
        with FixtureServer(fixture) as fs:
            info = srv.start(timeout=120)
            tl = srv.request("tools/list", timeout=60)
            _record(transcript, tl)
            tools = [t["name"] for t in (tl.response or {}).get("tools", [])]
            for tool, args in PLAYWRIGHT_CALLS:
                call_args = {"url": fs.base_url} if args is None else dict(args)
                ex = srv.call_tool(tool, call_args, timeout=120)
                _record(transcript, ex)
                label = f"{tool}({json.dumps(call_args, sort_keys=True)})" \
                    if args else tool
                label = label.replace(fs.base_url, "<fixture-url>")
                for vector, _desc in VECTORS:
                    observations.append(observe(
                        server=server_name, tool=label, vector=vector,
                        token=tokens[vector], provenance="remote_passthrough",
                        result=ex.response, tested=True,
                    ))
    finally:
        srv.stop()
        shutil.rmtree(outdir, ignore_errors=True)
    return ProbeResult(server=server_name, probed=True, reason=reason,
                       tools_listed=tools, server_info=redact_obj(info),
                       observations=observations, transcript=transcript)


# --------------------------------------------------------------------------- mempalace

MEMPALACE_VECTORS = [
    ("ARGECHO", "canary placed in the tool's own query argument"),
    ("STORED", "canary stored in a drawer, then retrieved by a later search"),
    ("ABSENT", "NEGATIVE CONTROL: never placed anywhere"),
]


def probe_mempalace(server_name: str, reason: str, command: str, args: list[str],
                    seed: str) -> ProbeResult:
    from .fixtures import token as mk_token

    if not os.path.isfile(command):
        raise ProbeUnavailable(
            f"mempalace interpreter not found at {command.replace(os.path.expanduser('~'), '~')}. "
            "It is the command recorded in the machine's own MCP config; if mempalace has "
            "been moved or removed, update ~/.claude.json. The rest of the suite still runs."
        )
    palace_root = tempfile.mkdtemp(prefix="mcp-canary-palace-")
    tokens = {v: mk_token(v, seed) for v, _ in MEMPALACE_VECTORS}
    transcript: list[dict] = []
    observations: list[Observation] = []
    # Only the palace path is redirected. HOME is left alone on purpose: overriding it
    # sends chromadb after a fresh 79 MB ONNX embedding model over the network, which
    # would make this probe both slow and dependent on an internet connection.
    srv = StdioServer(server_name, command, args,
                      env={"MEMPALACE_PALACE_PATH": os.path.join(palace_root, "palace")})
    try:
        info = srv.start(timeout=180)
        tl = srv.request("tools/list", timeout=60)
        _record(transcript, tl)
        tools = [t["name"] for t in (tl.response or {}).get("tools", [])]

        add = srv.call_tool("mempalace_add_drawer", {
            "wing": "mcp-canary",
            "room": "general",
            "content": f"Benign inert canary marker for a defensive test: {tokens['STORED']}",
        }, timeout=300)
        _record(transcript, add)

        query = f"benign inert canary marker {tokens['ARGECHO']}"
        search = srv.call_tool("mempalace_search", {"query": query, "limit": 5}, timeout=300)
        _record(transcript, search)

        for vector, _d in MEMPALACE_VECTORS:
            provenance = {"ARGECHO": "argument_echo",
                          "STORED": "stored_passthrough",
                          "ABSENT": "argument_echo"}[vector]
            observations.append(observe(
                server=server_name, tool="mempalace_search", vector=vector,
                token=tokens[vector], provenance=provenance,
                result=search.response, tested=search.ok,
                reason="" if search.ok else f"mempalace_search failed: {search.error[:200]}",
            ))
    finally:
        srv.stop()
        shutil.rmtree(palace_root, ignore_errors=True)
    return ProbeResult(server=server_name, probed=True, reason=reason,
                       tools_listed=tools, server_info=redact_obj(info),
                       observations=observations, transcript=transcript)


# ------------------------------------------------------------------------- echo_search

ECHO_VECTORS = [("ARGECHO", "canary placed in the tool's own query argument"),
                ("ABSENT", "NEGATIVE CONTROL: never placed anywhere")]


def probe_echo_search(server_name: str, reason: str, command: str, args: list[str],
                      seed: str, tool_candidates=("search", "smart_search")) -> ProbeResult:
    """Read-only argument-echo probe for a local search server.

    Nothing is written. The only question asked is whether a string handed to the server
    in tool arguments comes back inside the tool result.
    """
    from .fixtures import token as mk_token

    if not os.path.exists(command):
        raise ProbeUnavailable(f"{server_name}: command not found at "
                               f"{command.replace(os.path.expanduser('~'), '~')}")
    tokens = {v: mk_token(v, f"{server_name}|{seed}") for v, _ in ECHO_VECTORS}
    transcript: list[dict] = []
    observations: list[Observation] = []
    srv = StdioServer(server_name, command, args)
    try:
        info = srv.start(timeout=120)
        tl = srv.request("tools/list", timeout=60)
        _record(transcript, tl)
        tools = [t["name"] for t in (tl.response or {}).get("tools", [])]
        chosen = next((t for t in tool_candidates if t in tools), None)
        if chosen is None:
            reason2 = (f"{server_name} exposes no read-only search tool among "
                       f"{list(tool_candidates)}; listed tools were {tools}")
            for vector, _d in ECHO_VECTORS:
                observations.append(Observation(
                    server=server_name, tool="(none)", vector=vector, token=tokens[vector],
                    provenance="argument_echo", status=NOT_TESTED, reason=reason2))
            return ProbeResult(server=server_name, probed=False, reason=reason2,
                               tools_listed=tools, server_info=redact_obj(info),
                               observations=observations, transcript=transcript)

        schema = next(t.get("inputSchema", {}) for t in tl.response["tools"] if t["name"] == chosen)
        props = list((schema.get("properties") or {}).keys())
        arg_name = next((a for a in ("query", "q", "text", "search") if a in props),
                        props[0] if props else "query")
        ex = srv.call_tool(chosen, {arg_name: f"benign canary {tokens['ARGECHO']}"}, timeout=120)
        _record(transcript, ex)
        for vector, _d in ECHO_VECTORS:
            observations.append(observe(
                server=server_name, tool=f"{chosen}({arg_name}=...)", vector=vector,
                token=tokens[vector], provenance="argument_echo",
                result=ex.response, tested=ex.ok,
                reason="" if ex.ok else f"{chosen} failed: {ex.error[:200]}",
            ))
    finally:
        srv.stop()
    return ProbeResult(server=server_name, probed=True, reason=reason,
                       tools_listed=tools, server_info=redact_obj(info),
                       observations=observations, transcript=transcript)


# --------------------------------------------------------------------- tools_list_only

def probe_tools_list_only(server_name: str, reason: str, command: str,
                          args: list[str]) -> ProbeResult:
    """Start the server and list its tools; call none of them.

    Useful where the tool surface is worth recording but no tool can be exercised without
    a side effect. Every canary vector for such a server is NOT_TESTED, and says so.
    """
    resolved = shutil.which(command) or command
    if not os.path.exists(resolved):
        raise ProbeUnavailable(f"{server_name}: command not found: {command}")
    transcript: list[dict] = []
    srv = StdioServer(server_name, resolved, args)
    try:
        info = srv.start(timeout=120)
        tl = srv.request("tools/list", timeout=60)
        _record(transcript, tl)
        tools = [t["name"] for t in (tl.response or {}).get("tools", [])]
    finally:
        srv.stop()
    why = (f"{reason}. Tool surface recorded ({len(tools)} tools); no tool was called, so "
           "no canary vector was exercised.")
    obs = [Observation(server=server_name, tool="(none)", vector=v, token="(none)",
                       provenance="argument_echo", status=NOT_TESTED, reason=why)
           for v in ("ARGECHO", "ABSENT")]
    return ProbeResult(server=server_name, probed=False, reason=why, tools_listed=tools,
                       server_info=redact_obj(info), observations=obs, transcript=transcript)


def result_as_dict(r: ProbeResult) -> dict:
    d = asdict(r)
    d["observations"] = [asdict(o) for o in r.observations]
    return d
