"""Minimal MCP client speaking JSON-RPC 2.0 over a stdio subprocess.

Deliberately small and dependency-free. It exists so the canary harness can drive a
real MCP server the same way an agent host does, without going through any agent, and
capture the *raw* JSON of every response before anything reformats it.

Only stdio servers are driven here. HTTP/OAuth servers are never contacted; see
canary/inventory.py for why each one is out of scope or untested.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any


PROTOCOL_VERSION = "2025-06-18"


class McpError(RuntimeError):
    pass


@dataclass
class Exchange:
    """One request/response pair, kept verbatim for the independent checker."""

    method: str
    params: dict
    response: Any
    ok: bool
    error: str = ""
    elapsed_s: float = 0.0


@dataclass
class StdioServer:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None

    _proc: subprocess.Popen | None = None
    _next_id: int = 1
    _stderr: list[str] = field(default_factory=list)

    def start(self, timeout: float = 60.0) -> dict:
        env = dict(os.environ)
        env.update(self.env)
        # A server that inherits a chatty locale or colour setting can emit ANSI to
        # stdout and corrupt the JSON stream; force the boring case.
        env["NO_COLOR"] = "1"
        env["TERM"] = "dumb"
        self._proc = subprocess.Popen(
            [self.command, *self.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
            cwd=self.cwd,
        )
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        init = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-canary", "version": "1.0"},
            },
            timeout=timeout,
        )
        if not init.ok:
            raise McpError(f"{self.name}: initialize failed: {init.error}")
        self.notify("notifications/initialized")
        return init.response

    def _drain_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for line in self._proc.stderr:
            self._stderr.append(line.rstrip("\n"))

    def stderr_text(self) -> str:
        return "\n".join(self._stderr)

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method: str, params: dict | None = None, timeout: float = 60.0) -> Exchange:
        assert self._proc, "start() first"
        rid = self._next_id
        self._next_id += 1
        started = time.time()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        try:
            msg = self._read_until(rid, timeout)
        except Exception as exc:  # noqa: BLE001 - the failure reason is the payload
            return Exchange(method, params or {}, None, False, f"{type(exc).__name__}: {exc}",
                            round(time.time() - started, 3))
        elapsed = round(time.time() - started, 3)
        if "error" in msg:
            return Exchange(method, params or {}, msg, False, json.dumps(msg["error"])[:500], elapsed)
        return Exchange(method, params or {}, msg.get("result"), True, "", elapsed)

    def call_tool(self, name: str, arguments: dict, timeout: float = 90.0) -> Exchange:
        ex = self.request("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
        # An MCP server reports tool-level failure inside a successful JSON-RPC response
        # via isError, so a transport-level ok is not the same as the tool having worked.
        if ex.ok and isinstance(ex.response, dict) and ex.response.get("isError"):
            ex.ok = False
            ex.error = "isError=true in tool result"
        return ex

    def _send(self, obj: dict) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(json.dumps(obj) + "\n")
        self._proc.stdin.flush()

    def _read_until(self, rid: int, timeout: float) -> dict:
        assert self._proc and self._proc.stdout
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(f"no response to id={rid} within {timeout}s")
            line = _readline_with_timeout(self._proc, remaining)
            if line is None:
                raise TimeoutError(f"no response to id={rid} within {timeout}s")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                # Non-JSON chatter on stdout. Record it; do not treat it as a response.
                self._stderr.append(f"[stdout-noise] {line[:200]}")
                continue
            if msg.get("id") == rid:
                return msg
            # Server-initiated request or notification: ignore, but keep a trace.
            self._stderr.append(f"[unsolicited] {line[:200]}")

    def stop(self) -> None:
        if not self._proc:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            self._proc.wait(timeout=10)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        self._proc = None


def _readline_with_timeout(proc: subprocess.Popen, timeout: float) -> str | None:
    """readline() with a wall clock bound, using a helper thread.

    select() on a text-mode pipe is not reliable across platforms, and a blocking
    readline on a hung server would wedge the whole suite.
    """
    box: list[str | None] = []

    def _read() -> None:
        assert proc.stdout
        box.append(proc.stdout.readline())

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    t.join(timeout)
    if not box:
        return None
    return box[0] or None
