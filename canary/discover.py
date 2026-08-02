"""Find the MCP servers actually configured on this machine.

Nothing here is assumed. Every server in the inventory came from a file read at run time,
and each entry records the path it came from so a reader can check the claim. Config is
merged from four places, which is the real Claude Code layout as of this run:

  ~/.claude.json                     global `mcpServers` and a per-project block per cwd
  ~/.claude/settings.json            `enabledPlugins`, which gates the plugin servers
  ~/.claude/plugins/cache/<mp>/<plugin>/<version>/.mcp.json
  <project>/.mcp.json                project-scoped servers, if present

Nothing in this module writes, launches, or authenticates anything.
"""

from __future__ import annotations

import json
import os
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any

from .redact import redact_obj, redact_env, redact_text

HOME = pathlib.Path.home()


@dataclass
class ServerRecord:
    name: str
    source: str            # redacted path the definition came from
    scope: str             # "global" | "project" | "plugin" | "project-file"
    plugin: str = ""
    transport: str = ""    # "stdio" | "http" | "sse" | "unknown"
    command: str = ""
    args: list[str] = field(default_factory=list)
    url: str = ""
    env_keys: dict[str, str] = field(default_factory=dict)
    header_keys: list[str] = field(default_factory=list)
    enabled: bool = True
    local: bool = False    # runs as a local process, no third-party network on start


def _read_json(path: pathlib.Path) -> Any:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as exc:
        # A config we cannot parse is a distinct outcome from a config that is absent.
        # Collapsing the two would let a broken file look like "no servers configured".
        return {"__unreadable__": f"{type(exc).__name__}: {exc}"}


def _classify(defn: dict) -> tuple[str, bool]:
    t = (defn.get("type") or "").lower()
    if t in ("http", "sse", "streamable-http", "websocket", "ws"):
        return (t, False)
    if defn.get("url") and not defn.get("command"):
        return (t or "http", False)
    if defn.get("command"):
        return ("stdio", True)
    return (t or "unknown", False)


def _mk(name: str, defn: dict, source: pathlib.Path, scope: str, plugin: str = "") -> ServerRecord:
    transport, local = _classify(defn)
    headers = defn.get("headers") or {}
    return ServerRecord(
        name=name,
        source=redact_text(str(source)),
        scope=scope,
        plugin=plugin,
        transport=transport,
        command=redact_text(str(defn.get("command") or "")),
        args=[redact_text(str(a)) for a in (defn.get("args") or [])],
        url=redact_text(str(defn.get("url") or "")),
        env_keys=redact_env(defn.get("env") or {}),
        header_keys=sorted(headers.keys()),
        local=local,
    )


def _servers_block(blob: Any) -> dict:
    """A .mcp.json is written either as {"mcpServers": {...}} or as a bare {name: def}.

    Both forms are present in the installed plugins on this machine, so both are handled.
    """
    if not isinstance(blob, dict):
        return {}
    if "mcpServers" in blob and isinstance(blob["mcpServers"], dict):
        return blob["mcpServers"]
    out = {}
    for k, v in blob.items():
        if isinstance(v, dict) and ("command" in v or "url" in v or "type" in v):
            out[k] = v
    return out


def discover(project_dir: str | None = None) -> dict:
    project_dir = project_dir or os.getcwd()
    found: list[ServerRecord] = []
    notes: list[str] = []

    claude_json = HOME / ".claude.json"
    blob = _read_json(claude_json)
    if blob is None:
        notes.append(f"absent: {redact_text(str(claude_json))}")
    elif "__unreadable__" in blob:
        notes.append(f"unreadable: {redact_text(str(claude_json))}: {blob['__unreadable__']}")
    else:
        for name, defn in (blob.get("mcpServers") or {}).items():
            found.append(_mk(name, defn, claude_json, "global"))
        projects = blob.get("projects") or {}
        for pdir, pconf in projects.items():
            for name, defn in ((pconf or {}).get("mcpServers") or {}).items():
                rec = _mk(name, defn, claude_json, "project")
                rec.source = f"{rec.source}#projects[{redact_text(pdir)}]"
                found.append(rec)

    settings = _read_json(HOME / ".claude" / "settings.json") or {}
    enabled_plugins = {k for k, v in (settings.get("enabledPlugins") or {}).items() if v}

    installed = _read_json(HOME / ".claude" / "plugins" / "installed_plugins.json") or {}
    for pkey, entries in (installed.get("plugins") or {}).items():
        for entry in entries or []:
            root = pathlib.Path(entry.get("installPath") or "")
            mcp = root / ".mcp.json"
            blob = _read_json(mcp)
            if not blob:
                continue
            if "__unreadable__" in blob:
                notes.append(f"unreadable: {redact_text(str(mcp))}")
                continue
            for name, defn in _servers_block(blob).items():
                rec = _mk(name, defn, mcp, "plugin", plugin=pkey)
                rec.enabled = pkey in enabled_plugins
                found.append(rec)

    proj_mcp = pathlib.Path(project_dir) / ".mcp.json"
    blob = _read_json(proj_mcp)
    if blob and "__unreadable__" not in blob:
        for name, defn in _servers_block(blob).items():
            found.append(_mk(name, defn, proj_mcp, "project-file"))

    # Only the version of a plugin that is actually installed matters; the cache keeps old
    # ones. Deduplicate on (plugin, name), preferring an enabled record.
    dedup: dict[tuple[str, str], ServerRecord] = {}
    for rec in found:
        key = (rec.plugin, rec.name)
        prev = dedup.get(key)
        if prev is None or (rec.enabled and not prev.enabled):
            dedup[key] = rec

    servers = sorted(dedup.values(), key=lambda r: (r.plugin, r.name))
    return {
        "project_dir": redact_text(project_dir),
        "config_sources_checked": [
            redact_text(str(HOME / ".claude.json")),
            redact_text(str(HOME / ".claude" / "settings.json")),
            redact_text(str(HOME / ".claude" / "plugins" / "installed_plugins.json")),
            redact_text(str(HOME / ".claude" / "plugins" / "cache" / "<marketplace>" / "<plugin>" / "<version>" / ".mcp.json")),
            redact_text(str(proj_mcp)),
        ],
        "notes": notes,
        "servers": [redact_obj(asdict(s)) for s in servers],
    }


def launch_specs(project_dir: str | None = None) -> dict[str, dict]:
    """Unredacted command lines, for launching only. Never written to disk.

    discover() deliberately returns paths with the home directory replaced, because its
    output is committed. A probe still needs the real path to exec, and `${CLAUDE_PLUGIN_ROOT}`
    still needs expanding against the plugin's install directory, so that happens here and
    the result stays in memory.
    """
    project_dir = project_dir or os.getcwd()
    specs: dict[str, dict] = {}

    def add(name: str, defn: dict, plugin_root: str = "") -> None:
        if not defn.get("command"):
            return

        def expand(s: str) -> str:
            return str(s).replace("${CLAUDE_PLUGIN_ROOT}", plugin_root)

        specs[name] = {
            "command": os.path.expanduser(expand(defn["command"])),
            "args": [os.path.expanduser(expand(a)) for a in (defn.get("args") or [])],
            "plugin_root": plugin_root,
        }

    blob = _read_json(HOME / ".claude.json") or {}
    if "__unreadable__" not in blob:
        for name, defn in (blob.get("mcpServers") or {}).items():
            add(name, defn)
        for _pdir, pconf in (blob.get("projects") or {}).items():
            for name, defn in ((pconf or {}).get("mcpServers") or {}).items():
                add(name, defn)

    settings = _read_json(HOME / ".claude" / "settings.json") or {}
    enabled = {k for k, v in (settings.get("enabledPlugins") or {}).items() if v}
    installed = _read_json(HOME / ".claude" / "plugins" / "installed_plugins.json") or {}
    for pkey, entries in (installed.get("plugins") or {}).items():
        if pkey not in enabled:
            continue
        for entry in entries or []:
            root = entry.get("installPath") or ""
            blob = _read_json(pathlib.Path(root) / ".mcp.json")
            if not blob or "__unreadable__" in blob:
                continue
            for name, defn in _servers_block(blob).items():
                add(name, defn, plugin_root=root)

    blob = _read_json(pathlib.Path(project_dir) / ".mcp.json")
    if blob and "__unreadable__" not in blob:
        for name, defn in _servers_block(blob).items():
            add(name, defn)
    return specs


if __name__ == "__main__":  # pragma: no cover - manual inspection aid
    print(json.dumps(discover(), indent=2))
