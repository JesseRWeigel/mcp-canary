"""Where does a canary land inside an MCP tool result, and is it labelled?

The question this project exists to answer is not "can a server return text" (every one
can) but which *fields* of a tool result carry text a server did not author, and whether
anything in the result tells the reading model that the text is untrusted.

So the detector does three things and keeps them separate:

  * locate  - the exact JSON path of every canary occurrence in a raw result
  * classify - map that path to a field kind the host actually renders into context
  * label   - report whether any provenance marker appears in the same result

Status is a closed three-value set. REACHES_CONTEXT, NOT_REACHED, and NOT_TESTED are
different facts, and folding NOT_TESTED into either of the other two is the failure that
makes the whole exercise worthless, so the type refuses to represent it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

REACHES_CONTEXT = "REACHES_CONTEXT"
NOT_REACHED = "NOT_REACHED"
NOT_TESTED = "NOT_TESTED"
STATUSES = (REACHES_CONTEXT, NOT_REACHED, NOT_TESTED)

CANARY_RE = re.compile(r"MCPCANARY-[A-Z0-9]{2,12}-[0-9a-f]{8}")

# Field kinds, ordered most specific first. The path form is what an MCP result looks
# like on the wire; the label is what the host does with it.
_FIELD_KINDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\$\.content\[\d+\]\.text$"), "content[].text"),
    (re.compile(r"^\$\.content\[\d+\]\.resource\.text$"), "content[].resource.text"),
    (re.compile(r"^\$\.content\[\d+\]\.resource\."), "content[].resource.*"),
    (re.compile(r"^\$\.content\[\d+\]\.data$"), "content[].data"),
    (re.compile(r"^\$\.content\[\d+\]\."), "content[].other"),
    (re.compile(r"^\$\.structuredContent\b"), "structuredContent"),
    (re.compile(r"^\$\._meta\b"), "_meta"),
    (re.compile(r"^\$\.isError$"), "isError"),
]

# Strings a host or server could use to tell the model "this text is not from the user".
# Case-insensitive on purpose: these are prose conventions, not credential formats.
_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("untrusted-tag", re.compile(r"</?untrusted[^>]*>", re.I)),
    ("untrusted-word", re.compile(r"\buntrusted\b", re.I)),
    ("external-content", re.compile(r"\bexternal(ly)?[ -]?(supplied|provided|sourced|content)\b", re.I)),
    ("do-not-follow", re.compile(r"\bdo not (follow|obey|execute|act on)\b", re.I)),
    ("not-from-user", re.compile(r"\bnot (from|written by) the user\b", re.I)),
    ("system-reminder", re.compile(r"</?system-reminder>", re.I)),
    ("injection-warning", re.compile(r"\bprompt injection\b", re.I)),
    ("data-not-instructions", re.compile(r"\b(treat|as) data,? not (as )?instructions\b", re.I)),
]

# How the canary got into the server's hands. A server that echoes back a string we put
# in the tool arguments is a much weaker carrier than one that hands back text it fetched
# from somewhere an attacker could control.
PROVENANCE = ("argument_echo", "stored_passthrough", "remote_passthrough", "server_authored")


@dataclass
class Hit:
    token: str
    label: str
    json_path: str
    field_kind: str
    context: str          # short excerpt around the hit, canary included


@dataclass
class Observation:
    """One canary vector observed through one tool call."""

    server: str
    tool: str
    vector: str           # which channel the canary was planted in
    token: str
    provenance: str
    status: str
    hits: list[Hit] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)
    reason: str = ""      # required when status is NOT_TESTED

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}, got {self.status!r}")
        if self.provenance not in PROVENANCE:
            raise ValueError(f"provenance must be one of {PROVENANCE}, got {self.provenance!r}")
        if self.status == NOT_TESTED and not self.reason:
            raise ValueError("NOT_TESTED requires a reason; an unexplained gap reads as a pass")
        if self.status == REACHES_CONTEXT and not self.hits:
            raise ValueError("REACHES_CONTEXT claimed with no hit to back it")
        if self.status == NOT_REACHED and self.hits:
            raise ValueError("NOT_REACHED claimed while hits were recorded")


def walk_strings(obj: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield (json_path, string) for every string leaf, including dict keys' values."""
    if isinstance(obj, str):
        yield (path, obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{path}[{i}]")


def field_kind(json_path: str) -> str:
    for pat, kind in _FIELD_KINDS:
        if pat.search(json_path):
            return kind
    return "other"


def find_markers(obj: Any) -> list[str]:
    """Provenance markers anywhere in the result, not merely adjacent to the canary.

    A host that wraps the whole tool result in a warning still counts as labelling it,
    so this looks at the entire structure.
    """
    found: set[str] = set()
    for _, s in walk_strings(obj):
        for name, pat in _MARKERS:
            if pat.search(s):
                found.add(name)
    return sorted(found)


def find_canary(result: Any, token: str, window: int = 60) -> list[Hit]:
    hits: list[Hit] = []
    for path, s in walk_strings(result):
        start = 0
        while True:
            idx = s.find(token, start)
            if idx < 0:
                break
            lo = max(0, idx - window)
            hi = min(len(s), idx + len(token) + window)
            excerpt = s[lo:hi].replace("\n", " ")
            hits.append(Hit(token=token, label="", json_path=path,
                            field_kind=field_kind(path), context=excerpt))
            start = idx + len(token)
    return hits


def observe(server: str, tool: str, vector: str, token: str, provenance: str,
            result: Any, tested: bool, reason: str = "") -> Observation:
    """Build an Observation from a raw result.

    `tested` is passed in rather than inferred, because "the tool call did not happen"
    and "the tool call happened and returned nothing" produce the same empty result and
    must not be reported the same way.
    """
    if not tested:
        return Observation(server=server, tool=tool, vector=vector, token=token,
                           provenance=provenance, status=NOT_TESTED,
                           reason=reason or "tool was not exercised")
    hits = find_canary(result, token)
    return Observation(
        server=server, tool=tool, vector=vector, token=token, provenance=provenance,
        status=REACHES_CONTEXT if hits else NOT_REACHED,
        hits=hits, markers=find_markers(result),
    )
