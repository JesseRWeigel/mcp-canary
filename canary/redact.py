"""Redaction applied to everything this project writes to disk.

MCP configuration files sit next to real credentials, so nothing discovered is written
out raw. Two independent things happen here:

1. Credential-shaped substrings are replaced with a type tag.
2. The user's home directory is replaced with `~`, because verify output is pasted into
   the README and an absolute /home/<user> path there is both private and unportable.

checker/independent_check.py re-checks the written artefacts for both of these using its
own patterns and shares no code with this module, because a leak check that reuses the
filter's own regex inherits the filter's bugs.
"""

from __future__ import annotations

import os
import re

HOME = os.path.expanduser("~")

# Case-sensitive where the real credential format is case-sensitive. A case-insensitive
# AKIA rule matches ordinary base64 and turns every embedded image into a false alarm.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}")),
    ("SLACK_TOKEN", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("STRIPE_KEY", re.compile(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("OPENROUTER_KEY", re.compile(r"sk-or-v1-[A-Za-z0-9]{32,}")),
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[A-Za-z0-9_-]{24,}")),
    ("GOOGLE_KEY", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("AWS_KEY_ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("HF_TOKEN", re.compile(r"hf_[A-Za-z0-9]{34,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("BEARER", re.compile(r"(?i:bearer)\s+[A-Za-z0-9._~+/-]{24,}={0,2}")),
]

# ${VAR} placeholders are not secrets and must survive redaction, otherwise the inventory
# loses the fact that a server expects a credential from the environment.
_PLACEHOLDER = re.compile(r"^\$\{[A-Z0-9_]+\}$")


def redact_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    out = text
    for tag, pat in _PATTERNS:
        out = pat.sub(f"<REDACTED:{tag}>", out)
    if HOME and HOME != "/" and HOME in out:
        out = out.replace(HOME, "~")
    return out


def redact_env(env: dict) -> dict:
    """Env values are never emitted. Keys are, because the key name is the finding."""
    result = {}
    for k, v in (env or {}).items():
        if isinstance(v, str) and _PLACEHOLDER.match(v.strip()):
            result[k] = v.strip()
        elif v in (None, ""):
            result[k] = "<EMPTY>"
        else:
            result[k] = "<REDACTED:ENV_VALUE>"
    return result


def redact_obj(obj):
    """Recursively redact a JSON-shaped object.

    Keys whose *name* implies a credential get their value dropped wholesale, since a
    token that does not match any known pattern would otherwise survive.
    """
    secretish = ("token", "key", "secret", "password", "authorization", "cookie",
                 "credential", "apikey", "api_key", "passwd", "session")
    # Fields that hold key *names* rather than key values. Without this exemption the
    # substring rule eats `header_keys`, which is the finding itself, and the inventory
    # silently loses which credential a server expects.
    name_only = ("env_keys", "header_keys", "key_paths", "keys_present")
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in name_only:
                out[k] = redact_obj(v) if not isinstance(v, dict) else {
                    kk: (vv if isinstance(vv, str) and vv.startswith("<") else redact_text(str(vv)))
                    for kk, vv in v.items()
                }
                continue
            if isinstance(k, str) and any(s in k.lower() for s in secretish):
                if isinstance(v, str) and _PLACEHOLDER.match(v.strip()):
                    out[k] = v.strip()
                elif isinstance(v, str) and v.startswith("Bearer ${") and v.endswith("}"):
                    out[k] = v
                else:
                    out[k] = "<REDACTED:BY_KEY_NAME>"
                continue
            out[k] = redact_obj(v)
        return out
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
