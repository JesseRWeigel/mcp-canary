"""Per-server decision: probe it, or say why not.

Three rules constrain what may be probed, and they are written here rather than being
decided ad hoc inside each probe so that a reader can audit the whole policy in one place.

1. No configuration is modified. Servers are launched as child processes from their
   recorded command line; the host's own connections are never touched.
2. Nothing is authenticated. A server behind an interactive OAuth flow is NOT_TESTED.
3. No payload is sent to a service we do not control. A canary is attacker-controlled
   text by construction, and posting it to a third party would be doing the thing this
   suite exists to warn about.

`kind` selects the probe implementation. `reason` is mandatory whenever kind is None,
because a server with no probe and no explanation is indistinguishable from one that was
forgotten.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    kind: str | None          # probe implementation, or None
    reason: str = ""          # required when kind is None
    category: str = ""        # NOT_TESTED sub-reason: auth | remote | side-effect | unsupported

    def __post_init__(self) -> None:
        if self.kind is None and not self.reason:
            raise ValueError("a server with no probe needs a stated reason")


POLICY: dict[str, Policy] = {
    "playwright": Policy(
        kind="playwright",
        reason="local stdio server driving a local Chromium; the fixture page it visits is "
               "served from 127.0.0.1, so no payload leaves the machine",
    ),
    "mempalace": Policy(
        kind="mempalace",
        reason="local stdio server; probed against a throwaway palace directory supplied "
               "via MEMPALACE_PALACE_PATH so the real memory store is never written",
    ),
    "mcp-search": Policy(
        kind="echo_search",
        reason="local stdio server (claude-mem); read-only search only, no writes",
    ),
    "context-mode": Policy(
        kind="tools_list_only",
        reason="local stdio server; probed for its tool surface only",
    ),
    "context7": Policy(
        kind=None, category="remote",
        reason="OUT OF SCOPE. Every context7 tool forwards its argument string to Upstash's "
               "hosted API. Probing it would mean sending canary text to a third party we do "
               "not control, which is the exact act this suite exists to warn about.",
    ),
    "discord": Policy(
        kind=None, category="remote",
        reason="OUT OF SCOPE. The server authenticates to Discord with the user's bot token "
               "and every tool either reads a private guild or posts into it. Reading would "
               "expose private messages to this harness; posting would send canary text to a "
               "third party. Neither is acceptable.",
    ),
    "firebase": Policy(
        kind=None, category="remote",
        reason="NOT TESTED. Launch line is `npx -y firebase-tools@latest mcp`, which resolves "
               "`@latest` against the npm registry on every start, and its tools need either a "
               "signed-in Firebase project or a call to Google's hosted docs API.",
    ),
    "github": Policy(
        kind=None, category="auth",
        reason="NOT TESTED. HTTP server at api.githubcopilot.com requiring "
               "GITHUB_PERSONAL_ACCESS_TOKEN, which is not set in this environment, and every "
               "tool call is a request to GitHub.",
    ),
    "greptile": Policy(
        kind=None, category="auth",
        reason="NOT TESTED. HTTP server requiring GREPTILE_API_KEY, which is not set in this "
               "environment, and every tool call is a request to Greptile.",
    ),
    "stripe": Policy(
        kind=None, category="auth",
        reason="NOT TESTED. Hosted HTTP server at mcp.stripe.com behind an interactive OAuth "
               "flow. Completing it would authenticate a live payments account.",
    ),
    "vercel": Policy(
        kind=None, category="auth",
        reason="NOT TESTED. Hosted HTTP server at mcp.vercel.com behind an interactive OAuth "
               "flow.",
    ),
    "huggingface-skills": Policy(
        kind=None, category="auth",
        reason="NOT TESTED. Hosted HTTP server at huggingface.co/mcp with `?login`, an "
               "interactive sign-in.",
    ),
    "circleback": Policy(
        kind=None, category="auth",
        reason="NOT TESTED. Hosted HTTP server at app.circleback.ai behind an interactive "
               "OAuth flow, holding the user's meeting notes.",
    ),
}

# Servers this session exposed that are not defined by any file on this machine. They come
# from account-level claude.ai connectors, so local discovery cannot see them and this
# harness cannot drive them. Listing them keeps the inventory honest about its own blind
# spot rather than implying the local config is the whole picture.
SESSION_ONLY = {
    "claude_ai_Gmail": "account-level claude.ai connector; OAuth, remote, holds private mail",
    "claude_ai_Google_Calendar": "account-level claude.ai connector; OAuth, remote",
    "claude_ai_Google_Drive": "account-level claude.ai connector; OAuth, remote",
}
