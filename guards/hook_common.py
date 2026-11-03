#!/usr/bin/python3
"""
Shared helpers for the PreToolUse Bash guards.

Underscore filename (not hyphenated) so it is importable — the guards themselves
are hyphenated and loaded via importlib by bash-guard.py, but they can `import
hook_common` because sys.path[0] is the hooks dir under both the standalone
(`python3 .../block-prod.py`) and dispatcher (`python3 .../bash-guard.py`)
invocations. Verified from a foreign cwd; a dispatcher-path test pins it.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

# Context a hook already gave Claude in this session. Repeating it costs tokens
# on every later message and teaches nothing new. Cleared when the session is
# compacted, because the summary may drop it.
SEEN_DIR = Path.home() / ".claude" / "state" / "hook-seen"


def seen_before(session_id: str, key: str) -> bool:
    """True if `key` was already recorded for this session; records it otherwise."""
    if not session_id:
        return False
    path = SEEN_DIR / f"{session_id}.txt"
    try:
        if key in path.read_text().splitlines():
            return True
    except FileNotFoundError:
        pass
    SEEN_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(key + "\n")
    return False


def forget_session(session_id: str) -> None:
    if session_id:
        (SEEN_DIR / f"{session_id}.txt").unlink(missing_ok=True)

# Body between `<<TAG` (or `<<'TAG'` / `<<"TAG"` / `<<-TAG`) and a line that is
# just TAG. Shell syntax AROUND the heredoc is preserved.
_HEREDOC = re.compile(
    r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n.*?^\1\s*$",
    flags=re.DOTALL | re.MULTILINE,
)

# `git ... commit ... -m '<arg>'` / -m "<arg>". Captured prefix is kept so the
# command SHAPE stays visible; only the message text is elided. A double-quoted
# message may hold \" (shell escape); a single-quoted one can't, as in the shell.
_QUOTED_ARG = r"(?:'[^']*'|\"(?:\\.|[^\"\\])*\")"
_GIT_COMMIT_MSG = re.compile(
    # -m, combined short flags ending in m (-qm, -am), or --message[= ]
    r"(\bgit\b[^|;&\n]*?\bcommit\b[^|;&\n]*?\s(?:-[a-zA-Z]*m|--message)[\s=]+)" + _QUOTED_ARG,
    flags=re.DOTALL,
)


def elide_prose(command: str) -> str:
    """Blank out heredoc bodies and `git commit -m` message text before scanning.

    PROSE THAT MENTIONS a verb/secret/probe is not the thing itself. A commit
    message saying "un-truncate" is not a TRUNCATE; a heredoc documenting
    `oidc.yml` is not a read of it. Shell OUTSIDE the prose is untouched, so a
    real destructive command lurking after a heredoc still gets caught.
    """
    return elide_commit_msgs(_HEREDOC.sub("<heredoc-elided>", command))


def elide_commit_msgs(text: str) -> str:
    """Blank out the text of EVERY `-m`/--message of a `git commit` (guards that
    keep their own heredoc rules use just this part)."""
    out = _GIT_COMMIT_MSG.sub(r"\1<commit-msg-elided>", text)
    # the 2nd, 3rd … -m of the same commit are prose too (each follows an elided one)
    while True:
        nxt = _NEXT_COMMIT_MSG.sub(r"\1<commit-msg-elided>", out)
        if nxt == out:
            return out
        out = nxt


_NEXT_COMMIT_MSG = re.compile(
    r"(<commit-msg-elided>\s+(?:-[a-zA-Z]*m|--message)[\s=]+)" + _QUOTED_ARG,
    flags=re.DOTALL,
)


def last_assistant_text(transcript_path: str) -> str:
    """Last assistant TEXT block in the transcript (tool calls ignored).
    Used by Stop hooks that judge the final message (prod-data-guard)."""
    if not transcript_path or not os.path.exists(transcript_path):
        return ""
    _await_final_flush(transcript_path)
    last = ""
    try:
        with open(transcript_path, encoding="utf-8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                msg = obj.get("message") or {}
                if obj.get("type") != "assistant" or msg.get("role") != "assistant":
                    continue
                content = msg.get("content")
                parts = [content] if isinstance(content, str) else [
                    b.get("text", "") for b in content or []
                    if isinstance(b, dict) and b.get("type") == "text"]
                text = "\n".join(p for p in parts if p)
                if text.strip():
                    last = text
    except Exception:
        return ""
    return last


# Shared by Stop hooks that judge the FINAL message.
def _await_final_flush(transcript_path: str, timeout: float = 1.5) -> None:
    """Wait for the turn's FINAL assistant message to reach the transcript.

    The Stop hook can fire before that last message is written. Reading the file
    then yields the PREVIOUS assistant text — which, mid-turn, is usually a
    one-line "about to run X" narration — so the gate judges a message the user
    never saw as final, and its complaint makes no sense against what is on
    screen. Observed twice on 2026-07-27 in one session: two Stop gates (terse,
    persist) flagged a "Let me check…" preamble and a "say go" handoff, both
    from the prior message while the real final answer had
    already been delivered. Confirmed by replaying the hook's own extractor over
    the transcript afterwards: the matched text sat at message #40 of 41.

    Poll until an assistant record carrying a text block is the file's tail.
    Fails OPEN on timeout or any error — a gate must never wedge a turn.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            tail = None
            with open(transcript_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        tail = line
            obj = json.loads(tail) if tail else {}
            if obj.get("type") == "assistant":
                content = (obj.get("message") or {}).get("content")
                if isinstance(content, list) and any(
                    isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip()
                    for b in content
                ):
                    return
        except Exception:
            return
        time.sleep(0.05)


# "Claude-speak": filler and buzzwords that make English need translating
# into English. Used by doc-guard (Markdown). Plain swap exists
# for every one — that's the point. Not here on purpose: "underscore" (the
# character) and "seamless" ("seamless roaming" is a real Wi-Fi term).
CLAUDE_SPEAK = [
    r"\bit'?s worth noting\b",
    r"\bit is worth noting\b",
    r"\bin order to\b",
    r"\bleverag(e|es|ed|ing)\b",
    r"\bdelv(e|es|ing)\b",
    r"\ba testament to\b",
    r"\bnavigat(e|ing) the complexit",
    r"\bat the end of the day\b",
    r"\bessentially,",
]


def claude_speak_hit(text: str) -> str:
    """First CLAUDE_SPEAK pattern found in prose, or "".

    Code, code-spans and "quoted" text are names or examples, not prose —
    so a rule that lists the banned phrases doesn't trip itself.
    """
    t = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    t = re.sub(r"`[^`\n]*`", " ", t)
    t = re.sub(r"[\"“][^\"”\n]*[\"”]", " ", t)
    for p in CLAUDE_SPEAK:
        if re.search(p, t, re.IGNORECASE):
            return p
    return ""


# A Bash command that runs tests. Used by test-lock (one run per repo).
# CD finds the folder a command cd's into.
TEST_COMMAND = re.compile(
    r"(?:^|[\s;&|(])(?:"
    r"go\s+test\b"
    r"|make\s+(?:-\S+\s+)*(?:check|test|tests|test-\S+|green|e2e|e2e-\S+|fuzz|mutate)\b"
    r"|(?:bun|npm|pnpm|yarn)\s+(?:run\s+)?test\b"
    r"|(?:bunx|npx|bun\s+x)\s+(?:vitest|playwright|jest)\b"
    r"|python3?\s+-m\s+(?:unittest|pytest)\b"
    r"|vitest\b|jest\b|pytest\b|playwright\s+test\b|cargo\s+test\b"
    r")"
)
CD = re.compile(r"(?:^|[;&|(])\s*cd\s+(\"[^\"]+\"|'[^']+'|[^\s;&|)]+)")

