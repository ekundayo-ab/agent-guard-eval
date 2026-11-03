"""PreToolUse hook for one eval run.

    python3 observe.py <mode> <guard> <fence> <log>

mode   observe: ask the guard, log its verdict, never block.
       enforce: ask the guard, log its verdict, block when it blocks.
       none:    log the call only.
guard  a hook in guards/, without .py. It runs with HOME set to a fresh copy
       of guards/home inside the run, so it reads the repo's pattern files and
       writes nothing outside the run.
fence  the run's folder. A call that names a path outside it is blocked in
       every mode, so a run can never touch the rest of the machine.
log    JSONL file; one line per tool call.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

GUARDS = Path(__file__).resolve().parent / "guards"
PATH_KEYS = ("file_path", "path", "notebook_path")
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/opt/homebrew/", "/dev/null", "/dev/stdout", "/dev/stderr",
                   "/Library/Developer/CommandLineTools/")
HOME_RE = re.compile(r"(^|[\s='\"(:])~|\$HOME\b|\$\{HOME\}")
ABS_RE = re.compile(r"(?<![\w.:/-])(/[A-Za-z][^\s'\"`;|&)<>]*)")


def outside(path: str, fence: Path, cwd: Path) -> bool:
    p = Path(os.path.expanduser(path))
    p = (p if p.is_absolute() else cwd / p).resolve()
    return p != fence and fence not in p.parents


def fence_reason(tool: str, ti: dict, fence: Path, cwd: Path) -> str | None:
    if tool == "Bash":
        cmd = ti.get("command", "")
        if HOME_RE.search(cmd):
            return "names the home folder"
        for m in ABS_RE.finditer(cmd):
            p = m.group(1)
            if not p.startswith(SYSTEM_PREFIXES) and outside(p, fence, cwd):
                return f"names {p}"
        return None
    for key in PATH_KEYS:
        if ti.get(key) and outside(str(ti[key]), fence, cwd):
            return f"names {ti[key]}"
    return None


def guard_home(fence: Path) -> Path:
    home = fence / "guard-home"
    if not home.exists():
        shutil.copytree(GUARDS / "home", home)
    return home


def ask_guard(guard: str, raw: str, fence: Path) -> tuple[int, str, str]:
    home = guard_home(fence)
    env = {**os.environ, "HOME": str(home), "TRASH_GUARD_DIR": str(home / ".Trash")}
    r = subprocess.run([sys.executable, str(GUARDS / f"{guard}.py")], input=raw,
                       capture_output=True, text=True, timeout=60, env=env)
    return r.returncode, r.stdout, r.stderr


def main(argv: list[str]) -> int:
    mode, guard, fence, log = argv[1], argv[2], Path(argv[3]).resolve(), Path(argv[4])
    raw = sys.stdin.read()
    payload = json.loads(raw)
    tool, ti = payload.get("tool_name", ""), payload.get("tool_input") or {}
    cwd = Path(payload.get("cwd") or fence)

    entry = {"tool": tool, "input": ti, "mode": mode}
    reason = fence_reason(tool, ti, fence, cwd)
    rc, out, err = (0, "", "")
    if reason:
        entry["fence"] = reason
    elif mode != "none":
        rc, out, err = ask_guard(guard, raw, fence)
        entry.update(guard_rc=rc, guard_says=err[:400])
    with log.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    if reason:
        sys.stderr.write(f"Blocked: this call {reason}, outside the project folder {fence}. Stay inside it.\n")
        return 2
    if mode == "enforce":
        sys.stdout.write(out)
        sys.stderr.write(err)
        return rc
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
