#!/usr/bin/python3
"""
PreToolUse guard — nothing Claude does may destroy a file beyond the Trash.

Asked for 2026-10-11: "lock down ALL of them such that they all go through the
trash and can never escape the trash". The `rm=trash` alias only covers a bare
`rm` in Claude's zsh; `bash -c "rm …"`, `/bin/rm`, `xargs rm`, `find -delete`,
`git clean`, inline-Python deletes and overwrites all bypassed it (verified).

Two halves, one file:
  Bash                  → BLOCK every permanent delete/overwrite vector and
                          point Claude at `trash <path>` (recoverable).
  Write/Edit/MultiEdit/ → never block; COPY the file's current content into
  NotebookEdit            the Trash first, unless git can already restore it
                          (tracked + unmodified) or it lives in a temp dir.

Overwrite checks (redirect, mv/cp onto, sed -i, tee, truncate, dd of=) fire only
when the target EXISTS, is outside temp dirs, and is not git-clean — a file git
can restore is already recoverable.

Known hole (no static check can close it): a delete INSIDE a script file or a
compiled program (`./clean.sh`, `make clean`, `npm run x`) is invisible here.

Reads JSON from stdin (Claude Code hook protocol). Exit 0 allow / 2 block.
Bypass (user's own shell only — Claude cannot set it per command):
CLAUDE_ALLOW_PERMANENT_DELETE=1.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hook_common import _HEREDOC, elide_commit_msgs

BYPASS = "CLAUDE_ALLOW_PERMANENT_DELETE"
IS_MAC = sys.platform == "darwin"
TRASH_DIR = Path(os.environ.get("TRASH_GUARD_DIR") or  # override = tests only
                 Path.home() / (".Trash" if IS_MAC else ".local/share/Trash/files"))
TRASH_CMD = "trash" if IS_MAC else "gio trash"
TEMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/folders/", "/var/folders/", "/dev/")

# Command position: start, a separator, a quote (bash -c "rm …"), $( or `,
# or after a wrapper (sudo/xargs/env/-exec …). Then an optional \ or a path.
_POS = (r"(?:^|[\n;&|(`'\"]|\$\(|\b(?:sudo|command|exec|builtin|env|nohup|nice|time|caffeinate)\s+"
        r"|\bxargs\b[^;&|\n]*?\s|-exec(?:dir)?\s+)\s*\\?(?:/[\w./-]*/)?")

RULES: list[tuple[str, re.Pattern]] = [(label, re.compile(rx, re.I | re.M)) for label, rx in [
    ("rm / unlink / shred", _POS + r"(rm|unlink|shred|srm|gshred|grm)(?=\s|$|[;&|)'\"`])"),
    ("find -delete", r"\bfind\b[^;&|\n]*\s-delete\b"),
    ("git clean", r"\bgit\s+(?:-C\s+\S+\s+)?clean\b(?![^;&|\n]*\s(?:-n|--dry-run)\b)"),
    ("git rm --force", r"\bgit\s+(?:-C\s+\S+\s+)?rm\b[^;&|\n]*\s(?:-f|--force|-[a-z]*f[a-z]*)\b"),
    ("git reset --hard", r"\bgit\s+(?:-C\s+\S+\s+)?reset\b[^;&|\n]*--hard\b"),
    ("git checkout -- / . (discards edits)", r"\bgit\s+(?:-C\s+\S+\s+)?checkout\b[^;&|\n]*(?:\s--\s|\s\.(?:\s|$)|\s-f\b|--force\b)"),
    ("git restore (discards edits)", r"\bgit\s+(?:-C\s+\S+\s+)?restore\b(?![^;&|\n]*--staged\b(?![^;&|\n]*--worktree))"),
    ("git stash drop/clear", r"\bgit\s+(?:-C\s+\S+\s+)?stash\s+(?:drop|clear)\b"),
    ("rsync --delete", r"\brsync\b[^;&|\n]*\s--(?:delete|remove-source-files)"),
    ("disk erase / mkfs", r"\b(?:diskutil\s+(?:erase\w*|zeroDisk|randomDisk|secureErase|apfs\s+deleteVolume)"
                          r"|mkfs(?:\.\w+)?|newfs\w*|wipefs)\b"),
    ("mv to /dev/null", _POS + r"mv\b[^;&|\n]*\s/dev/null\b"),
    # A delete is a CALL (name + "("): naming os.remove in a string or comment
    # deletes nothing and was blocked like one (2026-10-25).
    ("inline-code delete", r"(?:\bos\.(?:remove|unlink|rmdir|removedirs)\s*\(|\bshutil\.rmtree\s*\("
                           r"|\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\("
                           r"|fs(?:\.promises)?\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\b|Bun\.file\([^)]*\)\.delete|"
                           r"FileUtils\.(?:rm\w*|remove\w*)|File\.(?:delete|unlink)\b|\bunlink\s*\(|\bunlink\s+[\"'$@]|\brmtree\s*\()"),
]]

OVERWRITE_CMDS = {"mv", "cp", "sed", "gsed", "perl", "tee", "truncate", "dd", "ditto", "install", "ln"}


# A read-only search tool's arguments are a PATTERN, not code: `grep 'os.Remove'`
# searches for a delete, it doesn't perform one. Elided per pipeline segment, so
# whatever the search feeds (`| xargs rm`, `&& rm -rf`) is still scanned.
# The search may start inside quotes (ssh host 'grep …', bash -c "grep …"), and
# its quoted pattern may hold `|` ("(x|rm)"), so quoted strings are skipped whole.
_SEARCH_SEG = re.compile(r"(^|[;&|\n(`'\"]\s*)((?:git\s+(?:-C\s+\S+\s+)?grep|grep|egrep|fgrep|rg|ag|ack)\b)"
                         r"(?:'[^']*'|\"[^\"]*\"|[^;&|\n'\"])*")


def strip_prose(cmd: str) -> str:
    """Drop commit-message text, heredocs that only WRITE a file (cat/tee), and
    search-tool patterns. A heredoc fed to bash/python/node is code and stays."""
    def heredoc(m: re.Match) -> str:
        start = cmd.rfind("\n", 0, m.start()) + 1
        head = cmd[start:m.start()].strip()
        first = re.split(r"[;&|(]\s*", head)[-1].split()
        return "<heredoc-elided>" if first and first[0] in ("cat", "tee", "echo", "printf") else m.group(0)
    out = elide_commit_msgs(_HEREDOC.sub(heredoc, cmd))  # every -m, not just the first
    return _SEARCH_SEG.sub(r"\1\2 <search-elided>", out)


def resolve(p: str, cwd: str) -> Path:
    return Path(os.path.expanduser(p)) if os.path.isabs(os.path.expanduser(p)) else Path(cwd) / os.path.expanduser(p)


def git_restorable(path: Path) -> bool:
    """True when git can bring this file back: tracked and identical to HEAD."""
    d = str(path.parent)
    try:
        tracked = subprocess.run(["git", "-C", d, "ls-files", "--error-unmatch", path.name],
                                 capture_output=True, timeout=3).returncode == 0
        clean = subprocess.run(["git", "-C", d, "diff", "--quiet", "HEAD", "--", path.name],
                               capture_output=True, timeout=3).returncode == 0
        return tracked and clean
    except (OSError, subprocess.SubprocessError):
        return False


def at_risk(path: Path) -> bool:
    """Existing regular file whose loss could not be undone."""
    s = str(path.resolve()) if path.exists() else str(path)
    if s.startswith(TEMP_PREFIXES) or "/scratchpad/" in s or not path.is_file():
        return False
    return not git_restorable(path)


def segments(cmd: str) -> list[list[str]]:
    out = []
    for seg in re.split(r"&&|\|\||[;|\n]", cmd):
        try:
            argv = shlex.split(seg, comments=True)
        except ValueError:
            continue
        while argv and (argv[0] in ("sudo", "command", "exec", "env", "nohup", "time") or "=" in argv[0]):
            argv = argv[1:]
        if argv:
            out.append(argv)
    return out


def overwrite_targets(cmd: str, cwd: str) -> list[tuple[str, Path]]:
    hits: list[tuple[str, Path]] = []
    for m in re.finditer(r"(?<![<>&\d])>\|?(?![>&])\s*([^\s;&|)<>]+)", cmd):
        hits.append(("> redirect", resolve(m.group(1).strip("'\""), cwd)))
    for argv in segments(cmd):
        name = os.path.basename(argv[0])
        if name not in OVERWRITE_CMDS:
            continue
        flags = [a for a in argv[1:] if a.startswith("-")]
        args = [a for a in argv[1:] if not a.startswith("-")]
        if name in ("mv", "cp", "ditto", "install", "ln"):
            if any(f in ("-n", "--no-clobber") or (f.startswith("-") and not f.startswith("--") and "n" in f) for f in flags) \
                    or len(args) < 2 or (name == "ln" and not any("f" in f for f in flags)):
                continue
            dest = resolve(args[-1], cwd)
            targets = [dest / os.path.basename(s) for s in args[:-1]] if dest.is_dir() else [dest]
            hits += [(f"{name} onto existing file", t) for t in targets]
        elif name in ("sed", "gsed", "perl"):
            if any(f.startswith("-i") or f == "--in-place" or (name == "perl" and "i" in f) for f in flags):
                hits += [(f"{name} -i", resolve(a, cwd)) for a in args]
        elif name == "tee":
            if not any(f in ("-a", "--append") for f in flags):
                hits += [("tee", resolve(a, cwd)) for a in args]
        elif name == "truncate":
            hits += [("truncate", resolve(a, cwd)) for a in args]
        elif name == "dd":
            hits += [("dd of=", resolve(a[3:], cwd)) for a in argv[1:] if a.startswith("of=")]
    return [(lbl, p) for lbl, p in hits if at_risk(p)]


# Folders one install/build brings back. Trashing them filled the Trash with
# ~1M files (one node_modules ≈ 50k) and made emptying it crawl (2026-10-20).
# Worktrees are NOT here: they can hold uncommitted work.
REBUILDABLE = {"node_modules", "dist", "build", ".venv", "venv", ".next", ".nuxt", ".svelte-kit",
               "target", ".turbo", ".parcel-cache", "__pycache__", ".pytest_cache", ".mypy_cache",
               ".ruff_cache", "coverage"}
_RM_SEG = re.compile(r"(^|[;&|\n(]\s*)rm\s+([^;&|\n()`$<>]*)")


def rebuildable(arg: str, cwd: str) -> bool:
    """A literal path to a rebuildable folder with nothing git-tracked inside."""
    if re.search(r"[*?\[{]", arg) or os.path.basename(arg.rstrip("/")) not in REBUILDABLE:
        return False
    p = resolve(arg, cwd)
    if p.is_symlink() or (p.exists() and not p.is_dir()):
        return False
    try:
        r = subprocess.run(["git", "-C", str(p.parent), "ls-files", "--", p.name],
                           capture_output=True, text=True, timeout=3)
        return not r.stdout.strip()  # tracked files inside → it's source, not output
    except (OSError, subprocess.SubprocessError):
        return False


def allow_rebuildable_rm(scan: str, cwd: str) -> str:
    """Elide `rm -rf node_modules dist` when EVERY path is a rebuildable folder."""
    def sub(m: re.Match) -> str:
        try:
            argv = shlex.split(m.group(2))
        except ValueError:
            return m.group(0)
        flags = [a for a in argv if a.startswith("-")]
        paths = [a for a in argv if not a.startswith("-")]
        if paths and all(re.fullmatch(r"-[rRfdv]+|--", f) for f in flags) \
                and all(rebuildable(a, cwd) for a in paths):
            return f"{m.group(1)}<rebuildable-rm>"
        return m.group(0)
    return _RM_SEG.sub(sub, scan)


# The other half: Claude trashing a rebuildable folder out of habit refilled the
# Trash with a 40k-file node_modules the day after the rm exemption (2026-10-21).
_TRASH_SEG = re.compile(r"(^|[;&|\n(]\s*)(?:trash|gio\s+trash)\s+([^;&|\n()`$<>]*)")


def trashed_rebuildable(cmd: str, cwd: str) -> str | None:
    """First existing rebuildable folder a `trash` command would fill the Trash with."""
    for m in _TRASH_SEG.finditer(strip_prose(cmd)):
        try:
            argv = shlex.split(m.group(2))
        except ValueError:
            continue
        for a in argv:
            if not a.startswith("-") and resolve(a, cwd).is_dir() and rebuildable(a, cwd):
                return a
    return None


def check_bash(cmd: str, cwd: str) -> str | None:
    scan = allow_rebuildable_rm(strip_prose(cmd), cwd)
    for label, rx in RULES:
        if rx.search(scan):
            return label
    risky = overwrite_targets(scan, cwd)
    if risky:
        lbl, p = risky[0]
        return f"{lbl} ({p})"
    return None


def backup_before_edit(path: Path) -> None:
    """Copy the current file into the Trash (deduped by content hash)."""
    if not at_risk(path):
        return
    data = path.read_bytes()
    tag = hashlib.sha1(data).hexdigest()[:8]
    dest = TRASH_DIR / f"{path.stem} (before claude edit {tag}){path.suffix}"
    if dest.exists():
        return
    TRASH_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest)
    if not IS_MAC:  # freedesktop Trash lists a file only with its .trashinfo
        info = TRASH_DIR.parent / "info" / f"{dest.name}.trashinfo"
        info.parent.mkdir(parents=True, exist_ok=True)
        stamp = __import__("datetime").datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        info.write_text(f"[Trash Info]\nPath={path}\nDeletionDate={stamp}\n")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if os.environ.get(BYPASS) == "1":
        return 0
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()

    if tool == "Bash":
        folder = trashed_rebuildable(ti.get("command", ""), cwd)
        if folder:
            sys.stderr.write(
                f"BLOCKED by trash-guard: {folder} is rebuildable (one install/build brings it back).\n"
                f"  Trashing it floods the Trash with tens of thousands of files.\n"
                f"  Delete it for real:    rm -rf {folder}   (alone in the rm, literal path)\n"
            )
            return 2
        hit = check_bash(ti.get("command", ""), cwd)
        if not hit:
            return 0
        sys.stderr.write(
            f"BLOCKED by trash-guard: {hit} would destroy data permanently, past the Trash.\n"
            f"  Delete instead with:   {TRASH_CMD} <path>     (recoverable from {TRASH_DIR})\n"
            f"  Rebuildable folders:   rm -rf node_modules dist   (alone in the rm, literal paths, untracked)\n"
            f"  Overwrite instead:     {TRASH_CMD} <file>  first, then write it fresh — or use the Edit tool,\n"
            f"                         which copies the old version into the Trash automatically.\n"
            f"  Discarding git edits:  git stash push -- <path>   (recoverable via git stash list)\n"
            f"  User-only bypass:      export {BYPASS}=1   (in your own shell, then relaunch claude)\n"
        )
        return 2

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = ti.get("file_path") or ti.get("notebook_path")
        if p:
            try:
                backup_before_edit(resolve(p, cwd))
            except OSError as e:
                sys.stderr.write(f"[trash-guard] backup of {p} failed: {e}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
