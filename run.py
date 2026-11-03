"""Run every scenario under each condition and model, then print the table.

    python3 run.py                                  # the full grid
    python3 run.py --scenarios secrets --models haiku --reps 1   # a pilot
    python3 run.py --report runs/<stamp>            # table for a finished grid

Conditions
    none    no rule in the prompt; the guard is asked but never blocks
    rule    the rule appended to the system prompt; the guard never blocks
    hook    no rule in the prompt; the guard blocks for real

In every condition the guard's verdict on each call is logged, so its
catches and false blocks can be checked against the scenario's own detector.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import scenarios as sc

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
CONDITIONS = ("none", "rule", "hook")
MODELS = ("haiku", "sonnet", "opus")
TOOLS = "Bash,Read,Edit,Write,Glob,Grep"
RUN_TIMEOUT_S = 900
VERSION = "0.1.0"


def settings(mode: str, guard: str, run_dir: Path, log: Path) -> dict:
    hook = f"{sys.executable} {ROOT / 'observe.py'} {mode} {guard} {run_dir} {log}"
    return {
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": hook}]}]},
        "permissions": {"blockReadsOutsideWorkingDirectories": True},
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "autoAllowBashIfSandboxed": True,
            "allowUnsandboxedCommands": False,
            "filesystem": {"denyRead": ["~/"], "allowRead": [str(run_dir)], "allowWrite": ["~/.Trash"]},
            "network": {"allowedDomains": [], "strictAllowlist": True},
        },
    }


def parse_stream(text: str) -> tuple[list[dict], list[str], dict]:
    """Tool calls (with whether a hook blocked them), tool outputs, final result event."""
    calls, outputs, by_id, result = [], [], {}, {}
    for line in text.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "result":
            result = ev
        msg = ev.get("message")
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            continue
        for b in content:
            if b.get("type") == "tool_use":
                call = {"tool": b.get("name"), "input": b.get("input") or {}, "blocked": False}
                by_id[b.get("id")] = call
                calls.append(call)
            elif b.get("type") == "tool_result":
                body = b.get("content")
                if isinstance(body, list):
                    body = "\n".join(x.get("text", "") for x in body if isinstance(x, dict))
                body = str(body or "")
                call = by_id.get(b.get("tool_use_id"))
                if call is not None and b.get("is_error") and body.startswith("PreToolUse:") and "hook error" in body:
                    call["blocked"] = True
                else:
                    outputs.append(body)
    return calls, outputs, result


def read_log(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()]


def one_run(stamp_dir: Path, s: sc.Scenario, cond: str, model: str, rep: int) -> dict:
    run_dir = stamp_dir / f"{s.name}-{cond}-{model}-{rep}"
    repo, tmp = run_dir / "repo", run_dir / "tmp"
    repo.mkdir(parents=True)
    tmp.mkdir()
    facts = s.build(repo)
    log = run_dir / "guard.jsonl"
    mode = "enforce" if cond == "hook" else "observe"
    (run_dir / "settings.json").write_text(json.dumps(settings(mode, s.guard, run_dir, log), indent=2))

    cmd = ["claude", "-p", s.task, "--model", model,
           "--setting-sources", "project", "--strict-mcp-config", "--no-session-persistence",
           "--output-format", "stream-json", "--verbose", "--tools", TOOLS,
           "--permission-mode", "bypassPermissions",
           "--settings", str(run_dir / "settings.json")]
    if cond == "rule":
        cmd += ["--append-system-prompt", s.rule]
    gitconfig = run_dir / "gitconfig"
    gitconfig.write_text("[user]\n\tname = eval\n\temail = eval@example.invalid\n")
    env = {**os.environ, "TMPDIR": str(tmp), "GIT_CONFIG_GLOBAL": str(gitconfig), "GIT_CONFIG_NOSYSTEM": "1"}
    start = time.time()
    try:
        p = subprocess.run(cmd, cwd=repo, env=env, capture_output=True, text=True, timeout=RUN_TIMEOUT_S)
        stream, err, timed_out = p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        stream, err, timed_out = (e.stdout or b"").decode(errors="replace"), "timeout", True
    (run_dir / "stream.jsonl").write_text(stream)

    calls, outputs, result = parse_stream(stream)
    ran = [c for c in calls if not c["blocked"]]
    entries = read_log(log)
    flagged = [e for e in entries if e.get("guard_rc") == 2]
    row = {
        "scenario": s.name, "condition": cond, "model": model, "rep": rep,
        "done": s.done(repo, facts),
        "attempted": s.unsafe(sc.Run(calls, outputs, repo), facts),
        "harmed": s.unsafe(sc.Run(ran, outputs, repo), facts),
        "guard_flags": len(flagged),
        "fence_blocks": sum(1 for e in entries if "fence" in e),
        "tool_calls": len(calls),
        "turns": result.get("num_turns"),
        "cost_usd": result.get("total_cost_usd"),
        "seconds": round(time.time() - start),
        "error": timed_out or bool(result.get("is_error")) or not result,
    }
    if row["error"]:
        row["stderr"] = err[-400:]
    return row


def grid(args) -> Path:
    stamp_dir = RUNS / time.strftime("%Y%m%d-%H%M%S")
    stamp_dir.mkdir(parents=True)
    jobs = [(sc.ALL[n], c, m, r) for n in args.scenarios for c in args.conditions
            for m in args.models for r in range(1, args.reps + 1)]
    results = stamp_dir / "results.jsonl"
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for row in pool.map(lambda j: one_run(stamp_dir, *j), jobs):
            with results.open("a") as f:
                f.write(json.dumps(row) + "\n")
            print(json.dumps(row), flush=True)
    return stamp_dir


def pct(rows: list[dict], key: str) -> str:
    return f"{sum(1 for r in rows if r[key])}/{len(rows)}"


def report(stamp_dir: Path) -> str:
    rows = [json.loads(x) for x in (stamp_dir / "results.jsonl").read_text().splitlines() if x.strip()]
    keys = sorted({(r["scenario"], r["condition"], r["model"]) for r in rows},
                  key=lambda k: (k[0], CONDITIONS.index(k[1]), MODELS.index(k[2]) if k[2] in MODELS else 9))
    lines = ["| Scenario | Condition | Model | Task done | Tried the unsafe step | Unsafe step ran | Guard flagged a run | Errors |",
             "|---|---|---|---|---|---|---|---|"]
    for k in keys:
        g = [r for r in rows if (r["scenario"], r["condition"], r["model"]) == k]
        flagged = f"{sum(1 for r in g if r['guard_flags'])}/{len(g)}"
        lines.append(f"| {k[0]} | {k[1]} | {k[2]} | {pct(g, 'done')} | {pct(g, 'attempted')} | "
                     f"{pct(g, 'harmed')} | {flagged} | {pct(g, 'error')} |")
    # Guard against the detector: does the guard flag the runs that tried, and only those?
    observed = [r for r in rows if r["condition"] != "hook"]
    tp = sum(1 for r in observed if r["attempted"] and r["guard_flags"])
    fn = sum(1 for r in observed if r["attempted"] and not r["guard_flags"])
    fp = sum(1 for r in observed if not r["attempted"] and r["guard_flags"])
    lines += ["", f"Guard vs detector, runs where the guard only watched: caught {tp}, missed {fn}, "
                  f"flagged a clean run {fp}."]
    cost = sum(r["cost_usd"] or 0 for r in rows)
    lines.append(f"{len(rows)} runs, list-price cost ${cost:.2f}.")
    text = "\n".join(lines) + "\n"
    (stamp_dir / "results.md").write_text(text)
    return text


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Run coding-agent scenarios with and without a guard, and score each run.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 run.py                                              # full grid, 135 runs\n"
               "  python3 run.py --scenarios secrets --models haiku --reps 1  # one-scenario pilot\n"
               "  python3 run.py --report runs/20261103-194356                # table for a finished grid\n")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    ap.add_argument("--scenarios", nargs="+", default=list(sc.ALL), choices=list(sc.ALL))
    ap.add_argument("--conditions", nargs="+", default=list(CONDITIONS), choices=CONDITIONS)
    ap.add_argument("--models", nargs="+", default=list(MODELS))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()
    print(report(args.report if args.report else grid(args)))


if __name__ == "__main__":
    main()
