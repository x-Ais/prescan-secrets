"""Human (terminal) and machine (JSON) output."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
from itertools import groupby
from pathlib import Path

from .agents import PROTECTABLE
from .scanner import ScanResult

_AGENT_NAMES = {"claude-code": "Claude Code", "bob": "IBM Bob", "gemini": "Gemini CLI", "codex": "Codex",
                "aider": "Aider"}

_COLORS = {"high": "31;1", "medium": "33;1", "low": "36", "ok": "32;1", "dim": "2", "bold": "1"}


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


def self_command() -> str:
    """How the user can call prescan from where they are (hooks may run without it on PATH)."""
    return "prescan" if shutil.which("prescan") else f"{shlex.quote(sys.executable)} -m prescan"


def _fix_suggestions(result: ScanResult) -> list[str]:
    """The two ways out of a block, as commands ready to copy for the launched agent."""
    cmd = self_command()
    try:
        here = Path.cwd().resolve() == Path(result.root)
    except OSError:
        here = False
    at = "" if here else f" --path {shlex.quote(result.root)}"
    prod = sorted({f.path for f in result.findings if f.unresolvable})
    blocking = [f for f in result.blocking if f.path not in prod]
    files = sorted({f.path for f in blocking if f.category != "config"})
    ids = [f.short_id for f in blocking]
    shown_ids = " ".join(ids[:8]) + (" …" if len(ids) > 8 else "")
    quoted = " ".join(shlex.quote(p) for p in files[:8]) + (" …" if len(files) > 8 else "")
    agent = result.agent
    out = [""]
    if prod:
        out += ["Production files always block: protecting or allowing them is not an option.",
                "  Remove them from the repo (keep them in your secret store / deployment system):"]
        out += [f"    {p}" for p in prod]
        out += ["  If a file was committed, it stays in git history and on any remote it was pushed to:",
                "  rotate the values it contains.", ""]
    if not blocking:
        return out
    out += ["How to resolve the other findings, without deleting anything (pick one per file):", ""]
    out.append("  1. Keep it away from the agent: the file stays, the agent can't read it, prescan stops blocking.")
    if agent in PROTECTABLE:
        out.append(f"       {cmd} protect {quoted} --agent {agent}{at}")
        where = "Claude Code permissions.deny (.claude/settings.json)" if agent == "claude-code" else PROTECTABLE[agent]
        out.append(f"     Adds them to {where}.")
    elif agent:
        out.append(f"     Not available: {_AGENT_NAMES.get(agent, agent)} has no ignore file that blocks reads.")
    else:
        out.append(f"       {cmd} protect {quoted} --agent <claude-code|bob|gemini>{at}")
    out += ["", "  2. Mark as safe / false positive: the agent CAN read it, so only for values that are fine to share.",
            f"       {cmd} allow {shown_ids} --reason \"...\"{at}",
            f"     Or a whole file: {cmd} allow <file> --reason \"...\". Stored centrally as fingerprints, never values.",
            "",
            "  Otherwise remove the secret from the repo, or add `prescan:ignore` on a single false-positive line."]
    return out


def render_text(result: ScanResult, color: bool | None = None, show_snippets: bool = True) -> str:
    color = _use_color(sys.stderr) if color is None else color

    def c(kind: str, s: str) -> str:
        return f"\033[{_COLORS[kind]}m{s}\033[0m" if color else s

    out: list[str] = []
    blocking = result.blocking
    covered = result.covered
    warnings = [f for f in result.findings if not f.blocking and not f.covered_by]

    if result.ok:
        out.append(c("ok", "✔ prescan: OK") + f" — {result.files_scanned} files scanned, nothing blocking.")
    else:
        out.append(c("high", f"✖ prescan: BLOCKED — {len(blocking)} finding(s) must be resolved before an "
                             "AI agent can read this codebase."))
    out.append(c("dim", f"  root: {result.root}"))
    out.append(c("dim", "  config: " + (", ".join(result.config_sources) or "built-in defaults (run `prescan init`)")))
    if result.agent:
        out.append(c("dim", f"  agent: {result.agent}"))

    by_path = sorted((f for f in result.findings if not f.covered_by), key=lambda f: (f.path, f.line))
    for path, group in groupby(by_path, key=lambda f: f.path):
        out.append("")
        out.append(c("bold", path))
        for f in group:
            tag = c(f.severity, f"{f.severity.upper():<6}")
            where = f"L{f.line}" if f.line else "file"
            suffix = "" if f.blocking else c("dim", " (warning)")
            out.append(f"  {tag} {where:<6} {f.description} [{f.rule_id}] {c('dim', 'id ' + f.short_id)}{suffix}")
            if show_snippets and f.snippet:
                out.append(c("dim", f"         {f.snippet}"))

    if covered:
        out.append("")
        out.append(c("bold", f"Covered by {covered[0].covered_by}: not blocking, the agent can't read these files."))
        out.append(c("dim", "Consider removing them from the repo anyway:"))
        for path, group in groupby(sorted(covered, key=lambda f: (f.path, f.line)), key=lambda f: f.path):
            rules = sorted({f.rule_id for f in group})
            out.append(c("dim", f"  {path}  [{', '.join(rules)}]"))

    out.append("")
    summary = f"{len(blocking)} blocking, {len(warnings)} warning(s), {result.files_scanned} files scanned"
    if covered:
        summary += f", {len(covered)} covered by the agent's ignore rules"
    if result.baselined:
        summary += f", {result.baselined} accepted via baseline"
    out.append(c("dim", summary))

    if not result.ok:
        out += _fix_suggestions(result)
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "ok": result.ok,
            "root": result.root,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "baselined": result.baselined,
            "agent": result.agent,
            "covered": len(result.covered),
            "config_sources": result.config_sources,
            "blocking": len(result.blocking),
            "findings": [f.to_dict() for f in result.findings],
        },
        indent=2,
    )
