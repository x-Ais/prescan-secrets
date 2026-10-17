"""Human (terminal) and machine (JSON) output."""

from __future__ import annotations

import json
import os
import sys
from itertools import groupby

from .scanner import ScanResult

_COLORS = {"high": "31;1", "medium": "33;1", "low": "36", "ok": "32;1", "dim": "2", "bold": "1"}


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


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
            out.append(f"  {tag} {where:<6} {f.description} [{f.rule_id}]{suffix}")
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
        out += [
            "",
            "How to resolve:",
            "  • Move secrets out of the repo (secret manager, or a file outside the project dir).",
            "  • False positive on one line?  add a comment containing  prescan:ignore",
            "  • Whole file/dir is fine?      add it to `exclude` for this project in the central config",
            "                                 (prescan init prints where it is)",
            "  • Accept everything currently flagged:  prescan baseline",
        ]
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
