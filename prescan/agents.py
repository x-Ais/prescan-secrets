"""What the launched agent is itself configured not to read.

A finding in a file the agent can't read is "covered": reported, never blocking. Only the
launched agent's own mechanism counts (.cursorignore doesn't protect anything from Bob).

Every reader is conservative: when a rule's meaning is ambiguous, the file is NOT covered,
because a wrong "covered" would let the agent read a file prescan thought was protected.
"""

from __future__ import annotations

import json
import os
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .gitignore import GitIgnore

AGENTS = ("claude-code", "bob", "gemini", "codex", "aider")

# Command name (as typed after `prescan run --`) -> agent
COMMAND_AGENTS = {"claude": "claude-code", "bob": "bob", "gemini": "gemini", "codex": "codex", "aider": "aider"}

# Ignore files that look like protection but aren't enforced by that agent.
UNENFORCED = {
    "claude-code": (".claudeignore", "`.claudeignore` is not a Claude Code feature: files listed there are "
                                     "still readable. Use permissions.deny Read(...) rules instead."),
    "aider": (".aiderignore", "`.aiderignore` only hides files from Aider's repo map; it doesn't stop "
                              "Aider from reading them."),
}


@dataclass
class Coverage:
    label: str                                   # shown in the report, e.g. ".bobignore"
    check: Callable[[str, bool], bool] = field(repr=False)

    def covers(self, rel: str, is_dir: bool = False) -> bool:
        return self.check(rel, is_dir)


def agent_for_command(cmd: str) -> str | None:
    return COMMAND_AGENTS.get(os.path.basename(cmd))


def coverage_for(agent: str | None, root: Path) -> Coverage | None:
    if agent in ("bob", "gemini"):
        return _ignore_file(root, ".bobignore" if agent == "bob" else ".geminiignore")
    if agent == "claude-code":
        return _claude_deny(root)
    return None


def unenforced_ignore_file(agent: str | None, root: Path) -> tuple[str, str] | None:
    entry = UNENFORCED.get(agent or "")
    if entry and (root / entry[0]).is_file():
        return entry
    return None


# --------------------------------------------------------------------------- #
# .bobignore / .geminiignore — gitignore syntax at the project root
# --------------------------------------------------------------------------- #
def _ignore_file(root: Path, name: str) -> Coverage | None:
    f = root / name
    if not f.is_file():
        return None
    try:
        gi = GitIgnore(f.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return None
    return Coverage(name, gi.is_ignored_everywhere) if gi else None


# --------------------------------------------------------------------------- #
# Claude Code — permissions.deny Read(...) rules
# --------------------------------------------------------------------------- #
def claude_settings_files(root: Path) -> list[Path]:
    managed = (Path("/Library/Application Support/ClaudeCode/managed-settings.json")
               if platform.system() == "Darwin" else Path("/etc/claude-code/managed-settings.json"))
    user_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    return [managed, user_dir / "settings.json",
            root / ".claude" / "settings.json", root / ".claude" / "settings.local.json"]


_READ_RULE = re.compile(r"^Read(?:\((.*)\))?$")
_GLOB_CHARS = re.compile(r"[*?\[]")


def _resolve_literal_prefix(abs_pattern: str) -> str:
    """Resolve symlinks in the glob-free leading part (macOS /var -> /private/var)."""
    parts = abs_pattern.split("/")
    i = next((k for k, part in enumerate(parts) if _GLOB_CHARS.search(part)), len(parts))
    prefix = "/".join(parts[:i]) or "/"
    resolved = str(Path(prefix).resolve())
    rest = "/".join(parts[i:])
    return resolved.rstrip("/") + ("/" + rest if rest else "")


def claude_rule_to_pattern(spec: str, root: Path) -> str | None:
    """Read(...) path -> absolute gitignore pattern, or None if the form is ambiguous.

    Supported: `//abs`, `~/home-relative`, `./x` and `x` (relative to the project root, anchored
    there; prescan does NOT assume `.env` also matches `sub/.env`). Unsupported: `/x` (relative
    to the settings file's location, whose base differs by file), so it never counts as coverage.
    """
    spec = spec.strip()
    if not spec:
        return None
    if spec.startswith("//"):
        abs_pat = "/" + spec[2:]
    elif spec == "~" or spec.startswith("~/"):
        abs_pat = str(Path.home().resolve()) + spec[1:]
    elif spec.startswith("/"):
        return None
    else:
        abs_pat = str(root.resolve()) + "/" + (spec[2:] if spec.startswith("./") else spec)
    return _resolve_literal_prefix(abs_pat)


def _claude_deny(root: Path) -> Coverage | None:
    patterns: list[str] = []
    deny_all = False
    for f in claude_settings_files(root):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        deny = (data.get("permissions") or {}).get("deny") or []
        for rule in deny if isinstance(deny, list) else []:
            m = _READ_RULE.match(rule.strip()) if isinstance(rule, str) else None
            if not m:
                continue
            if m.group(1) is None:
                deny_all = True  # bare `Read`: every read is denied
                continue
            pat = claude_rule_to_pattern(m.group(1), root)
            if pat:
                patterns.append("/" + pat.lstrip("/"))  # leading `/` = anchored to filesystem root
    if not patterns and not deny_all:
        return None
    gi = GitIgnore(patterns)
    base = str(root.resolve())

    def check(rel: str, is_dir: bool) -> bool:
        return deny_all or gi.is_ignored_everywhere((base + "/" + rel).lstrip("/"), is_dir)

    return Coverage("Claude Code permissions.deny", check)
