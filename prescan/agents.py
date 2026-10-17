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


# --------------------------------------------------------------------------- #
# protect: add files to the launched agent's own ignore mechanism
# --------------------------------------------------------------------------- #
PROTECTABLE = {"bob": ".bobignore", "gemini": ".geminiignore", "claude-code": "permissions.deny"}


class ProtectError(Exception):
    pass


def _gitignore_escape(rel: str) -> str:
    """Anchored, literal gitignore pattern for exactly this path."""
    out = re.sub(r"([*?\[\]\\])", r"\\\1", rel)
    if out.endswith(" "):
        out = out[:-1] + "\\ "
    return "/" + out


def protect(agent: str, root: Path, rels: list[str], scope: str = "project") -> tuple[Path, list[str]]:
    """Add `rels` (paths relative to root, files or dirs) to `agent`'s ignore mechanism.

    Returns (file written, entries added). Raises ProtectError if the agent has no enforced
    mechanism, or if prescan doesn't see a path as covered afterwards: a "protect" that the
    agent wouldn't honour must fail loudly, not leave a false sense of safety.
    """
    root = root.resolve()
    if agent not in PROTECTABLE:
        raise ProtectError(f"{agent or 'this agent'} has no ignore mechanism that blocks reads; "
                           "use `prescan allow` for findings that are safe to share, or remove the secret")
    entries: list[str] = []
    if agent in ("bob", "gemini"):
        target = root / PROTECTABLE[agent]
        existing = target.read_text(encoding="utf-8").splitlines() if target.is_file() else []
        current = coverage_for(agent, root)
        for rel in rels:
            if current and current.covers(rel, (root / rel).is_dir()):
                continue
            entries.append(_gitignore_escape(rel) + ("/" if (root / rel).is_dir() else ""))
        if entries:
            text = "\n".join(existing)
            if text and not text.endswith("\n"):
                text += "\n"
            if not existing:
                text += "# Files the agent must not read (added by prescan protect)\n"
            target.write_text(text + "\n".join(entries) + "\n", encoding="utf-8")
    else:  # claude-code: Read(./path) deny rules in the project's settings
        target = root / ".claude" / ("settings.local.json" if scope == "local" else "settings.json")
        try:
            data = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {}
        except ValueError as e:
            raise ProtectError(f"{target} is not valid JSON ({e}); not touching it") from e
        deny = data.setdefault("permissions", {}).setdefault("deny", [])
        for rel in rels:
            if re.search(r"[*?\[\]()\\]", rel):
                raise ProtectError(f"can't write an exact Claude rule for {rel!r} (glob/paren characters); "
                                   "add a permissions.deny rule by hand")
            rule = f"Read(./{rel}/**)" if (root / rel).is_dir() else f"Read(./{rel})"
            if rule not in deny:
                deny.append(rule)
                entries.append(rule)
        if entries:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    after = coverage_for(agent, root)
    missing = [r for r in rels if not (after and after.covers(r if not (root / r).is_dir() else r + "/x"))]
    if missing:
        raise ProtectError(f"wrote {target}, but prescan still doesn't see these as covered: {', '.join(missing)}. "
                           "Another rule in that file may re-include them; check it by hand")
    return target, entries
