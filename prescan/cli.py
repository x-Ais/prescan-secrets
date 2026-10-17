"""Command-line interface.

  prescan [scan] [PATH]          scan, exit 0 = ok, 1 = blocked, 2 = error
  prescan baseline [PATH]        accept everything currently flagged
  prescan protect FILE... --agent A   add files to agent A's ignore rules (they stop blocking)
  prescan allow ID|FILE...       mark findings as safe / false positives (central baseline)
  prescan run [--path P] -- CMD  scan, then exec CMD only if the scan is OK
  prescan hook claude-code|bob   UserPromptSubmit hook for Claude Code / IBM Bob (JSON on stdin)
  prescan install-hook           add the hook to Claude Code (or --agent bob) settings
  prescan init                   write the central config (~/.config/prescan/config.toml)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from . import context as C
from .agents import AGENTS, PROTECTABLE, ProtectError, agent_for_command, protect
from .config import CONFIG_NAME, ConfigError, central_config_path, load_config, prescan_home
from .report import render_json, render_text
from .scanner import ScanResult, Scanner, write_baseline

EXIT_OK, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2
SUBCOMMANDS = {"scan", "baseline", "protect", "allow", "run", "hook", "install-hook", "init"}


def _scan(path: str, args, agent: str | None = None) -> ScanResult:
    root = Path(path).expanduser()
    if not root.is_dir():
        raise ConfigError(f"not a directory: {root}")
    cfg = load_config(root.resolve(), Path(args.config) if getattr(args, "config", None) else None)
    if getattr(args, "fail_on", None):
        cfg.fail_on = args.fail_on
    return Scanner(root, cfg, agent=agent).scan()


def _add_scan_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="central config file (default: $PRESCAN_HOME/config.toml, "
                                    "i.e. ~/.config/prescan/config.toml)")
    p.add_argument("--fail-on", choices=["high", "medium", "low"],
                   help="minimum severity that blocks (default: medium, or fail_on in config)")


def _add_agent_opt(p: argparse.ArgumentParser, extra_help: str = "") -> None:
    p.add_argument("--agent", choices=AGENTS,
                   help="the agent that will read the repo: findings in files that agent is configured "
                        "not to read (.bobignore, .geminiignore, Claude permissions.deny) don't block" + extra_help)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_scan(args) -> int:
    result = _scan(args.path, args, agent=args.agent)
    if args.format == "json":
        print(render_json(result))
    else:
        color = False if args.no_color else None
        if not (args.quiet and result.ok):
            print(render_text(result, color=color, show_snippets=not args.no_snippets), file=sys.stderr)
    return EXIT_OK if result.ok else EXIT_BLOCKED


def _production_paths(result: ScanResult) -> set[str]:
    return {f.path for f in result.findings if f.unresolvable}


def cmd_baseline(args) -> int:
    result = _scan(args.path, args)
    prod = _production_paths(result)
    accept = [f for f in result.findings if f.path not in prod]
    if prod:
        print(f"Not accepted (production files always block, remove them): {', '.join(sorted(prod))}",
              file=sys.stderr)
    if not accept:
        print("Nothing to accept.", file=sys.stderr)
        return EXIT_OK if not prod else EXIT_BLOCKED
    p = write_baseline(Path(args.path), accept)
    print(f"Accepted {len(accept)} finding(s) into {p}", file=sys.stderr)
    print("New findings will still block. Delete that file to undo.", file=sys.stderr)
    return EXIT_OK


def _rel_paths(root: Path, paths: list[str]) -> list[str]:
    """User-typed paths (relative to the current dir, or absolute) -> paths relative to root."""
    out = []
    for p in paths:
        full = (Path(p) if Path(p).is_absolute() else Path.cwd() / p)
        if not full.exists() and not full.is_symlink():
            raise ConfigError(f"no such file or directory: {p}")
        try:
            rel = full.parent.resolve().joinpath(full.name).relative_to(root)
        except ValueError:
            raise ConfigError(f"{p} is outside the project ({root})") from None
        if str(rel) == ".":
            raise ConfigError("refusing to protect/allow the whole project; name files or directories")
        out.append(rel.as_posix())
    return out


def cmd_protect(args) -> int:
    root = Path(args.path).expanduser().resolve()
    rels = _rel_paths(root, args.files)
    definite = ("env", "config")  # "possible" production files can be protected like any other
    prod = sorted({r for r in rels if C.production_kind(r) in definite} | {
        f.relative_to(root).as_posix() for r in rels if (root / r).is_dir()
        for f in (root / r).rglob("*") if f.is_file() and C.production_kind(f.relative_to(root).as_posix()) in definite})
    if prod:
        print("prescan protect: production files can't be protected away, they always block. "
              f"Remove them from the repo: {', '.join(prod)}", file=sys.stderr)
        return EXIT_ERROR
    try:
        target, added = protect(args.agent, root, rels, scope=args.scope)
    except ProtectError as e:
        print(f"prescan protect: {e}", file=sys.stderr)
        return EXIT_ERROR
    if added:
        print(f"Added to {target}:", file=sys.stderr)
        for entry in added:
            print(f"  {entry}", file=sys.stderr)
    else:
        print(f"Already covered by {target.name}; nothing to change.", file=sys.stderr)
    print(f"{args.agent} won't read these files, so findings in them no longer block. Keep {target.name} "
          "in the repo so teammates' agents skip them too.", file=sys.stderr)
    return EXIT_OK


def cmd_allow(args) -> int:
    root = Path(args.path).expanduser().resolve()
    result = _scan(str(root), args)
    chosen, problems = [], []
    for sel in args.selectors:
        if re.fullmatch(r"[0-9a-f]{6,20}", sel) and not (Path.cwd() / sel).exists():
            hits = {f.fingerprint: f for f in result.findings if f.fingerprint.startswith(sel)}
            if len(hits) == 1:
                chosen += hits.values()
            else:
                problems.append(f"{sel}: {'ambiguous, use more characters' if hits else 'no current finding with this id'}")
            continue
        try:
            rel = _rel_paths(root, [sel])[0]
        except ConfigError as e:
            problems.append(str(e))
            continue
        hits = [f for f in result.findings if f.path == rel or f.path.startswith(rel + "/")]
        chosen += hits if hits else []
        if not hits:
            problems.append(f"{sel}: no current findings in this path")
    prod = sorted(_production_paths(result) & {f.path for f in chosen})
    if prod:
        problems.append("production files can't be marked safe, they always block. Remove them from the repo: "
                        + ", ".join(prod))
    if problems:
        for p in problems:
            print(f"prescan allow: {p}", file=sys.stderr)
        return EXIT_ERROR
    p = write_baseline(root, chosen, reason=args.reason)
    print(f"Marked {len(chosen)} finding(s) as safe in {p}", file=sys.stderr)
    for f in chosen:
        print(f"  {f.short_id}  {f.path}{':' + str(f.line) if f.line else ''}  {f.rule_id}", file=sys.stderr)
    print("The agent can read these. A new or changed secret will still block.", file=sys.stderr)
    return EXIT_OK


def cmd_run(args) -> int:
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("prescan run: missing command, e.g.  prescan run -- claude", file=sys.stderr)
        return EXIT_ERROR
    result = _scan(args.path, args, agent=args.agent or agent_for_command(cmd[0]))
    if not result.ok:
        print(render_text(result), file=sys.stderr)
        print(f"\nprescan: refusing to start `{cmd[0]}`.", file=sys.stderr)
        return EXIT_BLOCKED
    if any(not f.blocking for f in result.findings):
        print(render_text(result), file=sys.stderr)
    exe = shutil.which(cmd[0])
    if not exe:
        print(f"prescan run: command not found: {cmd[0]}", file=sys.stderr)
        return EXIT_ERROR
    os.execv(exe, cmd)  # replaces this process; never returns


def cmd_hook(args) -> int:
    """UserPromptSubmit hook. Claude Code and IBM Bob share the contract: JSON with `cwd` on stdin,
    exit 2 blocks the prompt, any other non-zero exit is ignored (so every failure here must be 2)."""
    try:
        payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except json.JSONDecodeError:
        payload = {}
    root = payload.get("cwd") or os.getcwd()
    if args.agent == "claude-code":
        root = os.environ.get("CLAUDE_PROJECT_DIR") or root

    try:
        result = _scan(root, args, agent=args.agent)
    except Exception as e:  # fail closed: if we can't scan, the agent doesn't get the code
        print(f"prescan: scan failed ({e}). Blocking to be safe. "
              f"Set PRESCAN_FAIL_OPEN=1 to allow on errors.", file=sys.stderr)
        return EXIT_OK if os.environ.get("PRESCAN_FAIL_OPEN") == "1" else 2

    if not result.ok:
        # Exit 2 blocks the prompt. Claude Code shows stderr to the user (not the model);
        # Bob shows an error and writes stderr to its logs.
        print(render_text(result, color=False), file=sys.stderr)
        return 2

    # Passed. Claude Code: show warnings once per session as a user-visible message (not model
    # context). Bob doesn't document what it does with hook stdout, so print nothing there.
    if args.agent != "claude-code":
        return EXIT_OK
    warnings = [f for f in result.findings if not f.blocking and not f.covered_by]
    session = payload.get("session_id")
    if warnings and session and _first_time(session, result):
        msg = f"prescan: OK with {len(warnings)} warning(s): " + "; ".join(
            f"{f.path}:{f.line} {f.description}" for f in warnings[:5])
        print(json.dumps({"systemMessage": msg}))
    return EXIT_OK


def _first_time(session: str, result: ScanResult) -> bool:
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "prescan" / "sessions"
    key = hashlib.sha256((session + "".join(f.fingerprint for f in result.findings)).encode()).hexdigest()
    marker = cache / key[:32]
    if marker.exists():
        return False
    try:
        cache.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except OSError:
        pass
    return True


HOOK_AGENTS = ("claude-code", "bob")
_VERBS = {"add": ("would add", "added"), "update": ("would update", "updated")}


def _hook_marker(agent: str) -> str:
    return f"prescan hook {agent}"


def _hook_command(agent: str) -> str:
    """The hook always names an absolute interpreter. Agents run hooks in a plain shell where
    `prescan` may not be on PATH, and "command not found" (exit 127) does NOT block a prompt (only
    exit 2 does), so a bare `prescan ...` command would silently fail open."""
    cmd = f"{shlex.quote(sys.executable)} -m {_hook_marker(agent)}"
    probe = subprocess.run([sys.executable, "-c", "import prescan"], cwd="/", capture_output=True,
                           env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
    if probe.returncode != 0:
        # Running from a source checkout that isn't installed into this interpreter.
        cmd = f"PYTHONPATH={shlex.quote(str(Path(__file__).resolve().parent.parent))} {cmd}"
    return cmd


def _is_bare_hook(command: str, agent: str) -> bool:
    return command.strip().startswith(_hook_marker(agent))


def _claude_path_rule(p: Path) -> str:
    """Claude Code permission path syntax: `~/x` is home-relative, `//x` is absolute."""
    p = p.expanduser().resolve()
    try:
        return f"~/{p.relative_to(Path.home().resolve()).as_posix()}/**"
    except ValueError:
        return f"/{p.as_posix()}/**"


def _settings_target(agent: str, scope: str, path: str) -> Path:
    project = Path(path).resolve()
    if agent == "bob":  # Bob: global ~/.bob/settings/settings.json, workspace .bob/settings.json
        if scope == "local":
            raise ConfigError("Bob has no local settings file; use --scope user or --scope project")
        return Path.home() / ".bob" / "settings" / "settings.json" if scope == "user" \
            else project / ".bob" / "settings.json"
    if scope == "user":
        return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "settings.json"
    return project / ".claude" / ("settings.local.json" if scope == "local" else "settings.json")


def cmd_install_hook(args) -> int:
    agent = args.agent
    target = _settings_target(agent, args.scope, args.path)
    data = {}
    if target.is_file():
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"{target} is not valid JSON ({e}); not touching it.", file=sys.stderr)
            return EXIT_ERROR

    changes: list[tuple[str, str]] = []
    cmd = _hook_command(agent)
    groups = data.setdefault("hooks", {}).setdefault("UserPromptSubmit", [])
    existing = [h for g in groups for h in g.get("hooks", []) if _hook_marker(agent) in h.get("command", "")]
    for h in existing:
        if _is_bare_hook(h["command"], agent):  # old installs: depend on PATH, fail open in a plain shell
            changes.append(("update", f"hook: {h['command']!r} -> {cmd}"))
            h["command"] = cmd
    if not existing:
        groups.append({"hooks": [{"type": "command", "command": cmd, "timeout": 60}]})
        changes.append(("add", f"hook: UserPromptSubmit -> {cmd}"))

    # Keep agents away from prescan's own home: it lists exactly what you are hiding,
    # and an agent able to edit it could switch the gate off.
    if agent == "claude-code":
        deny = data.setdefault("permissions", {}).setdefault("deny", [])
        rule_path = _claude_path_rule(prescan_home())
        for tool in ("Read", "Edit"):
            rule = f"{tool}({rule_path})"
            if rule not in deny:
                deny.append(rule)
                changes.append(("add", f"permissions.deny: {rule}"))

    if not changes:
        print(f"Already installed in {target}", file=sys.stderr)
        return EXIT_OK
    for verb, c in changes:
        print(f"{_VERBS[verb][0 if args.dry_run else 1]} {c}", file=sys.stderr)
    if any("hook:" in c for _, c in changes):
        print(f"note: the hook runs {sys.executable}. If that interpreter or its venv is deleted, the "
              "hook fails with 'command not found', which the agent does NOT treat as a block. "
              f"Re-run `prescan install-hook --agent {agent}` after moving or recreating it.", file=sys.stderr)
    if agent == "bob":
        print(f"note: Bob has no deny rules for paths outside the workspace. Keep Bob's \"Allow outside "
              f"workspace tool requests\" setting off so it can't read {prescan_home()}.", file=sys.stderr)
    if args.dry_run:
        print(f"(dry run: {target} not modified)", file=sys.stderr)
        return EXIT_OK
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Updated {target}", file=sys.stderr)
    return EXIT_OK


STARTER_CONFIG = """\
# prescan central configuration.
# This file lives outside your projects and applies to every scan. Keep it private:
# `prescan install-hook` adds a Claude Code deny rule so agents can't read or edit this directory.

# Findings at or above this severity block the agent: high | medium | low
fail_on = "medium"

# Your organisation's domains: the domain itself AND every subdomain are flagged (high).
internal_domains = [
  # "acme.com",
]

# Paths to skip in every project (gitignore syntax, relative to the project root)
exclude = []

# Rule ids to turn off everywhere, e.g. ["jwt", "sensitive-hostname"]
disable_rules = []

# Regexes for values that are known-safe (e.g. public publishable keys)
allow_values = [
  # "^pk_live_",
]

# Honour .prescan.toml / .prescanignore / .prescan-baseline.json found inside scanned repos.
# Off by default: the code being gated should not be able to switch the gate off.
trust_project_config = false

# Things that must never reach an agent. Every match blocks (severity below).
[block]
# Host globs, matched in URLs and as bare hostnames:
#   "myprivate.domaine"   exactly that host
#   "*.privatedomaine"    any subdomain (api.privatedomaine, db.eu.privatedomaine), not the apex
#   "db-*.acme.*"         * matches anything, including dots
domains = []
# URL globs, matched against whole URLs (scheme optional): "https://partner.com/internal/*"
urls = []
# Variable-name globs (case-insensitive), flagged when assigned a literal value:
#   PROD_DB_HOST=..., export PROD_X="...", "PROD_X": "...", prod_x = '...'
# References such as os.environ["PROD_X"] or process.env.PROD_X are not flagged.
variables = [
  # "PROD_*",
  # "*_DB_PASSWORD",
]
# Literal strings, case-insensitive, whole-word: codenames, client names, ...
keywords = []
severity = "high"

# Per-project overrides. `path` is a directory (it and everything under it) or a glob.
# Lists are added to the settings above; fail_on and other scalars replace them.
#
# [[project]]
# path = "~/src/billing-api"
# exclude = ["tests/fixtures/"]
# disable_rules = ["generic-secret-assignment"]
#
# [[project]]
# path = "~/clients/*"
# fail_on = "low"
# [project.block]
# keywords = ["ClientCo"]

# Custom regex rules
# [[rules]]
# id = "acme-api-key"
# description = "ACME internal API key"
# pattern = "acme_[a-f0-9]{32}"
# severity = "high"
# keywords = ["acme_"]
"""

STARTER_PROJECT_CONFIG = """\
# Repo-level prescan config. Only read when the central config sets trust_project_config = true.
# It can add rules and exclusions; it cannot loosen fail_on.
exclude = []
"""


def cmd_init(args) -> int:
    if args.project:
        root = Path(args.project)
        targets = [(root / CONFIG_NAME, STARTER_PROJECT_CONFIG)]
    else:
        targets = [(central_config_path(), STARTER_CONFIG)]
    for p, body in targets:
        if p.exists():
            print(f"exists, not overwritten: {p}", file=sys.stderr)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
            print(f"created {p}", file=sys.stderr)
    if not args.project:
        print(f"prescan home: {prescan_home()}  (override with PRESCAN_HOME)", file=sys.stderr)
    return EXIT_OK


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="prescan", description="Check a codebase for confidential "
                                 "material before letting an AI agent read it.")
    ap.add_argument("--version", action="version", version=f"prescan {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan a directory (default command)")
    p.add_argument("path", nargs="?", default=".")
    _add_agent_opt(p)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-snippets", action="store_true", help="don't print the offending lines")
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing when the scan passes")
    _add_scan_opts(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("baseline", help="accept all current findings (stored in the prescan home)")
    p.add_argument("path", nargs="?", default=".")
    _add_scan_opts(p)
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("protect", help="add files to an agent's ignore rules so findings in them stop blocking")
    p.add_argument("files", nargs="+", metavar="FILE")
    p.add_argument("--agent", required=True, choices=tuple(PROTECTABLE),
                   help="bob -> .bobignore, gemini -> .geminiignore, claude-code -> permissions.deny")
    p.add_argument("--scope", choices=["project", "local"], default="project",
                   help="claude-code only: .claude/settings.json (project, shared) or settings.local.json (local)")
    p.add_argument("--path", default=".", help="project root (default: current directory)")
    p.set_defaults(func=cmd_protect)

    p = sub.add_parser("allow", help="mark findings as safe / false positives (by id from the report, or by file)")
    p.add_argument("selectors", nargs="+", metavar="ID_OR_FILE")
    p.add_argument("--reason", help="why this is safe (stored with the baseline entry)")
    p.add_argument("--path", default=".", help="project root (default: current directory)")
    _add_scan_opts(p)
    p.set_defaults(func=cmd_allow)

    p = sub.add_parser("run", help="scan, then run the agent only if OK:  prescan run -- claude")
    p.add_argument("--path", default=".")
    _add_scan_opts(p)
    _add_agent_opt(p, " (default: guessed from the command name)")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("hook", help="run as an agent hook (reads hook JSON on stdin)")
    p.add_argument("agent", choices=HOOK_AGENTS)
    _add_scan_opts(p)
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("install-hook", help="add the prescan hook to Claude Code settings")
    p.add_argument("--scope", choices=["user", "project", "local"], default="user",
                   help="user = ~/.claude/settings.json (all projects); project/local = <path>/.claude/")
    p.add_argument("--path", default=".")
    p.add_argument("--agent", choices=HOOK_AGENTS, default="claude-code")
    p.add_argument("--dry-run", action="store_true", help="show what would change without writing")
    p.set_defaults(func=cmd_install_hook)

    p = sub.add_parser("init", help="write the starter central config")
    p.add_argument("--project", metavar="PATH",
                   help="write a repo-level .prescan.toml instead (needs trust_project_config = true)")
    p.set_defaults(func=cmd_init)
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as e:
        print(f"prescan: {e}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
