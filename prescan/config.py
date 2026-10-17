"""Configuration.

All configuration lives in ONE place outside your projects — the prescan home
(~/.config/prescan/ by default, or $PRESCAN_HOME):

    config.toml     settings, your [block] list, and per-project [[project]] overrides
    baselines/      accepted findings, one file per scanned project

Files inside the scanned repo (.prescan.toml, .prescanignore, .prescan-baseline.json) are
ignored unless `trust_project_config = true`: the code being gated must not be able to
switch the gate off.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .gitignore import GitIgnore
from .rules import HIGH, LOW, MEDIUM, SEVERITY_ORDER, CustomRuleSpec

CONFIG_NAME = ".prescan.toml"
IGNORE_NAME = ".prescanignore"
BASELINE_NAME = ".prescan-baseline.json"

# Directories that are never worth scanning (dependencies, caches, VCS internals).
DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "__pycache__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle", ".terraform",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".parcel-cache", ".cache", "Pods", ".dart_tool",
    ".vscode-test", "site-packages", "_vendor",
}
# A directory containing one of these markers is a cache / virtualenv and is skipped.
SKIP_DIR_MARKERS = ("CACHEDIR.TAG", "pyvenv.cfg")


class ConfigError(Exception):
    pass


def prescan_home() -> Path:
    if os.environ.get("PRESCAN_HOME"):
        return Path(os.environ["PRESCAN_HOME"]).expanduser()
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "prescan"


def central_config_path() -> Path:
    return prescan_home() / "config.toml"


def baseline_path(root: Path) -> Path:
    """Baselines are stored centrally, keyed by the project's absolute path."""
    key = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]
    return prescan_home() / "baselines" / f"{root.resolve().name}-{key}.json"


@dataclass
class BlockConfig:
    """User-defined things that must never reach an agent ([block] in the config)."""
    # Host globs: "api.acme.com" (exact host), "*.acme.com" (any subdomain), "db-*.acme.*"
    domains: list[str] = field(default_factory=list)
    # URL globs matched against whole URLs: "https://partner.com/internal/*"
    urls: list[str] = field(default_factory=list)
    # Variable-name globs, flagged when assigned a literal value: "PROD_*", "*_DB_PASSWORD"
    variables: list[str] = field(default_factory=list)
    # Literal strings (case-insensitive): project codenames, client names, ...
    keywords: list[str] = field(default_factory=list)
    severity: str = HIGH

    def __bool__(self) -> bool:
        return bool(self.domains or self.urls or self.variables or self.keywords)


@dataclass
class Config:
    # Findings at or above this severity block the agent. Lower ones are reported as warnings.
    fail_on: str = MEDIUM
    # Your company's domains: any URL/host under these is treated as internal (high severity).
    internal_domains: list[str] = field(default_factory=list)
    # Extra glob patterns to skip (same syntax as .prescanignore).
    exclude: list[str] = field(default_factory=list)
    # Rule ids to disable entirely.
    disable_rules: list[str] = field(default_factory=list)
    # Regexes; a finding whose matched value matches one of these is dropped.
    allow_values: list[str] = field(default_factory=list)
    max_file_size: int = 2_000_000
    entropy_threshold: float = 3.0
    # The generic `name = value` rule skips lines longer than this (minified bundles).
    generic_max_line_length: int = 400
    # Low-severity "this host looks like prod/internal tooling" hints.
    flag_sensitive_hostnames: bool = True
    custom_rules: list[CustomRuleSpec] = field(default_factory=list)
    block: BlockConfig = field(default_factory=BlockConfig)
    # Extra container registries / package hosts to treat as public (not flagged as private).
    public_registries: list[str] = field(default_factory=list)
    # Honour .prescan.toml / .prescanignore / .prescan-baseline.json inside scanned repos.
    trust_project_config: bool = False
    # Where settings came from (shown in the report).
    sources: list[str] = field(default_factory=list)

    def blocks(self, severity: str) -> bool:
        return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[self.fail_on]


def _check_severity(value: str, key: str) -> str:
    if value not in (HIGH, MEDIUM, LOW):
        raise ConfigError(f"{key} must be one of high|medium|low, got {value!r}")
    return value


def load_config(root: Path, explicit: Path | None = None) -> Config:
    """Central config, then every [[project]] entry whose path covers `root`, then (only if
    trust_project_config) the repo's own .prescan.toml, which can add rules but never loosen fail_on."""
    root = root.resolve()
    cfg = Config()
    path = explicit or central_config_path()
    if path.is_file():
        data = _read_toml(path)
        _apply(cfg, data, str(path))
        cfg.trust_project_config = bool(data.get("trust_project_config", False))
        projects = data.get("project", [])
        if not isinstance(projects, list):
            raise ConfigError(f"{path}: use [[project]] (array of tables) for per-project settings")
        for i, proj in enumerate(projects):
            if not isinstance(proj.get("path"), str):
                raise ConfigError(f"{path}: [[project]] entry #{i + 1} needs a `path`")
            if project_matches(proj["path"], root):
                _apply(cfg, proj, f"{path} [[project]] {proj['path']}")
    elif explicit:
        raise ConfigError(f"config file not found: {path}")

    repo_cfg = root / CONFIG_NAME
    if cfg.trust_project_config and repo_cfg.is_file():
        _apply(cfg, _read_toml(repo_cfg), str(repo_cfg), can_loosen=False)
    return cfg


def project_matches(pattern: str, root: Path) -> bool:
    """`~/work/api` matches that dir and anything under it; `~/clients/*` is a glob."""
    expanded = os.path.expanduser(pattern)
    candidates = [root, *root.parents]
    if any(ch in expanded for ch in "*?["):
        # Resolve the literal prefix (symlinks such as macOS /var -> /private/var), keep the glob part.
        parts = Path(expanded).parts
        i = next(i for i, part in enumerate(parts) if any(ch in part for ch in "*?["))
        pattern = str(Path(*parts[:i]).resolve().joinpath(*parts[i:])) if i else expanded
        return any(fnmatch.fnmatchcase(str(c), pattern.rstrip("/")) for c in candidates)
    p = Path(expanded).resolve()
    return p in candidates


def _read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from e


def _str_list(data: dict, key: str, where: str) -> list[str]:
    v = data.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{where}: `{key}` must be a list of strings")
    return [x.strip() for x in v if x.strip()]


def _apply(cfg: Config, data: dict, path: str, can_loosen: bool = True) -> None:
    cfg.sources.append(path)
    if "fail_on" in data:
        new = _check_severity(data["fail_on"], f"{path}: fail_on")
        if can_loosen or SEVERITY_ORDER[new] < SEVERITY_ORDER[cfg.fail_on]:
            cfg.fail_on = new
    cfg.internal_domains += [d.lower().lstrip("*.") for d in _str_list(data, "internal_domains", str(path))]
    cfg.exclude += _str_list(data, "exclude", str(path))
    cfg.disable_rules += _str_list(data, "disable_rules", str(path))
    cfg.allow_values += _str_list(data, "allow_values", str(path))
    cfg.public_registries += [h.lower() for h in _str_list(data, "public_registries", str(path))]
    cfg.max_file_size = int(data.get("max_file_size", cfg.max_file_size))
    cfg.entropy_threshold = float(data.get("entropy_threshold", cfg.entropy_threshold))
    cfg.flag_sensitive_hostnames = bool(data.get("flag_sensitive_hostnames", cfg.flag_sensitive_hostnames))

    block = data.get("block", {})
    if not isinstance(block, dict):
        raise ConfigError(f"{path}: [block] must be a table")
    where = f"{path} [block]"
    cfg.block.domains += [d.lower() for d in _str_list(block, "domains", where)]
    cfg.block.urls += _str_list(block, "urls", where)
    cfg.block.variables += _str_list(block, "variables", where)
    cfg.block.keywords += _str_list(block, "keywords", where)
    if "severity" in block:
        cfg.block.severity = _check_severity(block["severity"], f"{where} severity")

    for i, r in enumerate(data.get("rules", [])):
        if "id" not in r or "pattern" not in r:
            raise ConfigError(f"{path}: [[rules]] entry #{i + 1} needs at least `id` and `pattern`")
        cfg.custom_rules.append(CustomRuleSpec(
            id=r["id"],
            pattern=r["pattern"],
            severity=_check_severity(r.get("severity", MEDIUM), f"rules[{r['id']}].severity"),
            description=r.get("description", "Custom rule"),
            keywords=list(r.get("keywords", [])),
        ))


class IgnoreMatcher:
    """`exclude` patterns (and a trusted repo .prescanignore), with git's semantics."""

    def __init__(self, patterns: list[str]):
        self.gi = GitIgnore(patterns)

    @classmethod
    def from_root(cls, root: Path, extra: list[str], read_repo_file: bool) -> "IgnoreMatcher":
        lines = list(extra)
        f = root / IGNORE_NAME
        if read_repo_file and f.is_file():
            lines += f.read_text(encoding="utf-8", errors="replace").splitlines()
        return cls(lines)

    def match(self, rel: str, is_dir: bool) -> bool:
        return self.gi.is_ignored_git(rel, is_dir)
