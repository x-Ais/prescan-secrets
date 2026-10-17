"""Walks a directory tree and produces findings."""

from __future__ import annotations

import bisect
import fnmatch
import hashlib
import ipaddress
import json
import math
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import context as C
from . import rules as R
from .agents import coverage_for, unenforced_ignore_file
from .blocklist import BlockList
from .config import (
    BASELINE_NAME,
    CONFIG_NAME,
    DEFAULT_SKIP_DIRS,
    SKIP_DIR_MARKERS,
    Config,
    IgnoreMatcher,
    baseline_path,
)

INLINE_IGNORE = re.compile(r"prescan:\s*(?:ignore|allow)", re.IGNORECASE)


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    path: str               # relative to scan root, forward slashes
    line: int               # 1-based, 0 for file-level findings
    column: int
    redacted: str           # safe-to-display version of the matched value
    snippet: str            # the line with the secret redacted
    fingerprint: str
    blocking: bool = True
    covered_by: str | None = None   # set when the launched agent is configured not to read this file

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    files_scanned: int
    files_skipped: int
    baselined: int
    config_sources: list[str] = field(default_factory=list)
    agent: str | None = None

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.blocking]

    @property
    def covered(self) -> list[Finding]:
        return [f for f in self.findings if f.covered_by]

    @property
    def ok(self) -> bool:
        return not self.blocking


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def redact(value: str) -> str:
    """Keep just enough to recognise the value, never enough to use it."""
    if len(value) <= 8:
        return "*" * len(value)
    keep = 4 if len(value) < 40 else 6
    return f"{value[:keep]}…{'*' * 4} ({len(value)} chars)"


def fingerprint(rule_id: str, path: str, value: str) -> str:
    return hashlib.sha256(f"{rule_id}\0{path}\0{value}".encode()).hexdigest()[:20]


def _is_binary(chunk: bytes) -> bool:
    return b"\0" in chunk


def _looks_generated_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'`")
    return bool(R.PLACEHOLDER_RE.match(v)) or bool(R.CODE_REF_RE.search(v))


def _host_is_safe(host: str) -> bool:
    return host in R.SAFE_HOSTS or host.endswith(R.SAFE_HOST_SUFFIXES)


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]  # prescan:ignore


def _is_private_ip(host: str) -> bool:
    """RFC 1918 / CGNAT / ULA only (ipaddress.is_private also counts reserved ranges)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in n for n in _PRIVATE_NETS if n.version == ip.version)


# --------------------------------------------------------------------------- #
# scanner
# --------------------------------------------------------------------------- #
class Scanner:
    def __init__(self, root: Path, config: Config, agent: str | None = None):
        self.root = root.resolve()
        self.cfg = config
        self.agent = agent
        self.coverage = coverage_for(agent, self.root)
        self.ignore = IgnoreMatcher.from_root(self.root, config.exclude, config.trust_project_config)
        disabled = set(config.disable_rules)
        self.content_rules = [r for r in R.CONTENT_RULES if r.id not in disabled]
        self.content_rules += [c.compile() for c in config.custom_rules if c.id not in disabled]
        self.file_rules = [r for r in R.FILE_RULES if r.id not in disabled]
        self.allow_values = [re.compile(p) for p in config.allow_values]
        self.url_checks = "internal-url" not in disabled
        self.blocklist = BlockList(config.block, config.internal_domains)

    # -- walking ------------------------------------------------------------ #
    def iter_files(self):
        skipped = 0
        self._symlinks: list[tuple[Path, str]] = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            d = Path(dirpath)
            rel_dir = d.relative_to(self.root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir + "/"
            keep = []
            for name in dirnames:
                full = d / name
                rel = rel_dir + name
                if name in DEFAULT_SKIP_DIRS or self.ignore.match(rel, True):
                    continue
                if full.is_symlink():
                    self._symlinks.append((full, rel))
                    continue
                if any((full / m).exists() for m in SKIP_DIR_MARKERS):
                    continue
                keep.append(name)
            dirnames[:] = sorted(keep)
            for name in sorted(filenames):
                rel = rel_dir + name
                if self.ignore.match(rel, False):
                    skipped += 1
                    continue
                if (d / name).is_symlink():
                    self._symlinks.append((d / name, rel))
                    continue
                yield d / name, rel
        self._skipped_by_ignore = skipped

    # -- entry point -------------------------------------------------------- #
    def scan(self) -> ScanResult:
        findings: list[Finding] = []
        scanned = skipped = 0
        self._skipped_by_ignore = 0
        for full, rel in self.iter_files():
            try:
                size = full.stat().st_size
            except OSError:
                size = 0
            findings += self._file_rule_findings(rel, size)
            if rel == CONFIG_NAME and self.cfg.trust_project_config:
                # prescan's own config lists the very names it blocks; don't flag it against itself.
                findings += self._config_exposure_findings(full)
                continue
            text = self._read(full)
            if text is None:
                skipped += 1
                continue
            scanned += 1
            findings += self._scan_text(rel, text)

        findings += self._symlink_findings()
        # .git/ is skipped, but its config often holds tokens in remote URLs (https://user:<token>@host).
        git_config = self.root / ".git" / "config"
        if git_config.is_file() and not self.ignore.match(".git/config", False):
            text = self._read(git_config)
            if text is not None:
                scanned += 1
                findings += self._scan_text(".git/config", text)
        unenforced = unenforced_ignore_file(self.agent, self.root)
        if unenforced:
            findings.append(Finding(
                rule_id="agent-ignore-not-enforced", category="config", severity=R.LOW,
                description=unenforced[1], path=unenforced[0], line=0, column=0, redacted="",
                snippet="", fingerprint=fingerprint("agent-ignore-not-enforced", unenforced[0], ""),
            ))

        findings = self._dedupe(findings)
        baseline = self._load_baseline()
        kept = [f for f in findings if f.fingerprint not in baseline]
        for f in kept:
            if self.coverage and f.category != "config" and self.coverage.covers(f.path):
                f.covered_by = self.coverage.label
                f.blocking = False
            else:
                f.blocking = self.cfg.blocks(f.severity)
        kept.sort(key=lambda f: (-R.SEVERITY_ORDER[f.severity], f.path, f.line))
        return ScanResult(
            root=str(self.root),
            findings=kept,
            files_scanned=scanned,
            files_skipped=skipped + self._skipped_by_ignore,
            baselined=len(findings) - len(kept),
            config_sources=list(self.cfg.sources),
            agent=self.agent,
        )

    def _read(self, full: Path) -> str | None:
        try:
            if full.is_symlink() or not full.is_file():
                return None
            if full.stat().st_size > self.cfg.max_file_size:
                return None
            data = full.read_bytes()
        except OSError:
            return None
        if _is_binary(data[:8192]):
            return None
        return data.decode("utf-8", errors="replace")

    # -- file-name rules ---------------------------------------------------- #
    def _symlink_findings(self) -> list[Finding]:
        """A link to a file outside the repo is invisible to prescan but readable by the agent."""
        out = []
        home = str(Path.home().resolve())
        for full, rel in self._symlinks:
            target = os.path.realpath(full)
            if target == str(self.root) or target.startswith(str(self.root) + os.sep):
                continue
            shown = "~" + target[len(home):] if target.startswith(home + os.sep) else target
            out.append(Finding(
                rule_id="symlink-outside-repo", category="sensitive-file", severity=R.MEDIUM,
                description="Symlink to a location outside the repo (not scanned, but readable by the agent)",
                path=rel, line=0, column=0, redacted=shown, snippet=f"-> {shown}",
                fingerprint=fingerprint("symlink-outside-repo", rel, target),
            ))
        return out

    def _file_rule_findings(self, rel: str, size: int = 0) -> list[Finding]:
        name = rel.rsplit("/", 1)[-1]
        out = []
        for rule in self.file_rules:
            if size < rule.min_size:
                continue
            def hit(g: str) -> bool:
                return fnmatch.fnmatchcase(rel, g) or rel.endswith("/" + g) if "/" in g \
                    else fnmatch.fnmatchcase(name, g)
            if any(hit(g) for g in rule.globs) and not any(hit(g) for g in rule.exclude_globs):
                out.append(Finding(
                    rule_id=rule.id, category=rule.category, severity=rule.severity,
                    description=rule.description, path=rel, line=0, column=0,
                    redacted="", snippet="(file contents should not be shared)",
                    fingerprint=fingerprint(rule.id, rel, ""),
                ))
                break
        return out

    # -- content rules ------------------------------------------------------ #
    def _scan_text(self, rel: str, text: str) -> list[Finding]:
        lower = text.lower()
        line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
        lines = text.split("\n")
        out: list[Finding] = []

        # (finding, raw value, is_secret, mask) — mask = (raw text, replacement) to hide in snippets
        pending: list[tuple[Finding, str, bool, tuple[str, str] | None]] = []

        def add(rule_id, category, severity, description, start, value, display=None, mask=None):
            ln = bisect.bisect_right(line_starts, start) - 1
            line = lines[ln] if ln < len(lines) else ""
            if INLINE_IGNORE.search(line):
                return
            if any(a.search(value) for a in self.allow_values):
                return
            f = Finding(
                rule_id=rule_id, category=category, severity=severity, description=description,
                path=rel, line=ln + 1, column=start - line_starts[ln] + 1,
                redacted=display if display is not None else redact(value), snippet="",
                fingerprint=fingerprint(rule_id, rel, value),
            )
            pending.append((f, value, display is None, mask))

        name = rel.rsplit("/", 1)[-1]
        for rule in self.content_rules:
            if rule.keywords and not any(k in lower for k in rule.keywords):
                continue
            if rule.path_globs and not any(fnmatch.fnmatchcase(name, g) for g in rule.path_globs):
                continue
            for m in rule.pattern.finditer(text):
                value = m.group(rule.secret_group) or ""
                if rule.min_entropy is not None:
                    threshold = max(rule.min_entropy, self.cfg.entropy_threshold) if rule.generic \
                        else rule.min_entropy
                    if shannon_entropy(value) < threshold:
                        continue
                if rule.generic and self._reject_generic(rule, m, value):
                    continue
                add(rule.id, rule.category, rule.severity, rule.description,
                    m.start(rule.secret_group), value, display=value if rule.show_match else None)

        self._scan_hosts(text, lower, add)
        self._scan_blocklist(text, lower, add)
        C.scan_everywhere(text, lower, add)
        classes = C.classify(rel, text)
        # Always called: package-manager files (.npmrc, pip.conf, ...) have no class but are checked
        # for private registries; every other rule inside checks the classes itself.
        C.scan_context(rel, text, classes, add, set(self.cfg.public_registries))

        # A pipeline rule and the generic `name = value` rule often catch the same value: keep the
        # stronger, more specific finding.
        specific = {(f.line, v) for f, v, _, _ in pending
                    if f.rule_id in ("ci-literal-env", "inline-cli-credential", "k8s-secret-data")}
        k8s = {(f.line, v) for f, v, _, _ in pending if f.rule_id == "k8s-secret-data"}
        pending[:] = [p for p in pending
                      if not (p[0].rule_id == "generic-secret-assignment" and (p[0].line, p[1]) in specific)
                      and not (p[0].rule_id == "ci-literal-env" and (p[0].line, p[1]) in k8s)]

        # Production files (values-prod.yaml, overlays/production/, environment: production):
        # what's merely medium elsewhere is high here.
        if classes and C.is_production(rel, text):
            for f, _, _, _ in pending:
                if f.severity == R.MEDIUM:
                    f.severity = R.HIGH
                    f.description += " [production file]"

        # Build snippets last, redacting *every* secret found on a line, so that e.g. an
        # internal-host finding never displays a password another rule matched on that line.
        hide_by_line: dict[int, dict[str, str]] = {}
        for f, value, is_secret, mask in pending:
            if is_secret and value:
                hide_by_line.setdefault(f.line, {})[value] = redact(value)
            if mask and mask[0] != mask[1]:
                hide_by_line.setdefault(f.line, {}).setdefault(mask[0], mask[1])
        for f, _, _, _ in pending:
            snippet = lines[f.line - 1]
            for raw, shown in sorted(hide_by_line.get(f.line, {}).items(), key=lambda kv: len(kv[0]),
                                     reverse=True):
                snippet = snippet.replace(raw, shown)
            snippet = snippet.strip()
            f.snippet = snippet if len(snippet) <= 160 else snippet[:157] + "..."
            out.append(f)
        return out

    def _reject_generic(self, rule: R.ContentRule, m: re.Match, value: str) -> bool:
        if _looks_generated_placeholder(value):
            return True
        if rule.id == "generic-secret-assignment":
            ls = m.string.rfind("\n", 0, m.start()) + 1
            le = m.string.find("\n", m.end())
            if (le if le != -1 else len(m.string)) - ls > self.cfg.generic_max_line_length:
                return True
            name = m.group(1).lower()
            v = value.lower()
            # `password = new_password`, `token: tokenValue` -> variable, not literal
            if any(k in v for k in ("password", "secret", "token", "apikey", "api_key")):
                return True
            # Unquoted identifier-ish values are almost always code (`token = getToken`)
            if not m.group("q") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) and \
                    not any(ch.isdigit() for ch in value):
                return True
            # `*_token_url`, `password_reset_path`, `public_key`... aren't secrets
            if re.search(r"(?:url|uri|path|file|dir|endpoint|name|type|length|len|header|field|param|"
                         r"public|regex|pattern|format|expires?|ttl|id)$", name):
                return True
            # URL values are handled by the URL rules
            if "://" in value:
                return True
        return False

    # -- URLs / hosts ------------------------------------------------------- #
    def _classify_host(self, host: str) -> tuple[str, str, str] | None:
        """Returns (rule_id, severity, description) or None."""
        host = host.lower().strip("[]").rstrip(".")
        if not host or _host_is_safe(host):
            return None
        blocked = self.blocklist.match_host(host)
        if blocked:
            return blocked
        if not self.url_checks:
            return None
        if _is_private_ip(host):
            return "private-ip", R.MEDIUM, "Private network IP address"
        tld_hit = next((t for t in R.INTERNAL_TLDS if host.endswith("." + t)), None)
        if tld_hit:
            return "internal-hostname", R.MEDIUM, f"Internal hostname (.{tld_hit})"
        if host.endswith(R.CLOUD_PRIVATE_SUFFIXES):
            return "cloud-private-endpoint", R.MEDIUM, "Managed infrastructure endpoint (DB/cache/queue/API)"
        if self.cfg.flag_sensitive_hostnames:
            labels = re.split(r"[.\-]", host)[:-1]  # ignore TLD
            hit = next((lab for lab in labels if lab in R.SENSITIVE_HOST_LABELS), None)
            if hit:
                return "sensitive-hostname", R.LOW, f"Hostname suggests production/internal tooling ('{hit}')"
        return None

    def _scan_hosts(self, text: str, lower: str, add) -> None:
        seen: set[tuple[int, str]] = set()

        def report(host: str, start: int, display: str, mask=None):
            c = self._classify_host(host)
            if not c or (start, c[0]) in seen:
                return
            seen.add((start, c[0]))
            rid, sev, desc = c
            category = "blocked" if rid in ("blocked-domain", "company-domain") else "internal-url"
            add(rid, category, sev, desc, start, display, display=display, mask=mask)

        for m in R.URL_RE.finditer(text):
            url = m.group(0).rstrip(".:;")
            try:
                parts = urlsplit(url.replace("jdbc:", "", 1) if url.lower().startswith("jdbc:") else url)
                host = parts.hostname or ""
            except ValueError:
                continue
            # Display scheme://host only — paths, query strings and credentials stay out of the report.
            short = f"{parts.scheme}://{host}"
            report(host, m.start(), short, mask=(url, short))
            glob = self.blocklist.match_url(url)
            if glob:
                shown = f"{short}{parts.path}"
                add("blocked-url", "blocked", self.blocklist.severity, f"Blocked URL ({glob})",
                    m.start(), shown, display=shown, mask=(url, shown))

        for m in R.HOST_PORT_RE.finditer(text):
            report(m.group(1), m.start(), m.group(0))

        if any(sfx in lower for sfx in R.CLOUD_PRIVATE_SUFFIXES):
            for m in R.CLOUD_HOST_RE.finditer(text):
                report(m.group(1), m.start(1), m.group(1))

        for m in R.IPV4_RE.finditer(text):
            ip = m.group(1)
            if all(0 <= int(o) <= 255 for o in ip.split(".")):
                # skip if this IP already reported as part of a URL on the same spot
                report(ip, m.start(), ip)

        # Bare hostnames anywhere (`host: db.acme.com`, `"api.acme.com"`) against the block list.
        for host, start in self.blocklist.bare_hosts(text, lower):
            report(host, start, host)

    def _scan_blocklist(self, text: str, lower: str, add) -> None:
        sev = self.blocklist.severity
        for name, value, start in self.blocklist.variables(text, lower):
            add("blocked-variable", "blocked", sev, f"Blocked variable assigned a value ({name})", start, value)
        for word, start in self.blocklist.keywords(text, lower):
            add("blocked-keyword", "blocked", sev, f"Blocked keyword ({word})", start, word, display=word)

    def _config_exposure_findings(self, full: Path) -> list[Finding]:
        """Warn when the in-repo config lists blocked names: agents can read that file too."""
        try:
            import tomllib
            block = tomllib.loads(full.read_text(encoding="utf-8")).get("block", {})
        except (OSError, ValueError):
            return []
        if not any(block.get(k) for k in ("domains", "urls", "variables", "keywords")):
            return []
        return [Finding(
            rule_id="config-exposes-blocklist", category="config", severity=R.LOW,
            description="[block] entries in the repo's .prescan.toml are readable by agents; "
                        "move them to the central config (prescan init)",
            path=CONFIG_NAME, line=0, column=0, redacted="", snippet="",
            fingerprint=fingerprint("config-exposes-blocklist", CONFIG_NAME, ""),
        )]

    # -- post-processing ---------------------------------------------------- #
    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """Drop an IP/host finding when a URL finding already covers the same line+value."""
        by_line: dict[tuple[str, int], list[Finding]] = {}
        for f in findings:
            by_line.setdefault((f.path, f.line), []).append(f)
        out = []
        seen_fp = set()
        for f in findings:
            if f.fingerprint in seen_fp and f.line == 0:
                continue
            if f.category in ("internal-url", "blocked") and f.line:
                same = by_line[(f.path, f.line)]
                if any(o is not f and o.rule_id == f.rule_id and f.redacted in o.redacted
                       and len(o.redacted) > len(f.redacted) for o in same):
                    continue
            seen_fp.add(f.fingerprint)
            out.append(f)
        return out

    def _load_baseline(self) -> set[str]:
        files = [baseline_path(self.root)]
        if self.cfg.trust_project_config:
            files.append(self.root / BASELINE_NAME)
        out: set[str] = set()
        for p in files:
            if not p.is_file():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            out |= {e["fingerprint"] for e in data.get("accepted", []) if "fingerprint" in e}
        return out


def write_baseline(root: Path, findings: list[Finding]) -> Path:
    p = baseline_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if p.is_file():
        try:
            for e in json.loads(p.read_text(encoding="utf-8")).get("accepted", []):
                existing[e["fingerprint"]] = e
        except (OSError, json.JSONDecodeError, KeyError):
            pass
    for f in findings:
        existing[f.fingerprint] = {
            "fingerprint": f.fingerprint, "rule_id": f.rule_id, "path": f.path, "line": f.line,
        }
    p.write_text(json.dumps({"project": str(root.resolve()),
                             "accepted": sorted(existing.values(), key=lambda e: (e["path"], e["line"]))},
                            indent=2) + "\n", encoding="utf-8")
    return p
