"""User-defined block list: domains, URLs, variable names and keywords from the [block] config."""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlsplit

from .config import BlockConfig

# Any dotted hostname-looking token. Candidates are only kept if they match a configured glob.
HOST_CANDIDATE_RE = re.compile(r"(?<![\w\-.])((?:[a-z0-9\-]+\.)+[a-z0-9\-]+)(?![\w\-])", re.IGNORECASE)

_LITERAL_VALUES = {"none", "null", "nil", "undefined", "true", "false", ""}
# References to *other* values (env lookups, interpolation, calls). Narrower than rules.CODE_REF_RE:
# a value like `api.acme.org` is a literal here, since the user explicitly named this variable.
_VAR_REF_RE = re.compile(
    r"(?i)^(?:process\.env|os\.environ|os\.getenv|getenv|env\(|ENV\[|import\.meta|secrets\.|vars\.)"
    r"|[()\[\]{}$]"
)


def _glob_literals(glob: str) -> list[str]:
    """Longest literal pieces of a glob, used as a cheap 'could this file match at all' filter."""
    pieces = [p for p in re.split(r"[*?\[\]]", glob.lower()) if p.strip(".")]
    return [max(pieces, key=len)] if pieces else []


def _name_glob_to_regex(glob: str) -> str:
    out = []
    for ch in glob:
        out.append("[A-Za-z0-9_]*" if ch == "*" else "[A-Za-z0-9_]" if ch == "?" else re.escape(ch))
    return "".join(out)


class BlockList:
    def __init__(self, block: BlockConfig, internal_domains: list[str]):
        self.severity = block.severity
        # (glob, rule_id, description)
        self.domains: list[tuple[str, str, str]] = []
        for g in block.domains:
            self.domains.append((g, "blocked-domain", f"Blocked domain ({g})"))
        for d in internal_domains:  # legacy setting: the domain and all its subdomains
            desc = f"Host under internal company domain ({d})"
            self.domains += [(d, "company-domain", desc), (f"*.{d}", "company-domain", desc)]
        self.domain_literals = {lit for g, _, _ in self.domains for lit in _glob_literals(g)}
        self.match_all_hosts = any(not _glob_literals(g) for g, _, _ in self.domains)

        self.urls = [u.lower() for u in block.urls]

        self.variables_re = None
        if block.variables:
            names = "|".join(_name_glob_to_regex(v) for v in block.variables)
            self.variables_re = re.compile(
                r"(?<![\w.$])(?:export[ \t]+|set[ \t]+|\$env:)?(?P<nq>[\"']?)(?P<name>" + names + r")(?P=nq)"
                r"[ \t]*(?::=|=>|=|:)(?![=>])[ \t]*"
                r"(?:(?P<q>[\"'`])(?P<qv>[^\"'`\n]*)(?P=q)|(?P<uv>[^\s\"'`,;#)\]}]+))",
                re.IGNORECASE,
            )
            self.variable_literals = None if any(not _glob_literals(v) for v in block.variables) else \
                {lit for v in block.variables for lit in _glob_literals(v)}

        self.keywords_re = None
        if block.keywords:
            alts = "|".join(re.escape(k) for k in sorted(block.keywords, key=len, reverse=True))
            self.keywords_re = re.compile(r"(?<![A-Za-z0-9])(?:" + alts + r")(?![A-Za-z0-9])", re.IGNORECASE)
            self.keyword_literals = {k.lower() for k in block.keywords}

    # -- hosts / URLs ------------------------------------------------------- #
    def match_host(self, host: str) -> tuple[str, str, str] | None:
        host = host.lower().rstrip(".")
        for glob, rule_id, desc in self.domains:
            if fnmatch.fnmatchcase(host, glob):
                return rule_id, self.severity, desc
        return None

    def match_url(self, url: str) -> str | None:
        """Returns the matching URL glob, if any. Userinfo is stripped before matching."""
        if not self.urls:
            return None
        try:
            p = urlsplit(url)
        except ValueError:
            return None
        netloc = p.netloc.rsplit("@", 1)[-1]
        clean = f"{p.scheme}://{netloc}{p.path}" + (f"?{p.query}" if p.query else "")
        candidates = (clean.lower(), clean.lower().split("://", 1)[-1])
        for glob in self.urls:
            if any(fnmatch.fnmatchcase(c, glob) for c in candidates):
                return glob
        return None

    def bare_hosts(self, text: str, lower: str):
        """Yields (host, start) for hostname tokens anywhere in the text that may match a domain glob."""
        if not self.domains:
            return
        if not self.match_all_hosts and not any(lit in lower for lit in self.domain_literals):
            return
        for m in HOST_CANDIDATE_RE.finditer(text):
            host = m.group(1)
            s = m.start()
            if s and text[s - 1] == "@":
                # user@acme.com is an email address, unless it's scheme://user:pass@host
                left = text[max(0, s - 200):s]
                token = re.split(r"[\s\"'`<>(]", left)[-1]
                if "://" not in token:
                    continue
            yield host, s

    # -- variables / keywords ---------------------------------------------- #
    def variables(self, text: str, lower: str):
        """Yields (name, value, value_start) for blocked variable names assigned a literal."""
        if not self.variables_re:
            return
        if self.variable_literals is not None and not any(l in lower for l in self.variable_literals):
            return
        for m in self.variables_re.finditer(text):
            if m.group("q") is not None:
                value, start = m.group("qv"), m.start("qv")
            else:
                value, start = m.group("uv"), m.start("uv")
            if value.lower() in _LITERAL_VALUES or _VAR_REF_RE.search(value):
                continue
            yield m.group("name"), value, start

    def keywords(self, text: str, lower: str):
        if not self.keywords_re or not any(k in lower for k in self.keyword_literals):
            return
        for m in self.keywords_re.finditer(text):
            yield m.group(0), m.start()
