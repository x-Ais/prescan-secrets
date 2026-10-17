"""gitignore-syntax matching, used for `exclude` and for agent ignore files (.bobignore, ...).

Implements the gitignore rules: comments, `\\` escapes, trailing-space trimming, `!` negation,
trailing `/` (directories only), anchoring (a `/` anywhere but the end), `*`, `?`, `[...]`, and
`**` (leading `**/`, trailing `/**`, middle `/**/`).

Tools differ on two points:
  * git never re-includes a file whose parent directory is excluded, while some libraries let a
    later `!pattern` re-include it;
  * case sensitivity (git on macOS defaults to core.ignorecase=true, many libraries ignore case).
`is_ignored_everywhere()` only answers True when every combination agrees, which is what a
"the agent can't read this" decision needs: a wrong True would be a silent fail-open.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class _Rule:
    regex: re.Pattern
    negated: bool
    dir_only: bool


def _translate(pat: str) -> str:
    """Anchored gitignore glob (no leading `/`) -> regex body."""
    out, i, n = [], 0, len(pat)
    while i < n:
        at_segment_start = i == 0 or pat[i - 1] == "/"
        if at_segment_start and pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif at_segment_start and pat[i:] == "**":
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            while i < n and pat[i] == "*":  # `**` not at a segment boundary behaves like `*`
                i += 1
            out.append("[^/]*")
            continue
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        elif pat[i] == "[":
            j = i + 1
            if j < n and pat[j] in "!^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 1
            if j >= n:  # unterminated class: literal `[`
                out.append(re.escape("["))
                i += 1
            else:
                body = pat[i + 1:j]
                if body[:1] in ("!", "^"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        elif pat[i] == "\\" and i + 1 < n:
            out.append(re.escape(pat[i + 1]))
            i += 2
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return "".join(out)


def _parse_line(raw: str, ignorecase: bool = False) -> _Rule | None:
    line = raw.rstrip("\n").rstrip("\r")
    # trailing spaces are ignored unless escaped
    while line.endswith(" ") and not line.endswith("\\ "):
        line = line[:-1]
    if not line or line.startswith("#"):
        return None
    negated = False
    if line.startswith("!"):
        negated, line = True, line[1:]
    elif line.startswith("\\!") or line.startswith("\\#"):
        line = line[1:]
    dir_only = line.endswith("/") and not line.endswith("\\/")
    if dir_only:
        line = line.rstrip("/")
    if not line:
        return None
    anchored = "/" in line
    line = line.lstrip("/")
    body = _translate(line)
    if not anchored:
        body = "(?:.*/)?" + body
    try:
        return _Rule(re.compile("^" + body + "$", re.IGNORECASE if ignorecase else 0), negated, dir_only)
    except re.error:
        # A pattern we can't translate must never make a file count as ignored.
        return _Rule(re.compile(r"(?!)"), negated, dir_only)


class GitIgnore:
    def __init__(self, lines: list[str], ignorecase: bool = False):
        self.lines = list(lines)
        self.rules = [r for r in (_parse_line(line, ignorecase) for line in lines) if r]
        self._other_case: GitIgnore | None = None
        self.ignorecase = ignorecase

    def __bool__(self) -> bool:
        return bool(self.rules)

    def _last_match(self, path: str, is_dir: bool) -> bool | None:
        """True = ignored, False = re-included by `!`, None = no rule matched."""
        result = None
        for r in self.rules:
            if r.dir_only and not is_dir:
                continue
            if r.regex.match(path):
                result = not r.negated
        return result

    def is_ignored_git(self, rel: str, is_dir: bool = False) -> bool:
        """git semantics: an excluded parent directory excludes everything below it, for good."""
        parts = rel.strip("/").split("/")
        for k in range(1, len(parts)):
            if self._last_match("/".join(parts[:k]), True):
                return True
        return bool(self._last_match(rel, is_dir))

    def is_ignored_lenient(self, rel: str, is_dir: bool = False) -> bool:
        """Library semantics: rules apply in order to the path and its parent dirs; last match wins,
        so a later `!pattern` can re-include a file inside an excluded directory."""
        parts = rel.strip("/").split("/")
        candidates = [("/".join(parts[:k]), True) for k in range(1, len(parts))] + [(rel, is_dir)]
        result = None
        for r in self.rules:
            for path, d in candidates:
                if (d or not r.dir_only) and r.regex.match(path):
                    result = not r.negated
                    break
        return bool(result)

    def is_ignored_everywhere(self, rel: str, is_dir: bool = False) -> bool:
        if self._other_case is None:
            self._other_case = GitIgnore(self.lines, ignorecase=not self.ignorecase)
        return all(g.is_ignored_git(rel, is_dir) and g.is_ignored_lenient(rel, is_dir)
                   for g in (self, self._other_case))
