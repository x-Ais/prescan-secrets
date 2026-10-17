"""Tests. Fake secrets are assembled at runtime so this file never trips the scanner itself."""

import base64
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Never touch the developer's real ~/.config/prescan: tests get a throwaway prescan home.
os.environ["PRESCAN_HOME"] = tempfile.mkdtemp(prefix="prescan-home-")
# ...and never read the developer's real Claude Code settings for deny rules.
os.environ["CLAUDE_CONFIG_DIR"] = tempfile.mkdtemp(prefix="prescan-claude-")

from prescan.cli import main  # noqa: E402
from prescan.config import BlockConfig, Config, load_config  # noqa: E402
from prescan.scanner import Scanner, redact  # noqa: E402

J = "".join  # join pieces so literal secrets never appear in this file

AWS_ID = J(["AKIA", "Z3QXR7TLMN2PB4WK"])
GH = J(["ghp_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"])
STRIPE = J(["sk_", "live_", "51HxQ2bLkYv9TzR8mWp3NcD"])
SLACK_HOOK = J(["https://hooks.", "slack.com/services/T0ABC1234/B0DEF5678/", "q8Wz3Lm9Kp2Rt7Yx4Nv6Bc1D"])
PG_PASS = J(["Pz9", "#kLq2vX"])


def make_repo(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="prescan-tmp-"))
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return d


def scan(files: dict[str, str], **cfg) -> list:
    return Scanner(make_repo(files), Config(**cfg)).scan()


def ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


class TestSecrets(unittest.TestCase):
    def test_known_tokens(self):
        r = scan({"src/app.py": f"""
            AWS = "{AWS_ID}"
            gh = '{GH}'
            STRIPE_KEY = "{STRIPE}"
            notify = "{SLACK_HOOK}"
        """})
        self.assertTrue({"aws-access-key-id", "github-token", "stripe-live-key", "slack-webhook"} <= ids(r))
        self.assertFalse(r.ok)

    def test_private_key_block(self):
        r = scan({"deploy/key.txt": J(["-----BEGIN ", "OPENSSH PRIVATE KEY-----\nabc\n"])})
        self.assertIn("private-key", ids(r))

    def test_connection_string_with_password(self):
        r = scan({"config/db.yml": f"url: postgres://app:{PG_PASS}@db.prod.acme.io:5432/main\n"})
        self.assertIn("credentials-in-url", ids(r))

    def test_connection_string_with_empty_username(self):
        pw = J(["r3d1s", "P4ss"])
        r = scan({".env.example": f"REDIS_URL=redis://:{pw}@10.0.3.17:6379/0\n"})
        self.assertTrue({"credentials-in-url", "private-ip"} <= ids(r))
        dumped = json.dumps([f.to_dict() for f in r.findings])
        self.assertNotIn(pw, dumped)
        ip = next(f for f in r.findings if f.rule_id == "private-ip")
        self.assertEqual(ip.redacted, "redis://10.0.3.17")  # scheme://host only

    def test_generic_assignment(self):
        r = scan({"settings.py": J(['DB_PASSWORD = "', "Xk82!pQz", 'Lm4vT9"\n'])})
        self.assertIn("generic-secret-assignment", ids(r))

    def test_generic_ignores_code_and_placeholders(self):
        r = scan({"app.py": """
            password = os.environ["DB_PASSWORD"]
            token = get_token()
            api_key = settings.API_KEY
            secret: "${MY_SECRET}"
            password = "changeme"
            API_KEY=your_api_key_here
            password_reset_url = "/auth/reset/confirm"
            new_password = old_password
            url: postgres://user:password@localhost:5432/dev
        """})
        self.assertEqual([], [f for f in r.findings if f.category == "secret"], r.findings)

    def test_regressions_from_real_repos(self):
        long_line = "var a=1;" * 80 + 'x.token="Zq81mXv0Lw3";'
        r = scan({
            "client.py": "self._auth: AuthBase = auth or PasswordAuth()\n",
            "api.js": "fetch(u, { credentials: 'same-origin' })\n",
            "token.py": "Basic token types.\n\n:copyright: Copyright 2006 by the team\n",
            "dist/app.min.js": long_line,
            "net.py": "mask 255.255.255.0 and 127.0.1.1\n",
        })
        self.assertEqual([], r.findings)

    def test_npmrc_token(self):
        r = scan({".npmrc": J(["//registry.npmjs.org/:_authToken=", "aB3dE5fG7hJ9kL1mN3pQ"])})
        self.assertIn("npmrc-auth", ids(r))

    def test_secret_never_printed(self):
        r = scan({"a.py": f'url = "postgres://app:{PG_PASS}@10.0.3.7:5432/main"\n'})
        dumped = json.dumps([f.to_dict() for f in r.findings])
        self.assertNotIn(PG_PASS, dumped)
        self.assertNotIn(AWS_ID, json.dumps([f.to_dict() for f in
                                             scan({"b.py": f"k='{AWS_ID}'"}).findings]))

    def test_redact(self):
        self.assertEqual(redact("short"), "*****")
        self.assertTrue(redact(AWS_ID).startswith("AKIA…"))
        self.assertNotIn(AWS_ID[4:], redact(AWS_ID))


class TestFiles(unittest.TestCase):
    def test_env_files(self):
        r = scan({".env": "A=1\n", "svc/.env.production": "A=1\n", ".env.example": "A=\n"})
        flagged = {f.path for f in r.findings if f.rule_id == "env-file"}
        self.assertEqual(flagged, {".env", "svc/.env.production"})

    def test_key_and_state_files(self):
        r = scan({"certs/server.key": "x", "infra/terraform.tfstate": "{}", ".aws/credentials": "x",
                  "id_ed25519": "x", "id_ed25519.pub": "ssh-ed25519 AAAA",
                  "certs/ca-bundle.pem": "-----BEGIN CERTIFICATE-----\nMIIB\n"})
        self.assertEqual({f.path for f in r.findings},
                         {"certs/server.key", "infra/terraform.tfstate", ".aws/credentials", "id_ed25519"})

    def test_skips_dependencies(self):
        r = scan({"node_modules/pkg/.env": "A=1", ".venv/x/.env": "A=1"})
        self.assertTrue(r.ok)


class TestInternalUrls(unittest.TestCase):
    def test_private_ip_and_internal_tld(self):
        r = scan({"conf.yaml": """
            api: http://10.12.0.5:8080/v1
            cache: redis.billing.internal:6379
            ok: http://localhost:3000
            ok2: https://example.com/docs
            version: 3.10.0.1beta
        """})
        self.assertEqual({"private-ip", "internal-hostname"}, ids(r))

    def test_company_domain(self):
        r = scan({"client.ts": 'const API = "https://payments.acme-corp.io/api";\n'
                               'const mail = "jane@acme-corp.io";\n'},
                 internal_domains=["acme-corp.io"])
        hits = [f for f in r.findings if f.rule_id == "company-domain"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "high")

    def test_cloud_endpoint(self):
        r = scan({"db.ts": 'host = "orders.c9akciq32.eu-west-1.rds.amazonaws.com"\n'
                           'url = "https://orders.c9akciq32.eu-west-1.rds.amazonaws.com"'})
        self.assertIn("cloud-private-endpoint", ids(r))

    def test_cloud_endpoint_without_scheme(self):
        r = scan({"config/settings.yaml": """
            cache:
              host: my-cache.abc123.0001.use1.cache.amazonaws.com
            db: orders.c9akciq32.eu-west-1.rds.amazonaws.com:5432
            url: https://orders.c9akciq32.eu-west-1.rds.amazonaws.com/x
            dsn: postgres://svc:pw@orders.c9akciq32.eu-west-1.rds.amazonaws.com/main
            ignored: other.c9akciq32.eu-west-1.rds.amazonaws.com  # prescan:ignore
            notcloud: my-cache.abc123.cache.amazonaws.com.evil.test
        """})
        hits = [(f.line, f.redacted) for f in r.findings if f.rule_id == "cloud-private-endpoint"]
        self.assertEqual(hits, [
            (3, "my-cache.abc123.0001.use1.cache.amazonaws.com"),
            (4, "orders.c9akciq32.eu-west-1.rds.amazonaws.com"),
            (5, "https://orders.c9akciq32.eu-west-1.rds.amazonaws.com"),
            (6, "postgres://orders.c9akciq32.eu-west-1.rds.amazonaws.com"),
        ])  # one finding per line: URL hosts aren't reported twice

    def test_prod_hostname_is_warning_only(self):
        r = scan({"README.md": "Dashboard: https://grafana.prod.somecompany.com\n"})
        self.assertEqual(ids(r), {"sensitive-hostname"})
        self.assertTrue(r.ok)  # low severity doesn't block with default fail_on=medium


def block_scan(files: dict[str, str], **block) -> list:
    return scan(files, block=BlockConfig(**block))


class TestBlockList(unittest.TestCase):
    def test_exact_domain(self):
        r = block_scan({"a.ts": """
            const A = "https://myprivate.domaine/api";
            host: myprivate.domaine
            other: api.myprivate.domaine
        """}, domains=["myprivate.domaine"])
        hits = [(f.line, f.rule_id) for f in r.findings]
        self.assertEqual(hits, [(2, "blocked-domain"), (3, "blocked-domain")])
        self.assertTrue(all(f.severity == "high" for f in r.findings))

    def test_wildcard_domain(self):
        r = block_scan({"conf.yml": """
            api: https://api.privatedomaine/v1
            db: db.eu.prod.privatedomaine:5432
            apex: privatedomaine
            contact: ops@team.privatedomaine
            dsn: postgres://svc:pw@pg.privatedomaine/main
            unrelated: notprivatedomaine.com
        """}, domains=["*.privatedomaine"])
        self.assertEqual(sorted(f.line for f in r.findings if f.rule_id == "blocked-domain"), [2, 3, 6])

    def test_glob_inside_domain(self):
        r = block_scan({"a.py": 'X = "db-orders.acme.net"\nY = "web.acme.net"\n'}, domains=["db-*.acme.*"])
        self.assertEqual([f.line for f in r.findings], [1])

    def test_url_glob(self):
        r = block_scan({"a.md": """
            https://partner.com/internal/reports?id=3
            https://bot:pw@partner.com/internal/x
            https://partner.com/public/docs
        """}, urls=["https://partner.com/internal/*"])
        self.assertEqual(sorted(f.line for f in r.findings), [2, 3])
        self.assertNotIn("id=3", json.dumps([f.to_dict() for f in r.findings]))

    def test_url_glob_without_scheme(self):
        r = block_scan({"a.md": "see http://partner.com/internal/a\n"}, urls=["partner.com/internal/*"])
        self.assertEqual(ids(r), {"blocked-url"})

    def test_variables(self):
        value = J(["eu-", "west-", "3b"])
        r = block_scan({
            ".env.example": f"PROD_API_HOST=api.someplace.org\nexport PROD_TOKEN=\"abc123\"\n",
            "cfg.json": f'{{"PROD_REGION": "{value}"}}\n',
            "settings.py": "orders_db_password = 'x1y2z3'\n",
        }, variables=["PROD_*", "*_DB_PASSWORD"])
        got = sorted((f.path, f.line) for f in r.findings)
        self.assertEqual(got, [(".env.example", 1), (".env.example", 2), ("cfg.json", 1), ("settings.py", 1)])
        self.assertNotIn(value, json.dumps([f.to_dict() for f in r.findings]))  # values are redacted

    def test_variables_ignore_references(self):
        r = block_scan({"app.py": """
            PROD_HOST = os.environ["PROD_HOST"]
            host = process.env.PROD_HOST
            if PROD_MODE == "on": pass
            print($PROD_X)
            PROD_FLAG = None
            PROD_URL: ${PROD_URL}
        """}, variables=["PROD_*"])
        self.assertEqual([], r.findings)

    def test_keywords(self):
        r = block_scan({"notes.md": "Kickoff for project falcon.\nWe like falconry.\n"},
                       keywords=["Project Falcon"])
        self.assertEqual([(f.line, f.rule_id) for f in r.findings], [(1, "blocked-keyword")])

    def test_severity_override(self):
        r = block_scan({"a.txt": "codename-x\n"}, keywords=["codename-x"], severity="low")
        self.assertTrue(r.ok)
        self.assertEqual(len(r.findings), 1)


def central(toml: str) -> Path:
    """Write a central config file and return its path (passed explicitly, so tests don't share state)."""
    p = Path(tempfile.mkdtemp(prefix="prescan-cfg-")) / "config.toml"
    p.write_text(textwrap.dedent(toml))
    return p


class TestCentralConfig(unittest.TestCase):
    def test_project_overrides_apply_only_to_matching_paths(self):
        root = make_repo({"a.py": 'U = "https://api.secretcorp.io"  # bluebird\n'})
        other = make_repo({"a.py": 'U = "https://api.secretcorp.io"  # bluebird\n'})
        cfg_path = central(f"""
            [block]
            domains = ["*.secretcorp.io"]

            [[project]]
            path = "{root}"
            fail_on = "high"
            [project.block]
            keywords = ["bluebird"]

            [[project]]
            path = "/nowhere/else"
            disable_rules = ["blocked-domain"]
        """)
        cfg = load_config(root, cfg_path)
        self.assertEqual((cfg.fail_on, cfg.block.domains, cfg.block.keywords, cfg.disable_rules),
                         ("high", ["*.secretcorp.io"], ["bluebird"], []))
        self.assertEqual(ids(Scanner(root, cfg).scan()), {"blocked-domain", "blocked-keyword"})
        other_cfg = load_config(other, cfg_path)
        self.assertEqual((other_cfg.fail_on, other_cfg.block.keywords), ("medium", []))
        self.assertEqual(ids(Scanner(other, other_cfg).scan()), {"blocked-domain"})

    def test_project_path_covers_subdirs_and_globs(self):
        base = make_repo({"clients/acme/svc/a.txt": "x"})
        svc = base / "clients" / "acme" / "svc"
        for pattern in (str(base / "clients"), str(base / "clients" / "*")):
            cfg = load_config(svc, central(f'[[project]]\npath = "{pattern}"\nfail_on = "low"\n'))
            self.assertEqual(cfg.fail_on, "low", pattern)

    def test_repo_files_cannot_weaken_the_gate_by_default(self):
        root = make_repo({
            ".env": "A=1",
            ".prescanignore": "*\n",
            ".prescan.toml": 'fail_on = "high"\ndisable_rules = ["env-file"]\nexclude = ["**"]\n',
        })
        Path(root / ".prescan-baseline.json").write_text(json.dumps(
            {"accepted": [{"fingerprint": f.fingerprint} for f in Scanner(root, Config()).scan().findings]}))
        r = Scanner(root, load_config(root, central(""))).scan()
        self.assertFalse(r.ok)
        self.assertIn(".env", {f.path for f in r.findings})

    def test_trusted_repo_config_adds_but_cannot_loosen_fail_on(self):
        root = make_repo({
            "fixtures/.env": "A=1", ".prescanignore": "fixtures/\n",
            ".prescan.toml": 'fail_on = "high"\n[block]\nkeywords = ["bluebird"]\n',
            "a.yml": "host: http://10.0.0.8\nname: bluebird\n",
        })
        cfg = load_config(root, central('trust_project_config = true\n'))
        self.assertEqual((cfg.fail_on, cfg.block.keywords), ("medium", ["bluebird"]))
        r = Scanner(root, cfg).scan()
        self.assertEqual({(f.path, f.rule_id) for f in r.findings}, {
            ("a.yml", "private-ip"), ("a.yml", "blocked-keyword"),
            (".prescan.toml", "config-exposes-blocklist"),  # warning; the config isn't content-scanned
        })

    def test_starter_config_structure(self):
        import tomllib
        from prescan.cli import STARTER_CONFIG
        d = tomllib.loads(STARTER_CONFIG)
        self.assertTrue({"fail_on", "internal_domains", "exclude", "disable_rules", "allow_values",
                         "trust_project_config"} <= set(d))
        self.assertEqual(set(d["block"]), {"domains", "urls", "variables", "keywords", "severity"})
        self.assertFalse(d["trust_project_config"])

    def test_bad_config(self):
        root = make_repo({"a.txt": "x"})
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["scan", str(root), "--config", str(central('[block]\ndomains = "x.com"\n'))]), 2)
        self.assertIn("must be a list", err.getvalue())


class TestSuppression(unittest.TestCase):
    def test_inline_ignore(self):
        r = scan({"a.py": f'k = "{AWS_ID}"  # prescan:ignore\n'})
        self.assertTrue(r.ok)

    def test_central_exclude(self):
        root = make_repo({"fixtures/.env": "A=1"})
        cfg = load_config(root, central(f'[[project]]\npath = "{root}"\nexclude = ["fixtures/"]\n'))
        self.assertTrue(Scanner(root, cfg).scan().ok)

    def test_baseline_is_stored_centrally(self):
        from prescan.config import baseline_path
        root = make_repo({".env": "A=1"})
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["scan", str(root)]), 1)
            self.assertEqual(main(["baseline", str(root)]), 0)
            self.assertEqual(main(["scan", str(root)]), 0)
            (root / "new.key").write_text("x")
            self.assertEqual(main(["scan", str(root)]), 1)  # new findings still block
        self.assertFalse((root / ".prescan-baseline.json").exists())
        self.assertTrue(baseline_path(root).is_file())
        self.assertTrue(str(baseline_path(root)).startswith(os.environ["PRESCAN_HOME"]))

    def test_fail_on_high(self):
        root = make_repo({"a.yml": "host: http://10.0.0.8\n"})
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["scan", str(root)]), 1)
            self.assertEqual(main(["scan", str(root), "--fail-on", "high"]), 0)


class TestGitIgnore(unittest.TestCase):
    PATTERNS = ["# comment", "*.log", "!keep.log", "/build", "docs/**/*.md", "secret/", "!secret/public.txt",
                "**/tmp/**", "a?c.txt", "[Tt]est*.py", "\\#hash", "trailing   ", "nested/dir/", "foo/**",
                "*.LOG", "!/root-only.txt", "deep/**/x"]
    PATHS = ["x.log", "keep.log", "sub/keep.log", "build", "build/x", "sub/build", "docs/a.md", "docs/b/c/d.md",
             "docs/x.txt", "secret/k", "secret/public.txt", "a/secret/k", "tmp/x", "a/tmp/b/c", "abc.txt",
             "ac.txt", "Test1.py", "test2.py", "best.py", "#hash", "trailing", "nested/dir/x", "nested/dirx",
             "foo/a", "foo/a/b", "X.LOG", "deep/x", "deep/a/b/x", "deep/a/y"]

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_matches_git_check_ignore(self):
        from prescan.gitignore import GitIgnore
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        subprocess.run(["git", "config", "core.ignorecase", "false"], cwd=d, check=True)
        (d / ".gitignore").write_text("\n".join(self.PATTERNS) + "\n")
        for sub in ("build", "nested/dir", "foo", "secret"):
            (d / sub).mkdir(parents=True)
        out = subprocess.run(["git", "check-ignore", "--no-index", *self.PATHS], cwd=d,
                             capture_output=True, text=True).stdout.split()
        g = GitIgnore(self.PATTERNS)
        self.assertEqual(sorted(p for p in self.PATHS if g.is_ignored_git(p)), sorted(out))

    def test_ambiguous_cases_are_not_ignored_everywhere(self):
        from prescan.gitignore import GitIgnore
        g = GitIgnore(self.PATTERNS)
        self.assertTrue(g.is_ignored_git("secret/public.txt"))       # git: parent dir wins
        self.assertFalse(g.is_ignored_lenient("secret/public.txt"))  # libraries: `!` re-includes
        self.assertFalse(g.is_ignored_everywhere("secret/public.txt"))
        self.assertFalse(g.is_ignored_everywhere("keep.log"))        # `*.LOG` only matches ignoring case
        self.assertTrue(g.is_ignored_everywhere("x.log"))


class TestAgentCoverage(unittest.TestCase):
    def repo(self, **extra):
        return make_repo({".env": "A=1\n", "src/app.py": f'K = "{AWS_ID}"\n', **extra})

    def test_bobignore_covers_only_for_bob(self):
        root = self.repo(**{".bobignore": ".env\n"})
        bob = Scanner(root, Config(), agent="bob").scan()
        self.assertEqual({f.path for f in bob.covered}, {".env"})
        self.assertEqual({f.path for f in bob.blocking}, {"src/app.py"})
        for agent in (None, "gemini", "codex", "claude-code"):
            r = Scanner(root, Config(), agent=agent).scan()
            self.assertIn(".env", {f.path for f in r.blocking}, agent)

    def test_fully_covered_repo_passes(self):
        root = self.repo(**{".bobignore": ".env\nsrc/\n"})
        self.assertTrue(Scanner(root, Config(), agent="bob").scan().ok)

    def test_negation_and_case_are_conservative(self):
        root = make_repo({
            "secrets/a.txt": f"{GH}\n", "secrets/public.txt": f"{GH}\n", "conf/.env": "A=1\n",
            "deploy/staging.env": "A=1\n", "deploy/prod.env": "A=1\n",
            ".bobignore": "secrets/\n!secrets/public.txt\nconf/*.ENV\ndeploy/*.env\n!deploy/PROD.env\n",
        })
        r = Scanner(root, Config(), agent="bob").scan()
        self.assertEqual({f.path for f in r.covered}, {"secrets/a.txt", "deploy/staging.env"})
        # public.txt: re-included or not depending on the tool. conf/.env: only matches ignoring case.
        # prod.env: `!PROD.env` re-includes it only for case-insensitive tools.
        self.assertEqual({f.path for f in r.blocking}, {"secrets/public.txt", "conf/.env", "deploy/prod.env"})

    def test_geminiignore(self):
        root = self.repo(**{".geminiignore": "/.env\n/src/\n"})
        self.assertTrue(Scanner(root, Config(), agent="gemini").scan().ok)
        self.assertFalse(Scanner(root, Config(), agent="bob").scan().ok)

    def test_claude_deny_rules(self):
        settings = {"permissions": {"deny": ["Read(./.env)", "Read(**/*.key)", "Read(/conf/**)", "Edit(src/**)"]}}
        root = make_repo({
            ".env": "A=1\n", "sub/.env": "A=1\n", "certs/a/server.key": "x", "conf/.env.prod": "A=1\n",
            "src/app.py": f'K = "{AWS_ID}"\n', ".claude/settings.json": json.dumps(settings),
        })
        r = Scanner(root, Config(), agent="claude-code").scan()
        self.assertEqual({f.path for f in r.covered}, {".env", "certs/a/server.key"})
        # sub/.env: `./.env` is anchored at the root. conf/: `/x` form is ambiguous. src/: Edit, not Read.
        self.assertEqual({f.path for f in r.blocking}, {"sub/.env", "conf/.env.prod", "src/app.py"})

    def test_claude_user_settings_and_bare_read(self):
        user = Path(os.environ["CLAUDE_CONFIG_DIR"]) / "settings.json"
        root = self.repo()
        try:
            user.write_text(json.dumps({"permissions": {"deny": [f"Read(//{str(root.resolve()).lstrip('/')}/**)"]}}))
            self.assertTrue(Scanner(root, Config(), agent="claude-code").scan().ok)
            user.write_text(json.dumps({"permissions": {"deny": ["Read"]}}))
            self.assertTrue(Scanner(root, Config(), agent="claude-code").scan().ok)
        finally:
            user.unlink()

    def test_claudeignore_is_reported_not_trusted(self):
        root = self.repo(**{".claudeignore": ".env\nsrc/\n"})
        r = Scanner(root, Config(), agent="claude-code").scan()
        self.assertIn(".env", {f.path for f in r.blocking})
        notice = [f for f in r.findings if f.rule_id == "agent-ignore-not-enforced"]
        self.assertEqual((len(notice), notice[0].blocking), (1, False))

    def test_report_lists_covered_files(self):
        from prescan.report import render_text
        root = self.repo(**{".bobignore": ".env\n"})
        text = render_text(Scanner(root, Config(), agent="bob").scan(), color=False)
        self.assertIn("Covered by .bobignore", text)
        self.assertIn(".env  [env-file]", text)

    def test_agent_from_command(self):
        from prescan.agents import agent_for_command
        self.assertEqual([agent_for_command(c) for c in ("claude", "/usr/local/bin/bob", "gemini", "codex",
                                                          "cursor-agent")],
                         ["claude-code", "bob", "gemini", "codex", None])


class TestPhase1(unittest.TestCase):
    def test_git_config_token(self):
        r = scan({".git/config": f'[remote "origin"]\n\turl = https://me:{GH}@github.com/acme/app.git\n',
                  ".git/objects/ab/cd": f"{AWS_ID}"})
        self.assertEqual({(f.path, f.rule_id) for f in r.findings},
                         {(".git/config", "github-token"), (".git/config", "credentials-in-url")})

    def test_idea_is_scanned(self):
        pw = J(["Xk82", "pQzLm4"])
        r = scan({".idea/dataSources.local.xml": f"<password>{pw}</password>\n"})
        self.assertIn("xml-secret", ids(r))

    def test_symlink_outside_repo(self):
        outside = Path(tempfile.mkdtemp()) / "credentials"
        outside.write_text("x")
        root = make_repo({"real.txt": "hi"})
        (root / "aws").symlink_to(outside)
        (root / "inside").symlink_to(root / "real.txt")
        (root / "linkdir").symlink_to(outside.parent, target_is_directory=True)
        r = Scanner(root, Config()).scan()
        self.assertEqual(sorted((f.path, f.rule_id) for f in r.findings),
                         [("aws", "symlink-outside-repo"), ("linkdir", "symlink-outside-repo")])

    def test_enterprise_credential_files(self):
        names = ["svc.keytab", "key.kdb", "key.sth", "wallet/cwallet.sso", ".pypirc", "trace.har",
                 "prod.postman_environment.json", ".vault_pass", "ansible/vault-password.txt"]
        r = scan({n: "x" for n in names} | {"tnsnames.ora": "x", "heap.hprof": "x", "core.1234": "x", "core.js": "x"})
        self.assertEqual({f.path for f in r.findings if f.rule_id == "credentials-file"}, set(names))
        self.assertEqual({(f.path, f.rule_id) for f in r.findings if f.rule_id != "credentials-file"},
                         {("tnsnames.ora", "infra-config-file"), ("heap.hprof", "memory-dump"),
                          ("core.1234", "memory-dump")})

    def test_xml_secrets(self):
        pw = J(["Xk82", "pQzLm4"])
        r = scan({"settings.xml": f"""
            <server><username>deploy</username><password>{pw}</password></server>
            <server><password>${{env.DEPLOY_PASS}}</password></server>
            <server><password>{{COQLCE6DU6GtcS5P=}}</password></server>
            <property><name>db.password</name>
              <value>{pw}</value></property>
            <property><name>db.url</name><value>jdbc:h2:mem</value></property>
        """})
        self.assertEqual(sorted((f.rule_id, f.line) for f in r.findings),
                         [("xml-name-value-secret", 6), ("xml-secret", 2)])  # reported on the value's line
        self.assertNotIn(pw, json.dumps([f.to_dict() for f in r.findings]))

    def test_classification_labels(self):
        r = scan({"doc.md": """
            CONFIDENTIAL: do not share
            This design is Internal Use Only.
            Diffusion restreinte
            if level == Level.CONFIDENTIAL: pass
            labels = ["CONFIDENTIAL", "PUBLIC"]
            CONFIDENTIAL = 3
            is_confidential = True
            confidential info in lowercase prose
        """})
        self.assertEqual(sorted((f.line, f.redacted) for f in r.findings),
                         [(2, "CONFIDENTIAL"), (3, "Internal Use Only"), (4, "Diffusion restreinte")])

    def test_data_files_are_warnings(self):
        r = scan({"exports/customers.csv": "a,b\n" * 60_000, "tiny.csv": "a,b\n", "spec.pdf": "x",
                  "db/migrations/001.sql": "create table x();", "dump.sql": "insert into x values(1);\n" * 50_000})
        self.assertEqual({(f.path, f.rule_id) for f in r.findings},
                         {("exports/customers.csv", "data-file"), ("spec.pdf", "document-file"),
                          ("dump.sql", "sql-dump")})
        self.assertTrue(r.ok)  # low severity: reported, not blocking


def by_rule(result, *rules) -> list[tuple[str, int]]:
    return sorted((f.path, f.line) for f in result.findings if f.rule_id in rules)


class TestPipelineClassifier(unittest.TestCase):
    def test_classes(self):
        from prescan.context import classify, is_production
        cases = {
            ".github/workflows/ci.yml": {"ci"}, ".gitlab-ci.yml": {"ci"}, "Jenkinsfile": {"ci"},
            "azure-pipelines.yml": {"ci"}, "deploy/chart/values-prod.yaml": {"helm"},
            "chart/templates/deployment.yaml": {"helm"}, "infra/main.tf": {"iac"},
            "ansible/group_vars/all.yml": {"ansible"}, "inventory/hosts": {"ansible"},
            "Dockerfile": {"docker"}, "build/api.Dockerfile": {"docker"},
            "docker-compose.prod.yml": {"compose"}, "src/app.py": set(), "docs/values.md": set(),
        }
        for rel, expected in cases.items():
            self.assertEqual(set(classify(rel, "")), expected, rel)
        self.assertEqual(set(classify("k8s/app.yaml", "apiVersion: v1\nkind: Service\n")), {"k8s"})
        self.assertTrue(is_production("k8s/overlays/production/x.yaml", ""))
        self.assertTrue(is_production("deploy.yml", "environment: production\n"))
        self.assertFalse(is_production("src/product/views.py", "reproducible: true\n"))


class TestPipelineRules(unittest.TestCase):
    def test_github_actions(self):
        r = scan({".github/workflows/deploy.yml": f"""
            env:
              REGISTRY_PASSWORD: {J(["hunter2", "-deploy-9x"])}
              API_TOKEN: ${{{{ secrets.API_TOKEN }}}}
              TOKEN_URL: https://auth.example.com/token
            steps:
              - run: docker login reg.example.com -u ci -p {J(["Sup3r", "S3cret!"])}
              - run: echo "$PW" | docker login reg.example.com -u ci --password-stdin
              - run: curl -u deploy:{J(["Pa55", "w0rd123"])} https://api.example.com
              - run: helm upgrade app ./c --set db.password={J(["Zx81", "qLm2"])} --set image.tag=1.2
              - run: docker login -u ci -p <password>
        """})
        self.assertEqual(by_rule(r, "ci-literal-env"), [(".github/workflows/deploy.yml", 3)])
        self.assertEqual(by_rule(r, "inline-cli-credential"),
                         [(".github/workflows/deploy.yml", 7), (".github/workflows/deploy.yml", 9),
                          (".github/workflows/deploy.yml", 10)])
        self.assertNotIn("generic-secret-assignment", ids(r))  # same value: only the specific finding

    def test_references_are_not_literals(self):
        r = scan({
            ".gitlab-ci.yml": "variables:\n  DB_PASSWORD: $CI_DB_PASSWORD\n  TOKEN: ${VAULT_TOKEN}\n",
            "azure-pipelines.yml": "variables:\n  apiKey: $(System.AccessToken)\n",
            "Jenkinsfile": "environment {\n  DB_PASS = credentials('db-pass')\n}\n",
            "infra/main.tf": 'password = var.db_password\nsecret_key = random_password.db.result\n'
                             'client_secret = file("secret.txt")\n',
            "chart/templates/secret.yaml": "apiVersion: v1\nkind: Secret\ndata:\n  pw: {{ .Values.pw | b64enc }}\n",
            "ansible/group_vars/all.yml": 'ansible_become_pass: "{{ vault_become_pass }}"\n',
            "chart/values.yaml": 'db:\n  password: ""\n  existingSecret: ""\n  secretName: db-creds\n',
        })
        self.assertEqual([f for f in r.findings if f.category == "secret"], [])

    def test_literals_in_each_ecosystem(self):
        lit = J(["Lit3", "ral!x9"])
        r = scan({
            "Jenkinsfile": f"environment {{\n  DB_PASS = '{lit}'\n}}\n",
            "infra/main.tf": f'provider "x" {{\n  password = "{lit}"\n}}\n',
            "ansible/group_vars/all.yml": f'ansible_become_pass: "{lit}"\n',
            "k8s/deploy.yaml": f"apiVersion: apps/v1\nkind: Deployment\nenv:\n  - name: DB_PASSWORD\n    value: {lit}\n",
            "Dockerfile": f"FROM python:3.12\nENV API_KEY={lit}\nARG NPM_TOKEN\n",
        })
        self.assertEqual(by_rule(r, "ci-literal-env"),
                         [("Dockerfile", 2), ("Jenkinsfile", 2), ("ansible/group_vars/all.yml", 1),
                          ("infra/main.tf", 2), ("k8s/deploy.yaml", 5)])
        self.assertNotIn(lit, json.dumps([f.to_dict() for f in r.findings]))

    def test_k8s_secret(self):
        token_b64 = base64.b64encode(GH.encode()).decode()
        r = scan({"k8s/overlays/production/secret.yaml": f"""\
apiVersion: v1
kind: Secret
metadata:
  name: app
data:
  GITHUB_TOKEN: {token_b64}
  DB_PASS: c2VjcmV0MTIz
stringData:
  API_KEY: plain-text-key-123
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
spec:
  encryptedData:
    X: AgBy3i4OJSWK+PiTySYZZA1rO43cGDEq
"""})
        secrets = [f for f in r.findings if f.rule_id == "k8s-secret-data"]
        self.assertEqual([f.line for f in secrets], [6, 7, 9])
        self.assertIn("decodes to: GitHub token", secrets[0].description)
        self.assertNotIn("ci-literal-env", ids(r))

    def test_encrypted_values_are_skipped_but_plaintext_is_not(self):
        r = scan({
            "ansible/group_vars/vault.yml": "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n",
            "ansible/group_vars/all.yml": "db_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  3936\n",
            "k8s/secrets.enc.yaml": "apiVersion: v1\nkind: Secret\ndata:\n  pw: ENC[AES256_GCM,data:x]\n"
                                    f"  api_token_unencrypted: {J(['Pl41n', 'T3xt!'])}\n"
                                    "sops:\n  mac: ENC[x]\n  version: 3.8.1\n",
        })
        # SOPS leaves `*_unencrypted` keys in clear on purpose: that one must still be reported.
        self.assertEqual([(f.path, f.line) for f in r.findings if f.category == "secret"],
                         [("k8s/secrets.enc.yaml", 5)])

    def test_production_escalation(self):
        r = scan({"chart/values-prod.yaml": "redis:\n  host: 10.1.2.3\n",
                  "chart/values-dev.yaml": "redis:\n  host: 10.1.2.3\n"})
        sev = {f.path: (f.severity, f.description) for f in r.findings if f.rule_id == "private-ip"}
        self.assertEqual(sev["chart/values-prod.yaml"][0], "high")
        self.assertIn("[production file]", sev["chart/values-prod.yaml"][1])
        self.assertEqual(sev["chart/values-dev.yaml"][0], "medium")

    def test_deploy_targets(self):
        r = scan({
            ".github/workflows/cd.yml": "steps:\n  - run: ssh deploy@app01.example.org 'restart'\n"
                                        "  - run: kubectl --context prod-eu-1 apply -f k8s/\n"
                                        "  - run: git clone git@github.com:acme/app.git\n",
            "inventory/hosts": "[web]\nweb1 ansible_host=10.0.0.5\n",
        })
        self.assertEqual(sorted(f.redacted for f in r.findings if f.rule_id == "deploy-target"),
                         ["10.0.0.5", "deploy@app01.example.org", "prod-eu-1"])

    def test_dockerfile(self):
        r = scan({"Dockerfile": """\
FROM registry.acme.internal/base/python:3.12 AS build
RUN pip install --index-url https://artifactory.acme.internal/api/pypi/simple -r req.txt
RUN pip install --index-url https://pypi.org/simple flask
RUN useradd -u 10001 app
USER 10001:10001
COPY --from=build /app /app
FROM python:3.12-slim
FROM ghcr.io/acme/tool:1
FROM docker.io/library/alpine:3
FROM ${BASE_IMAGE}
USER app
"""})
        self.assertEqual(sorted((f.rule_id, f.line, f.redacted) for f in r.findings if f.category == "infra"), [
            ("dockerfile-user-id", 4, "10001"), ("dockerfile-user-id", 5, "10001:10001"),
            ("private-package-registry", 2, "artifactory.acme.internal"),
            ("private-registry-image", 1, "registry.acme.internal"),
        ])

    def test_public_registries_config(self):
        root = make_repo({"Dockerfile": "FROM registry.acme.internal/base/python:3.12\n"})
        self.assertIn("private-registry-image", ids(Scanner(root, Config()).scan()))
        cfg = load_config(root, central('public_registries = ["registry.acme.internal"]\n'))
        self.assertNotIn("private-registry-image", ids(Scanner(root, cfg).scan()))

    def test_images_and_package_config_files(self):
        r = scan({
            "docker-compose.yml": "services:\n  api:\n    image: 123456789012.dkr.ecr.eu-west-1.amazonaws.com/api:1\n"
                                  "  db:\n    image: postgres:16\n",
            ".npmrc": "registry=https://npm.acme.internal/api/npm/\n",
            "frontend/.npmrc": "registry=https://registry.npmjs.org/\n",
        })
        self.assertEqual(by_rule(r, "private-registry-image"), [("docker-compose.yml", 3)])
        self.assertEqual(by_rule(r, "private-package-registry"), [(".npmrc", 1)])
        self.assertEqual(by_rule(r, "cloud-account-id"), [("docker-compose.yml", 3)])

    def test_secret_file_references_are_warnings(self):
        r = scan({".github/workflows/x.yml": "steps:\n  - run: gcloud auth --key-file /etc/secrets/sa.json\n"
                                             "  - run: cp .env.example .env.ci\n  - run: echo $KUBECONFIG kubeconfig\n"})
        refs = sorted(f.redacted for f in r.findings if f.rule_id == "secret-file-reference")
        self.assertEqual(refs, [".env.ci", "/etc/secrets/sa.json", "kubeconfig"])
        self.assertTrue(r.ok)

    def test_terraform_backend_and_cloud_ids(self):
        r = scan({"infra/backend.tf": 'terraform {\n  backend "s3" {\n    bucket = "acme-tfstate"\n  }\n}\n'
                                      'role = "arn:aws:iam::123456789012:role/deploy"\n'})
        self.assertEqual(sorted((f.rule_id, f.severity) for f in r.findings),
                         [("cloud-account-id", "low"), ("tf-backend", "low")])

    def test_cli_credentials_anywhere(self):
        r = scan({"scripts/restore.sh": f"PGPASSWORD={J(['Xy81', 'qLm2z'])} psql -h db -U app\n",
                  "README.md": "Run `curl -u user:password https://api` and `docker login -p <password>`\n"})
        self.assertEqual(by_rule(r, "inline-cli-credential"), [("scripts/restore.sh", 1)])

    def test_false_positives_from_real_repos(self):
        r = scan({
            "vcs.py": '"""Auth is passed via the --username and --password options instead."""\n',
            "chart/templates/cm.yaml": 'VERIFY: {{ printf "%s/ca.pem" $cfg.mountPath | quote }}\n',
            "chart/values.yaml": "# token path defaults to /var/run/secrets/... or "
                                 "/var/run/secrets/kubernetes.io/serviceaccount/token\nca: ca.pem\n",
        })
        self.assertEqual(r.findings, [])
        r = scan({"chart/values.yaml": "tls:\n  key: /etc/tls/server-key.pem\n  ca: /etc/tls/ca.pem\n"})
        self.assertEqual([f.redacted for f in r.findings if f.rule_id == "secret-file-reference"],
                         ["/etc/tls/server-key.pem"])

    def test_non_pipeline_files_keep_generic_rules(self):
        r = scan({"notes.md": f"password: {J(['Xk82!pQz', 'Lm4vT9'])}\n"})
        self.assertEqual(ids(r), {"generic-secret-assignment"})


class TestFixes(unittest.TestCase):
    """The two ways out of a block: `protect` (agent ignore rules) and `allow` (safe / false positive)."""

    def repo(self):
        return make_repo({".env": f"AWS_ACCESS_KEY_ID={AWS_ID}\n", "src/app.py": f'K = "{GH}"\n',
                          "certs/a.key": "x", "certs/b.key": "x"})

    def run_cli(self, *argv):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(list(argv))
        return code, err.getvalue()

    def test_protect_bob(self):
        root = self.repo()
        code, out = self.run_cli("protect", str(root / ".env"), str(root / "certs"), "--agent", "bob",
                                 "--path", str(root))
        self.assertEqual(code, 0, out)
        self.assertEqual((root / ".bobignore").read_text().splitlines()[1:], ["/.env", "/certs/"])
        r = Scanner(root, Config(), agent="bob").scan()
        self.assertEqual({f.path for f in r.covered}, {".env", "certs/a.key", "certs/b.key"})
        self.assertEqual({f.path for f in r.blocking}, {"src/app.py"})
        code, out = self.run_cli("protect", str(root / ".env"), "--agent", "bob", "--path", str(root))
        self.assertIn("Already covered", out)  # idempotent
        self.assertEqual((root / ".bobignore").read_text().count("/.env"), 1)

    def test_protect_escapes_glob_characters(self):
        root = make_repo({"a[1].env": "A=1\n", "a1.env": "A=1\n"})
        self.assertEqual(self.run_cli("protect", str(root / "a[1].env"), "--agent", "gemini", "--path", str(root))[0], 0)
        r = Scanner(root, Config(), agent="gemini").scan()
        self.assertEqual(({f.path for f in r.covered}, {f.path for f in r.blocking}), ({"a[1].env"}, {"a1.env"}))

    def test_protect_claude(self):
        root = self.repo()
        (root / ".claude").mkdir()
        (root / ".claude" / "settings.json").write_text(json.dumps({"model": "x", "permissions": {"allow": ["Bash(ls)"]}}))
        self.assertEqual(self.run_cli("protect", str(root / ".env"), str(root / "certs"), "--agent", "claude-code",
                                      "--path", str(root))[0], 0)
        data = json.loads((root / ".claude" / "settings.json").read_text())
        self.assertEqual((data["model"], data["permissions"]["allow"], data["permissions"]["deny"]),
                         ("x", ["Bash(ls)"], ["Read(./.env)", "Read(./certs/**)"]))
        self.assertEqual({f.path for f in Scanner(root, Config(), agent="claude-code").scan().blocking}, {"src/app.py"})
        self.run_cli("protect", str(root / "src" / "app.py"), "--agent", "claude-code", "--scope", "local",
                     "--path", str(root))
        self.assertEqual(json.loads((root / ".claude" / "settings.local.json").read_text())["permissions"]["deny"],
                         ["Read(./src/app.py)"])
        self.assertTrue(Scanner(root, Config(), agent="claude-code").scan().ok)

    def test_protect_refusals(self):
        root = self.repo()
        for argv, msg in [
            (("protect", str(root / ".env"), "--agent", "codex"), "invalid choice"),
            (("protect", str(root / "nope.txt"), "--agent", "bob"), "no such file"),
            (("protect", str(Path(tempfile.mkdtemp())), "--agent", "bob"), "outside the project"),
            (("protect", str(root), "--agent", "bob"), "whole project"),
        ]:
            with redirect_stderr(io.StringIO()) as err:
                try:
                    code = main([*argv, "--path", str(root)])
                except SystemExit as e:  # argparse rejects unknown agents
                    code = e.code
            self.assertEqual(code, 2, argv)
            self.assertIn(msg, err.getvalue(), argv)
        self.assertFalse((root / ".bobignore").exists())

    def test_protect_fails_loudly_if_not_covered_afterwards(self):
        from unittest import mock
        from prescan.agents import ProtectError, protect
        root = self.repo()
        with mock.patch("prescan.agents.coverage_for", return_value=None):
            with self.assertRaises(ProtectError) as cm:
                protect("bob", root, [".env"])
        self.assertIn("still doesn't see these as covered", str(cm.exception))

    def test_allow_by_id_and_by_file(self):
        root = self.repo()
        r = Scanner(root, Config()).scan()
        gh = next(f for f in r.findings if f.rule_id == "github-token")
        code, out = self.run_cli("allow", gh.short_id, "--reason", "fake fixture", "--path", str(root))
        self.assertEqual(code, 0, out)
        code, out = self.run_cli("allow", str(root / ".env"), str(root / "certs"), "--path", str(root))
        self.assertEqual(code, 0, out)
        self.assertTrue(Scanner(root, Config()).scan().ok)
        from prescan.config import baseline_path
        entries = json.loads(baseline_path(root).read_text())["accepted"]
        self.assertEqual(next(e for e in entries if e["fingerprint"] == gh.fingerprint)["reason"], "fake fixture")
        self.assertNotIn(GH, baseline_path(root).read_text())  # fingerprints only, never values
        (root / ".env").write_text(f"AWS_ACCESS_KEY_ID={AWS_ID}\nTOKEN={J(['ghp_', 'Zz' * 18])}\n")
        self.assertEqual({f.rule_id for f in Scanner(root, Config()).scan().blocking}, {"github-token"})

    def test_allow_file_is_exact(self):
        root = make_repo({".env": "A=1\n", ".env.prod": "A=1\n", "certs/a.key": "x", "certs2/b.key": "x"})
        self.assertEqual(self.run_cli("allow", str(root / ".env"), str(root / "certs"), "--path", str(root))[0], 0)
        self.assertEqual({f.path for f in Scanner(root, Config()).scan().blocking}, {".env.prod", "certs2/b.key"})

    def test_allow_rejects_unknown_ids_and_paths(self):
        root = self.repo()
        for sel, msg in (("deadbeef", "no current finding"), (str(root / "missing.txt"), "no such file")):
            code, out = self.run_cli("allow", sel, "--path", str(root))
            self.assertEqual(code, 2)
            self.assertIn(msg, out)

    def test_report_suggests_both_fixes_for_the_agent(self):
        from prescan.report import render_text
        root = self.repo()
        bob = render_text(Scanner(root, Config(), agent="bob").scan(), color=False)
        self.assertIn("protect .env certs/a.key certs/b.key src/app.py --agent bob", bob)
        self.assertIn("Adds them to .bobignore", bob)
        ids = [f.short_id for f in Scanner(root, Config(), agent="bob").scan().blocking]
        self.assertIn("allow " + " ".join(ids), bob)
        self.assertIn(f"id {ids[0]}", bob)
        self.assertIn("Not available: Codex", render_text(Scanner(root, Config(), agent="codex").scan(), color=False))
        self.assertIn("--agent <claude-code|bob|gemini>", render_text(Scanner(root, Config()).scan(), color=False))
        self.assertIn("permissions.deny", render_text(Scanner(root, Config(), agent="claude-code").scan(), color=False))


class TestCli(unittest.TestCase):
    def _run(self, *args, stdin=""):
        return subprocess.run([sys.executable, "-m", "prescan", *args], cwd=ROOT, input=stdin,
                              capture_output=True, text=True, env={**os.environ, "NO_COLOR": "1"})

    def test_json_output(self):
        root = make_repo({".env": "A=1"})
        p = self._run("scan", str(root), "--format", "json")
        self.assertEqual(p.returncode, 1)
        self.assertFalse(json.loads(p.stdout)["ok"])

    def test_claude_hook_blocks_with_exit_2(self):
        root = make_repo({".env": "A=1"})
        p = self._run("hook", "claude-code", stdin=json.dumps({"cwd": str(root), "session_id": "t1"}))
        self.assertEqual(p.returncode, 2)
        self.assertIn(".env", p.stderr)
        self.assertEqual(p.stdout, "")  # nothing goes to the model

    def test_claude_hook_passes(self):
        root = make_repo({"main.py": "print('hi')\n"})
        p = self._run("hook", "claude-code", stdin=json.dumps({"cwd": str(root), "session_id": "t2"}))
        self.assertEqual(p.returncode, 0)

    def test_install_hook_adds_hook_and_deny_rules(self):
        home = Path(tempfile.mkdtemp(prefix="prescan-fakehome-"))
        settings = home / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text(json.dumps({"permissions": {"allow": ["Bash(ls:*)"]}, "model": "x"}))
        env = {**{k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}, "HOME": str(home),
               "PRESCAN_HOME": str(home / ".config" / "prescan")}
        for _ in range(2):  # second run must be a no-op
            p = subprocess.run([sys.executable, "-m", "prescan", "install-hook"], cwd=ROOT, env=env,
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(settings.read_text())
        self.assertEqual(data["model"], "x")
        self.assertEqual(data["permissions"]["allow"], ["Bash(ls:*)"])
        self.assertEqual(data["permissions"]["deny"],
                         ["Read(~/.config/prescan/**)", "Edit(~/.config/prescan/**)"])
        hooks = data["hooks"]["UserPromptSubmit"]
        self.assertEqual(len(hooks), 1)
        self.assertIn(f"{shlex.quote(sys.executable)} -m prescan hook claude-code", hooks[0]["hooks"][0]["command"])

    def _install(self, settings_data: dict) -> tuple[dict, str, dict]:
        home = Path(tempfile.mkdtemp(prefix="prescan-fakehome-"))
        settings = home / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text(json.dumps(settings_data))
        env = {**{k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}, "HOME": str(home),
               "PRESCAN_HOME": str(home / ".config" / "prescan")}
        p = subprocess.run([sys.executable, "-m", "prescan", "install-hook"], cwd=ROOT, env=env,
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(settings.read_text()), p.stderr, env

    def test_hook_command_blocks_without_prescan_on_path(self):
        data, err, env = self._install({})
        self.assertIn("note: the hook runs", err)
        cmd = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
        self.assertFalse(cmd.startswith("prescan "))
        # Run it the way Claude Code does: plain shell, minimal PATH, hook JSON on stdin.
        dirty = make_repo({".env": "A=1"})
        clean = make_repo({"main.py": "print('hi')\n"})
        minimal = {"PATH": "/usr/bin:/bin", "HOME": env["HOME"], "PRESCAN_HOME": env["PRESCAN_HOME"]}
        for root, expected in ((dirty, 2), (clean, 0)):
            p = subprocess.run(["sh", "-c", cmd], input=json.dumps({"cwd": str(root)}), env=minimal,
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, expected, p.stderr)

    def test_install_hook_rewrites_bare_command(self):
        old = {"hooks": {"UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": "prescan hook claude-code", "timeout": 60}]}]}}
        data, err, _ = self._install(old)
        hooks = [h for g in data["hooks"]["UserPromptSubmit"] for h in g["hooks"]]
        self.assertEqual(len(hooks), 1)
        self.assertIn(f"{shlex.quote(sys.executable)} -m prescan hook claude-code", hooks[0]["command"])
        self.assertIn("updated hook", err)

    def test_install_hook_keeps_custom_absolute_command(self):
        custom = "/opt/tools/venv/bin/prescan hook claude-code"
        data, _, _ = self._install({"hooks": {"UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": custom}]}]}})
        hooks = [h for g in data["hooks"]["UserPromptSubmit"] for h in g["hooks"]]
        self.assertEqual([h["command"] for h in hooks], [custom])

    def test_bob_hook(self):
        dirty = make_repo({".env": "A=1"})
        p = self._run("hook", "bob", stdin=json.dumps({"cwd": str(dirty), "session_id": "b1"}))
        self.assertEqual(p.returncode, 2)
        covered = make_repo({".env": "A=1", ".bobignore": ".env\n", "README.md": "see https://grafana.prod.x.com\n"})
        p = self._run("hook", "bob", stdin=json.dumps({"cwd": str(covered), "session_id": "b2"}))
        self.assertEqual((p.returncode, p.stdout), (0, ""))  # warnings never go to stdout for Bob

    def test_install_hook_for_bob(self):
        home = Path(tempfile.mkdtemp(prefix="prescan-fakehome-"))
        env = {**{k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}, "HOME": str(home),
               "PRESCAN_HOME": str(home / ".config" / "prescan")}
        p = subprocess.run([sys.executable, "-m", "prescan", "install-hook", "--agent", "bob"], cwd=ROOT,
                           env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads((home / ".bob" / "settings" / "settings.json").read_text())
        hook = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        self.assertIn(f"{shlex.quote(sys.executable)} -m prescan hook bob", hook["command"])
        self.assertEqual(hook["timeout"], 60)
        self.assertNotIn("permissions", data)
        self.assertIn("Allow outside workspace", p.stderr)

    def test_run_wrapper_honours_agent_ignore(self):
        root = make_repo({".env": "A=1", ".bobignore": ".env\n"})
        ok = self._run("run", "--agent", "bob", "--path", str(root), "--", "echo", "started")
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "started"))
        blocked = self._run("run", "--path", str(root), "--", "echo", "started")
        self.assertEqual(blocked.returncode, 1)

    def test_run_wrapper(self):
        clean = make_repo({"main.py": "print('hi')\n"})
        dirty = make_repo({".env": "A=1"})
        ok = self._run("run", "--path", str(clean), "--", "echo", "agent-started")
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "agent-started"))
        bad = self._run("run", "--path", str(dirty), "--", "echo", "agent-started")
        self.assertEqual(bad.returncode, 1)
        self.assertNotIn("agent-started", bad.stdout)


if __name__ == "__main__":
    unittest.main()
