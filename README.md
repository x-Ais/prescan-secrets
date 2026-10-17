# prescan

AI coding agents (Claude Code, Codex, Gemini CLI, Aider, …) start by reading your repository.
`prescan` runs **before** the agent does: it checks the codebase for confidential material. If it
finds any, the agent doesn't start and you get a report of what was flagged.

```
✖ prescan: BLOCKED — 2 finding(s) must be resolved before an AI agent can read this codebase.

.env
  HIGH   file   Environment file (.env) [env-file]
  MEDIUM L1     Internal hostname (.internal) [internal-hostname]
         DB_HOST=db.billing.internal:5432
```

* **Installed once, configured in one place.** prescan is a standalone tool. Your settings, your
  block list and per-project tweaks all live in `~/.config/prescan/`, outside every project. Projects
  need no prescan files at all.
* **A repo can't switch the gate off.** `.prescanignore` / `.prescan.toml` files inside a scanned repo
  are ignored unless you opt in.
* Zero dependencies: Python ≥ 3.11 standard library only. On Red Hat (RHEL 8.8+/9.2+) install
  `python3.11` from Red Hat's AppStream repos; the default `python3` there is too old. The same
  applies to macOS's system `python3`.
* **Respects what your agent already blocks.** Findings in files the launched agent is configured
  not to read (`.bobignore`, `.geminiignore`, Claude Code `permissions.deny`) are listed but never
  block. See [Files the agent already can't read](#files-the-agent-already-cant-read).
* Secrets are **never printed in full**. Reports show `AKIA…**** (20 chars)`, and URL findings show
  only `scheme://host`.
* Exit codes: `0` OK, `1` blocked, `2` error.

## Setup (once)

```bash
pipx install /path/to/prescan    # puts `prescan` on your PATH
prescan init                     # creates ~/.config/prescan/config.toml
prescan install-hook             # gates every Claude Code session (see below)
prescan install-hook --agent bob # gates every IBM Bob session
```

After that, every project is gated automatically. There's nothing to add to any repo.

## Use

```bash
prescan                     # scan current dir
prescan path/to/repo        # scan another dir
prescan --format json       # machine-readable
prescan --fail-on high      # only high-severity findings block
prescan --agent bob         # as Bob would see it: files in .bobignore don't block
prescan baseline            # accept everything currently flagged in this project (new findings still block)
prescan protect .env --agent bob          # let the agent's own ignore rules cover a file
prescan allow 3fa9c2e1 --reason "..."     # mark one finding (id from the report) as safe
```

## Production files always block

Production configuration doesn't belong where an agent can read it, and production secrets don't
belong in a repo at all. A file whose **path** says production always blocks:

| Rule | Files |
|---|---|
| `production-env-file` | `.env.prod`, `.env.production(.local)`, `.env.prd`, `prod.env`, `*.prod.env` |
| `production-file` | config / infra / script files with `prod`, `production` or `prd` as a word in the name (`values-prod.yaml`, `values_prod.yaml`, `appsettings.Production.json`, `docker-compose.prod.yml`, `Dockerfile.prod`, `deploy-prod.yml`, `prod.tfvars`, `kubeconfig-prod`) or as the extension (`values.prod`, `config.prd`), anything under a production folder (`overlays/production/`, `envs/prod/`, `k8s/prod-eu/`), and settings code named after it (`settings/prod.py`, `environments/production.rb`) |

Matching ignores case: `VALUES_PROD.YAML`, `.ENV.PROD`, `overlays/PRODUCTION/` and
`environment: PRODUCTION` all count.

**Possible production files.** `pro` is also used for production, but just as often for a pricing
tier or a Qt project file. The same places spelled `pro` (`values_pro.yaml`, `values.pro`,
`.env.pro`, `envs/PRO/`) give `possible-production-file`. These block (medium) but, unlike the files
above, the team decides: if it isn't production, `prescan allow <file> --reason "…"` (or `protect`)
clears it.

Not production: templates and examples (`.env.prod.example`, anything under `examples/`), docs, and
words that only contain the letters (`products.yaml`). A file that merely *mentions* production
(`environment: production`, `ENV NODE_ENV=production`) doesn't block by itself; its medium findings
are raised to high instead.

These findings **can't be cleared by the repo or the agent**: `allow`, `protect` and `baseline`
refuse them, and the agent's ignore rules don't make them "covered". The report says to remove the
file and checks git:
- **committed:** deleting it isn't enough, because it stays in history and on any remote. Rotate the values.
- **no longer tracked but in history:** same, rotate the values.
- **not committed:** delete it or move it out of the project directory.

The only override is deliberate and central, in your own config: `exclude` for a path, or
`disable_rules = ["production-file"]`.

## When prescan blocks: two fixes that don't delete anything

Deleting secrets every time you want to ask the agent something isn't workable, so every block
report ends with two ready-to-copy commands for the agent being launched:

**1. Keep the file away from the agent.** The file stays, the agent can't read it, and prescan
stops blocking on it, even when the secret inside changes.

```bash
prescan protect .env config/ --agent bob
```

| Agent | What `protect` writes |
|---|---|
| IBM Bob | `/.env`, `/config/` appended to `.bobignore` |
| Gemini CLI | same, in `.geminiignore` |
| Claude Code | `Read(./.env)`, `Read(./config/**)` in `.claude/settings.json` (`--scope local` → `settings.local.json`) |
| Codex, Aider | not available: no ignore file that blocks reads. Use option 2, or move the secret out. |

Entries are anchored, exact paths (glob characters escaped). After writing, prescan re-checks that
it really sees each path as covered, and fails if not, so you never get a false sense of safety.
Commit the ignore file so teammates' agents skip the file too.

**2. Mark it as safe / a false positive.** The agent **can** read it, so this is for test
fixtures, public endpoints and similar.

```bash
prescan allow 3fa9c2e1 9b0d1a77 --reason "fake fixture"
prescan allow tests/fixtures/ --reason "fake data"
```

IDs are shown next to each finding in the report. Choices are stored in the central baseline
(`~/.config/prescan/baselines/`) with the reason and date, as fingerprints only, never the values.
A new or changed secret still blocks.

## Where everything lives

```
~/.config/prescan/          ($PRESCAN_HOME to move it, e.g. into a private git repo)
├── config.toml             settings, [block] list, [[project]] overrides
└── baselines/              accepted findings, one file per project
```

Settings are applied in this order:

1. The top-level settings in `config.toml`, for every project.
2. Every `[[project]]` entry whose `path` covers the scanned directory. Lists (`exclude`,
   `disable_rules`, `[project.block]` entries, ...) are added; `fail_on` and other scalars replace.
3. Only if `trust_project_config = true`: the repo's own `.prescan.toml`, `.prescanignore` and
   `.prescan-baseline.json`. A repo file can add rules and exclusions but can never loosen `fail_on`.

Every report starts with a `config:` line listing exactly which files and project entries applied.

## Gate your agent

### Claude Code (hook, recommended)

```bash
prescan install-hook --dry-run   # show what would change
prescan install-hook             # writes ~/.claude/settings.json (all projects)
```

This makes two changes to `~/.claude/settings.json`:

* **A `UserPromptSubmit` hook** that runs `prescan hook claude-code` before each prompt.
* **`permissions.deny` rules** `Read(~/.config/prescan/**)` and `Edit(~/.config/prescan/**)`. Your
  config lists exactly what you're hiding, and an agent able to edit it could switch the gate off.

The hook command names the **absolute path of the Python interpreter** prescan is installed in
(`/path/to/venv/bin/python -m prescan hook claude-code`), because Claude Code runs hooks in a plain
shell where `prescan` may not be on PATH. **Keep that interpreter in place:** if the venv is deleted
or moved, the hook fails with "command not found" (exit 127), and Claude Code only blocks on exit 2,
so prompts would go through unscanned. Re-run `prescan install-hook` after recreating the venv.
Re-running it also upgrades an old bare `prescan hook claude-code` entry to the absolute form.

Existing settings are kept, and running it twice changes nothing. `--scope project|local` writes to
a repo's `.claude/` instead, but the user scope is the point: one install covers every project.

If the
scan fails, the hook exits with code 2: Claude Code drops the prompt, **nothing is sent to the model**,
and the report is shown to you, not to Claude. Low-severity warnings appear once per session as a
message to you. If the scan itself crashes, the hook blocks anyway (fail closed); set
`PRESCAN_FAIL_OPEN=1` to change that.

The hook runs on every prompt, so it also catches a `.env` that appears mid-session.

### IBM Bob (hook)

```bash
prescan install-hook --agent bob   # writes ~/.bob/settings/settings.json (all workspaces)
```

Bob's hooks use the same contract as Claude Code's (`UserPromptSubmit`, JSON with `cwd` on stdin,
exit 2 blocks), so this adds `<python> -m prescan hook bob` with a **60 s timeout**. Bob's default is
10 s, and a timeout doesn't block. It's written to Bob's *global* settings because workspace hooks
only run in folders you've marked as trusted. Differences from Claude Code:

* Bob shows that the prompt was blocked, but writes the report to its logs. Run `prescan` in a
  terminal to see what was flagged.
* `prescan hook bob` prints nothing on stdout, since Bob doesn't document what it does with hook output.
* Bob has no deny rules for paths outside the workspace. Keep its "Allow outside workspace tool
  requests" setting off so it can't read `~/.config/prescan/`.

### Any other agent (wrapper)

```bash
prescan run -- codex
prescan run -- gemini
prescan run --path ~/src/api -- aider
```

`prescan run` works out the agent from the command name (`claude`, `bob`, `gemini`, `codex`,
`aider`) to apply that agent's ignore rules; `--agent` overrides it.

To make it automatic, add aliases to `~/.zshrc`:

```bash
alias codex='prescan run -- command codex'
alias gemini='prescan run -- command gemini'
```

`prescan run` scans first and only `exec`s the agent if the result is OK. For these agents, keep
`~/.config/prescan/` out of their reach with whatever ignore or sandbox setting they offer.

## Files the agent already can't read

If a flagged file is already blocked by the launched agent's own configuration, it isn't a blocking
finding. The report lists it under "Covered by …" so you can still clean it up.

| Agent | What prescan honours |
|---|---|
| IBM Bob | `.bobignore` at the workspace root |
| Gemini CLI | `.geminiignore` at the project root |
| Claude Code | `permissions.deny` `Read(...)` rules from managed, user (`~/.claude/settings.json` or `$CLAUDE_CONFIG_DIR`), project and local settings |
| Codex | nothing (no ignore file) |
| Aider | nothing: `.aiderignore` only hides files from the repo map, it doesn't stop reads |

Only the **launched** agent's rules count: a file in `.geminiignore` still blocks when you start Bob.
Without an agent (`prescan` on its own, no `--agent`), nothing is covered.

prescan errs on the side of *not covered*, because a wrong "covered" would let the agent read
something prescan thought was protected:

* Ignore files are matched with **git's exact rules**, checked against `git check-ignore` in the tests.
* Where tools disagree, the file is **not covered**:
  * a `!pattern` re-including a file inside an excluded directory (git says ignored, many libraries
    say included);
  * a pattern that only matches when case is ignored.
* Claude `Read(./.env)` covers only the root `.env`, not `sub/.env`; use `Read(**/.env)` for every
  folder. The `Read(/path)` form (relative to the settings file) is never treated as coverage.
* A `.claudeignore` is reported as a warning: it isn't a Claude Code feature and protects nothing.

## What it detects

| Category | Rule ids | Default severity |
|---|---|---|
| **Sensitive files** (flagged by name) | `env-file` (`.env`, `.env.*`, `*.env`, `.envrc`; `.env.example`/`.sample`/`.template` are exempt but still content-scanned) | high |
| | `private-key-file` (`*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.ppk`, `id_rsa`, `id_ed25519`, …) | high |
| | `credentials-file` (`.netrc`, `.pgpass`, `.htpasswd`, `.git-credentials`, `.aws/credentials`, `.docker/config.json`, kubeconfig, `credentials.json`, `service-account*.json`, `secrets.{yml,json,toml}`, `*.ovpn`, Rails `master.key`, `*.kdbx`, `.pypirc`, Kerberos `*.keytab`, IBM GSKit `*.kdb`/`*.sth`, Oracle `cwallet.sso`, `*.har`, Postman environments, Ansible vault password files, …) | high |
| | `terraform-state` (`*.tfstate`: holds resource secrets in plaintext) | high |
| | `terraform-vars`, `database-file` (`*.sqlite`, `*.db`, `*.dump`, `*.bak`), `shell-history`, `memory-dump` (`*.hprof`, core dumps, `*.pcap`), `infra-config-file` (`tnsnames.ora`, `*.rdp`, Postman collections), `symlink-outside-repo` | medium |
| | `data-file` (`*.csv`/`*.tsv` over 100 KB), `sql-dump` (`*.sql` over 1 MB), `document-file` (`*.xlsx`, `*.parquet`, `*.pdf`, `*.docx`, …) | low (warning) |
| **Known token formats** | `private-key` (PEM blocks), `aws-access-key-id`, `aws-secret-access-key`, `github-token`, `gitlab-token`, `slack-token`, `slack-webhook`, `discord-webhook`, `stripe-live-key`, `google-api-key`, `gcp-service-account`, `openai-key`, `anthropic-key`, `huggingface-token`, `sendgrid-key`, `npm-token`, `npmrc-auth`, `pypi-token`, `azure-storage-conn` | high |
| | `stripe-test-key`, `twilio-key`, `jwt` | medium |
| **Credentials in URLs** | `credentials-in-url`: `postgres://user:pass@…`, `mongodb+srv://…`, `redis://:pass@…` (empty username), `https://user:pass@…` | high |
| **XML secrets** | `xml-secret` (`<password>…</password>`, `<db.secret>…`) and `xml-name-value-secret` (`<name>db.password</name><value>…</value>`), e.g. Maven `settings.xml`, Spring, Tomcat. Property references (`${…}`) and Maven-encrypted values (`{…}`) are skipped. | high |
| **Classification markings** | `classification-label`: `CONFIDENTIAL`, `CONFIDENTIEL` (capitals only), and phrases in any case: "internal use only", "strictly confidential", "proprietary and confidential", "do not distribute", "diffusion restreinte", … Code uses like `Level.CONFIDENTIAL` or `CONFIDENTIAL = 3` are skipped. | medium |
| **Hard-coded secrets** | `generic-secret-assignment`: `password = "…"`, `API_KEY: …`, `client_secret=…` when the value has high entropy and isn't a placeholder (`changeme`, `${VAR}`, `your_key_here`) or a code reference (`os.environ[...]`, `settings.X`, `getToken()`) | medium |
| **Your block list** (`[block]`) | `blocked-domain`, `blocked-url`, `blocked-variable`, `blocked-keyword`; see [Block your own domains, URLs, variables and keywords](#block-your-own-domains-urls-variables-and-keywords) | high (configurable) |
| **Internal infrastructure** | `company-domain`: any host under your `internal_domains` | high |
| | `private-ip` (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7), `internal-hostname` (`*.internal`, `.corp`, `.intranet`, `.lan`, `.local`, `.private`), `cloud-private-endpoint` (RDS, ElastiCache, Azure SQL, MongoDB Atlas, `*.svc.cluster.local`, Supabase, Neon, …, in URLs or as bare hostnames like `host: x.cache.amazonaws.com`) | medium |
| | `sensitive-hostname`: hosts with labels like `prod`, `admin`, `vault`, `jenkins`, `grafana`, `bastion` | low (warning) |

### Pipelines and deployment files

prescan recognises CI/CD and deployment files and runs extra rules on them:
- **CI/CD pipelines:** GitHub Actions, GitLab CI, Jenkinsfile, Azure Pipelines, Bitbucket, CircleCI,
  Travis, Drone, AWS CodeBuild, Cloud Build, Buildkite, Tekton, Argo Workflows.
- **Kubernetes:** Helm charts and values, Kubernetes manifests, Kustomize.
- **Infrastructure as code:** Terraform, Pulumi, CloudFormation, Serverless.
- **Ansible:** inventories, `group_vars`, `host_vars`.
- **Containers:** Dockerfiles, Compose files.

| Rule | Catches | Severity |
|---|---|---|
| `ci-literal-env` | A literal value under a sensitive name in `env:` / `variables:` / Helm values / ConfigMaps / `ENV`/`ARG` / HCL / Ansible vars. No randomness threshold in these files. References are skipped: `${{ secrets.X }}`, `$VAR`, `$(var)`, `{{ .Values.x }}`, `var.x`, `credentials('id')`, `file(...)`, `!vault`, SOPS `ENC[...]`, SealedSecret ciphertext. | high |
| `inline-cli-credential` | Credentials typed into commands, **in any file**: `docker login -p …`, `curl -u user:pass`, `Authorization: Bearer …`, `mysql -p…`, `sshpass -p`, `kubectl --from-literal=k=v`, `helm --set *.password=…`, `--password …`, `PGPASSWORD=… psql` | high |
| `k8s-secret-data` | Every value of a `kind: Secret` manifest; `data:` values are base64-decoded and checked against the token rules ("decodes to: GitHub token") | high |
| `private-registry-image` | `FROM` / `image:` / Helm `registry:` pulling from a registry that isn't public (Docker Hub, ghcr.io, quay.io, mcr, public ECR, Red Hat, registry.k8s.io, …) | medium |
| `private-package-registry` | `--index-url`, `.npmrc registry=`, `npmRegistryServer`, `GOPROXY`, Maven `<url>`, pip.conf, in Docker/CI files and package-manager config files | medium |
| `deploy-target` | `ssh/scp/rsync user@host`, `--context` / `use-context`, `cluster:`, `ansible_host` | medium |
| `dockerfile-user-id` | Numeric `USER 10001:10001`, `useradd -u 10001` | medium |
| `secret-file-reference` | Paths to secret files: `/etc/secrets/sa.json`, `*.key`, `*key*.pem`, `kubeconfig`, `.env.ci` | low (warning) |
| `cloud-account-id` | AWS account IDs (ARNs, ECR hosts), Azure subscription/tenant IDs, **in any file** | low (warning) |
| `tf-backend` | Terraform remote state backends (`backend "s3"`) | low (warning) |

**Production files** are files whose path contains `prod` / `production` / `prd` / `live`
(`values-prod.yaml`, `overlays/production/`), or that declare `environment: production`. In them,
every medium finding, built-in or pipeline, is raised to **high** and tagged `[production file]`.

If your company registry or package mirror is expected (most Dockerfiles use it), mark it as public:
`public_registries = ["registry.acme.internal", "artifactory.acme.internal"]`, or turn a rule off
with `disable_rules`.

Skipped by default: `.git` (except `.git/config`, which is scanned for tokens in remote URLs),
`node_modules`, virtualenvs, `site-packages`, vendored `_vendor` dirs, build caches (any dir
containing `CACHEDIR.TAG` or `pyvenv.cfg`), binary files, and files over 2 MB. IDE folders such as
`.idea/` and `.vscode/` **are** scanned: they often hold database connection settings.
`.gitignore` is deliberately **not** respected, because agents can read gitignored files and that's
exactly where `.env` lives.

## Block your own domains, URLs, variables and keywords

The built-in rules can't know your private names, so list them under `[block]`:

```toml
[block]
domains   = ["myprivate.domaine", "*.privatedomaine", "db-*.acme.*"]
urls      = ["https://partner.com/internal/*"]
variables = ["PROD_*", "*_DB_PASSWORD", "STRIPE_SECRET"]
keywords  = ["Project Falcon", "MegaBank"]
severity  = "high"           # severity for every [block] match
```

| Key | Matches | Examples |
|---|---|---|
| `domains` | Host globs, checked in URLs, `host:port`, and bare hostnames anywhere in the text (`host: db.acme.com`, `"api.acme.com"`). `*` matches anything, including dots. Email addresses (`ops@acme.com`) are ignored; `scheme://user:pass@host` is not. | `myprivate.domaine` matches that host only. `*.privatedomaine` matches `api.privatedomaine` and `db.eu.privatedomaine` but not the bare `privatedomaine`; list both if you want both. |
| `urls` | URL globs, matched against the whole URL with credentials removed. The scheme is optional. | `https://partner.com/internal/*`, `partner.com/admin*` |
| `variables` | Variable-name globs, case-insensitive. Flagged when the variable is **assigned a literal value** in `.env`, shell, YAML, JSON, Python, JS and similar files. References such as `os.environ["PROD_X"]`, `process.env.PROD_X`, `${PROD_X}` or `$PROD_X` are not flagged, and the value is redacted in the report. | `PROD_*`, `*_DB_PASSWORD`, `?_SECRET` |
| `keywords` | Literal strings, case-insensitive, whole words only (`falcon` doesn't match `falconry`). | Project codenames, client names, internal product names |

`internal_domains = ["acme.com"]` is shorthand for `domains = ["acme.com", "*.acme.com"]`.

Reports show only `scheme://host` (plus the path for `blocked-url`). Query strings and credentials
never appear, not even in the snippet line.

Put the block list in the central config, never in a repo: `*.privatedomaine` tells an agent
exactly what you're hiding. If you do enable `trust_project_config` and a repo's `.prescan.toml`
contains `[block]` entries, prescan warns you about it.

## Per-project settings

Add `[[project]]` entries to the central config. `path` is a directory (it and everything under it)
or a glob:

```toml
[[project]]
path = "~/src/billing-api"
exclude = ["tests/fixtures/"]               # gitignore syntax, relative to the project root
disable_rules = ["generic-secret-assignment"]

[[project]]
path = "~/clients/*"                        # every client checkout
fail_on = "low"                             # stricter here: even warnings block
[project.block]
keywords = ["ClientCo"]
```

## Tuning false positives

| Situation | Fix |
|---|---|
| One line is fine | add a comment containing `prescan:ignore` on that line |
| A file holds real secrets but must stay | `prescan protect <file> --agent <agent>`: the agent's own ignore rules cover it (not for production files: remove those) |
| A finding is a false positive / safe to share | `prescan allow <id or file> --reason "…"` |
| A file / directory should never be scanned | `exclude = ["path/"]` in that project's `[[project]]` entry (or top-level for all projects) |
| A known-safe value (e.g. publishable key) | `allow_values = ["^pk_live_"]` |
| A rule is too noisy | `disable_rules = ["jwt"]`, globally or per project |
| Accept the current state, block only new stuff | `prescan baseline` in that project. Stored in `~/.config/prescan/baselines/` as hashes, never the secrets. Delete the file to undo. |

## Full `config.toml` reference

```toml
fail_on = "medium"                         # high | medium | low
internal_domains = ["acme.com", "acme.io"] # strongly recommended: your company domains
exclude = []
disable_rules = []
allow_values = []
entropy_threshold = 3.0
flag_sensitive_hostnames = true
trust_project_config = false               # honour prescan files inside scanned repos
public_registries = []                     # registries / package hosts that aren't private

[block]
domains = ["*.privatedomaine"]
urls = []
variables = ["PROD_*"]
keywords = []
severity = "high"

[[project]]
path = "~/src/some-repo"
exclude = ["fixtures/"]

[[rules]]                                  # your own regex patterns
id = "acme-api-key"
description = "ACME internal API key"
pattern = "acme_[a-f0-9]{32}"
severity = "high"
keywords = ["acme_"]                       # optional: fast pre-filter
```

## Limits

prescan reduces what an agent sees on its first pass. It is not a sandbox. Things it does not cover:

* **Git history.** A secret deleted from the working tree is still visible via `git log -p`. Use
  `gitleaks git` / `trufflehog` for history, and rotate anything that was ever committed.
* **Files outside the repo.** An agent with shell access can still `cat ~/.aws/credentials`, or
  `cat` prescan's own config. Deny rules on the `Read` tool don't fully cover shell commands. For hard
  guarantees, use Claude Code's sandbox mode, which enforces filesystem rules for shell commands too.
* **Binary files and files > 2 MB** are not content-scanned (only name rules apply).
* **Inline `prescan:ignore` comments** are honoured even in untrusted repos (they're per-line and
  visible in review). Use `disable_rules`/`exclude` in the central config if you'd rather not rely on them.
* **Heuristics.** The generic and hostname rules trade recall for noise. Filling in `[block]` (or
  `internal_domains`) is the single most effective way to catch *your* internal URLs and names.

## Development

```bash
python3 -m unittest discover -s tests
```
