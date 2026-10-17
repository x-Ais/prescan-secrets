"""Detection rules.

Three kinds of rules:
  * ContentRule  - regex run against file contents (secrets, tokens, connection strings)
  * FileRule     - glob matched against the file path (.env, private keys, tfstate...)
  * URL checks   - every URL/host found is classified (private IPs, internal TLDs,
                   cloud private endpoints, company domains from config)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITY_ORDER = {LOW: 1, MEDIUM: 2, HIGH: 3}


@dataclass(frozen=True)
class ContentRule:
    id: str
    description: str
    severity: str
    pattern: re.Pattern
    # Cheap pre-filter: the regex only runs if one of these (lowercase) substrings is in the file.
    keywords: tuple[str, ...] = ()
    # Group holding the secret itself (0 = whole match). Used for redaction and fingerprinting.
    secret_group: int = 0
    # If set, the secret must have at least this Shannon entropy (bits/char).
    min_entropy: float | None = None
    # Run placeholder / variable-reference filtering on the captured value.
    generic: bool = False
    category: str = "secret"
    # If set, the rule only runs on files whose name matches one of these globs.
    path_globs: tuple[str, ...] = ()
    # Show the matched text as-is instead of redacting it (labels, not secrets).
    show_match: bool = False


@dataclass(frozen=True)
class FileRule:
    id: str
    description: str
    severity: str
    globs: tuple[str, ...]
    exclude_globs: tuple[str, ...] = ()
    category: str = "sensitive-file"
    # Only files at least this large match (e.g. big .sql files are dumps, small ones migrations).
    min_size: int = 0


def _re(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


# --------------------------------------------------------------------------- #
# Known token formats (high confidence, low false-positive rate)
# --------------------------------------------------------------------------- #
CONTENT_RULES: list[ContentRule] = [
    ContentRule(
        "private-key", "Private key block", HIGH,
        _re(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        keywords=("private key",),
    ),
    ContentRule(
        "aws-access-key-id", "AWS access key ID", HIGH,
        _re(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        keywords=("akia", "asia", "abia", "acca"), secret_group=1,
    ),
    ContentRule(
        "aws-secret-access-key", "AWS secret access key", HIGH,
        _re(r"(?i)aws.{0,20}?(?:secret|sk)[a-z_\-]*\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
        keywords=("aws",), secret_group=1, min_entropy=3.5,
    ),
    ContentRule(
        "github-token", "GitHub token", HIGH,
        _re(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"),
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), secret_group=1,
    ),
    ContentRule(
        "gitlab-token", "GitLab token", HIGH,
        _re(r"\b(gl(?:pat|dt|rt|cbt|ptt|ft|imt|agent)-[A-Za-z0-9_\-]{20,})"),
        keywords=("gl",), secret_group=1,
    ),
    ContentRule(
        "slack-token", "Slack token", HIGH,
        _re(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})"),
        keywords=("xox",), secret_group=1,
    ),
    ContentRule(
        "slack-webhook", "Slack incoming webhook", HIGH,
        _re(r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_\-]{20,})"),
        keywords=("hooks.slack.com",), secret_group=1,
    ),
    ContentRule(
        "discord-webhook", "Discord webhook", HIGH,
        _re(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{30,})"),
        keywords=("discord",), secret_group=1,
    ),
    ContentRule(
        "stripe-live-key", "Stripe live secret/restricted key", HIGH,
        _re(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"),
        keywords=("_live_",), secret_group=1,
    ),
    ContentRule(
        "stripe-test-key", "Stripe test secret key", MEDIUM,
        _re(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b"),
        keywords=("_test_",), secret_group=1,
    ),
    ContentRule(
        "google-api-key", "Google API key", HIGH,
        _re(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        keywords=("aiza",), secret_group=1,
    ),
    ContentRule(
        "gcp-service-account", "GCP service account JSON", HIGH,
        _re(r"\"type\"\s*:\s*\"service_account\""),
        keywords=("service_account",),
    ),
    ContentRule(
        "openai-key", "OpenAI API key", HIGH,
        _re(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
        keywords=("sk-",), secret_group=1,
    ),
    ContentRule(
        "anthropic-key", "Anthropic API key", HIGH,
        _re(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})"),
        keywords=("sk-ant-",), secret_group=1,
    ),
    ContentRule(
        "huggingface-token", "Hugging Face token", HIGH,
        _re(r"\b(hf_[A-Za-z0-9]{34,})\b"),
        keywords=("hf_",), secret_group=1,
    ),
    ContentRule(
        "sendgrid-key", "SendGrid API key", HIGH,
        _re(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
        keywords=("sg.",), secret_group=1,
    ),
    ContentRule(
        "twilio-key", "Twilio API key", MEDIUM,
        _re(r"\b(SK[0-9a-f]{32})\b"),
        keywords=("sk",), secret_group=1,
    ),
    ContentRule(
        "npm-token", "npm access token", HIGH,
        _re(r"\b(npm_[A-Za-z0-9]{36})\b"),
        keywords=("npm_",), secret_group=1,
    ),
    ContentRule(
        "npmrc-auth", "Registry auth token in .npmrc/.yarnrc", HIGH,
        _re(r"(?i)(?:_authToken|_auth|npmAuthToken)\s*[=:]\s*[\"']?([^\s\"'$]{8,})"),
        keywords=("_auth", "npmauthtoken"), secret_group=1, generic=True,
        path_globs=(".npmrc", "*.npmrc", ".yarnrc", ".yarnrc.yml"),
    ),
    ContentRule(
        "pypi-token", "PyPI upload token", HIGH,
        _re(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"),
        keywords=("pypi-",), secret_group=1,
    ),
    ContentRule(
        "azure-storage-conn", "Azure storage connection string", HIGH,
        _re(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=([A-Za-z0-9+/=]{40,})"),
        keywords=("accountkey",), secret_group=1,
    ),
    ContentRule(
        "jwt", "JSON Web Token", MEDIUM,
        _re(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
        keywords=("eyj",), secret_group=1,
    ),
    # scheme://user:password@host, user may be empty (redis://:pass@host)  (postgres, mysql, mongodb+srv, redis, amqp, https basic auth, ...)
    ContentRule(
        "credentials-in-url", "Credentials embedded in a URL / connection string", HIGH,
        _re(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@'\"`<>]{0,64}:([^\s:/@'\"`<>]{3,128})@[^\s/'\"`<>]+"),
        keywords=("://",), secret_group=1, generic=True,
    ),
    # XML: <password>...</password>, <db.secret>...</db.secret> (Maven settings.xml, Spring, web.config)
    ContentRule(
        "xml-secret", "Hard-coded secret in an XML element", HIGH,
        _re(r"(?i)<([\w.:\-]*(?:password|passwd|secret|token|api[_\-]?key|private[_\-]?key|passphrase"
            r"|credentials?))>\s*([^<\s][^<]{2,200}?)\s*</\1>"),
        keywords=("pass", "secret", "token", "key", "credential"), secret_group=2, generic=True,
    ),
    # XML name/value pairs: <name>db.password</name><value>...</value> (Hadoop, Spring, Tomcat)
    ContentRule(
        "xml-name-value-secret", "Hard-coded secret in an XML name/value pair", HIGH,
        _re(r"(?is)<name>\s*[^<]*(?:password|passwd|secret|token|api[_.\-]?key|credential)[^<]*</name>\s*"
            r"<value>\s*([^<\s][^<]{2,200}?)\s*</value>"),
        keywords=("<value>",), secret_group=1, generic=True,
    ),
    # Document classification markings. Single words only in capitals; phrases in any case.
    ContentRule(
        "classification-label", "Document classification marking", MEDIUM,
        _re(r"(?<![\w.\"'`/\-])(?:(?i:strictly confidential|highly confidential|company confidential"  # prescan:ignore
            r"|proprietary and confidential|for internal use only|internal use only|do not distribute"  # prescan:ignore
            r"|not for distribution|diffusion restreinte|usage interne uniquement|strictement confidentiel)"  # prescan:ignore
            r"|CONFIDENTIAL|CONFIDENTIEL)(?![\w\"'`])(?!\s*(?:=|\())"),  # prescan:ignore
        keywords=("confidential", "confidentiel", "internal use", "distribut", "diffusion restreinte",
                  "usage interne"),
        show_match=True, category="classification",
    ),
    # Generic `password = "..."`, `API_KEY: abc...`, `DB_SECRET=...`
    ContentRule(
        "generic-secret-assignment", "Hard-coded secret assigned to a sensitive-looking name", MEDIUM,
        _re(
            r"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey"
            r"|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth[_\-]?key|credentials?)[A-Za-z0-9_.\-]*)"
            r"[\"']?[ \t]*(?::=|=>|=|:)[ \t]*(?P<q>[\"'`]?)([^\s\"'`,;]{8,200})(?P=q)"
        ),
        keywords=("pass", "pwd", "secret", "token", "key", "credential"),
        secret_group=3, min_entropy=3.0, generic=True,
    ),
]

# --------------------------------------------------------------------------- #
# Sensitive files (flagged by name alone)
# --------------------------------------------------------------------------- #
ENV_EXAMPLES = ("*.example", "*.sample", "*.template", "*.dist", "*.defaults", "*.tpl", "*.schema")

FILE_RULES: list[FileRule] = [
    FileRule("env-file", "Environment file (.env)", HIGH,
             (".env", ".env.*", "*.env", ".envrc"), ENV_EXAMPLES),
    # *.pem/*.crt are often public certs; PEM private keys are caught by the `private-key` content rule.
    FileRule("private-key-file", "Private key / certificate store", HIGH,
             ("*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk", "*.p8",
              "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")),
    FileRule("credentials-file", "Credentials / auth file", HIGH,
             (".netrc", "_netrc", ".pgpass", ".htpasswd", ".git-credentials", ".aws/credentials",
              ".docker/config.json", ".kube/config", "kubeconfig", "*.kubeconfig",
              "credentials.json", "client_secret*.json", "service-account*.json", "serviceaccount*.json",
              "secrets.yml", "secrets.yaml", "secrets.json", "secrets.toml", ".secrets", "*.ovpn",
              "master.key", "credentials.yml.enc", "*.kdbx", "*.keychain", "*.keychain-db",
              ".pypirc", "*.keytab", "*.kdb", "*.sth", "cwallet.sso", "*.har",
              "*.postman_environment.json", ".vault_pass*", ".vault-pass*", "vault_pass*", "vault-password*",
              ".vault_password*")),
    FileRule("terraform-state", "Terraform state (contains resource secrets in plaintext)", HIGH,
             ("*.tfstate", "*.tfstate.backup")),
    FileRule("terraform-vars", "Terraform variables file", MEDIUM,
             ("*.tfvars", "*.tfvars.json"), ("*.example.tfvars", "*.tfvars.example")),
    FileRule("database-file", "Database file / dump (may contain real data)", MEDIUM,
             ("*.sqlite", "*.sqlite3", "*.db", "*.dump", "*.sql.gz", "*.bak")),
    FileRule("shell-history", "Shell / REPL history", MEDIUM,
             (".bash_history", ".zsh_history", ".python_history", ".psql_history", ".mysql_history",
              ".node_repl_history")),
    FileRule("memory-dump", "Memory dump / packet capture (may contain secrets and data in clear)", MEDIUM,
             ("*.hprof", "core.[0-9]*", "*.dmp", "*.mdmp", "*.pcap", "*.pcapng")),
    FileRule("infra-config-file", "Infrastructure connection file", MEDIUM,
             ("tnsnames.ora", "*.rdp", "*.postman_collection.json")),
    # Hints, not proof: these can hold customer data but often don't. Warnings by default.
    FileRule("data-file", "Large data export (may contain customer or personal data)", LOW,
             ("*.csv", "*.tsv"), min_size=100_000),
    FileRule("sql-dump", "Large SQL file (likely a dump, may contain real data)", LOW,
             ("*.sql",), min_size=1_000_000),
    FileRule("document-file", "Office document / data file (not content-scanned)", LOW,
             ("*.xlsx", "*.xls", "*.parquet", "*.avro", "*.pdf", "*.docx", "*.doc", "*.pptx")),
]

# --------------------------------------------------------------------------- #
# URLs / hosts
# --------------------------------------------------------------------------- #
URL_RE = _re(
    r"\b(?:https?|wss?|grpcs?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|kafka"
    r"|nats|ldaps?|ftp|sftp|ssh|s3|jdbc:[a-z]+)://[^\s'\"<>`)\]}\\,]+",
    re.IGNORECASE,
)
# host:port without a scheme on internal TLDs (e.g. `db.billing.internal:5432`)  prescan:ignore
HOST_PORT_RE = _re(
    r"(?<![\w.\-/@])((?:[a-z0-9\-]+\.)+(?:internal|corp|intranet|lan|local|localdomain|private))"
    r":\d{2,5}\b",
    re.IGNORECASE,
)
IPV4_RE = _re(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")

INTERNAL_TLDS = ("internal", "corp", "intranet", "lan", "local", "localdomain", "private", "home.arpa")

# Managed-infrastructure endpoints that are usually private (DBs, caches, queues, k8s services)
CLOUD_PRIVATE_SUFFIXES = (
    ".rds.amazonaws.com", ".cache.amazonaws.com", ".es.amazonaws.com", ".elb.amazonaws.com",
    ".redshift.amazonaws.com", ".docdb.amazonaws.com", ".mq.amazonaws.com", ".dax.amazonaws.com",
    ".execute-api.amazonaws.com", ".database.windows.net", ".redis.cache.windows.net",
    ".servicebus.windows.net", ".documents.azure.com", ".postgres.database.azure.com",
    ".mysql.database.azure.com", ".vault.azure.net", ".azurecr.io", ".mongodb.net",
    ".svc.cluster.local", ".cloudsql.google.com", ".supabase.co", ".neon.tech",
    ".upstash.io", ".firebaseio.com", ".pkg.dev",
)

# Bare hostnames (no scheme) under those suffixes, e.g. `host: my-cache.abc.use1.cache.amazonaws.com`.  # prescan:ignore
# The lookbehind skips hosts inside URLs (`://host`, `user:pass@host`): the URL pass reports those.
CLOUD_HOST_RE = _re(
    r"(?<![\w.\-@/])((?:[a-z0-9\-]+\.)+(?:"
    + "|".join(re.escape(sfx.lstrip(".")) for sfx in CLOUD_PRIVATE_SUFFIXES)
    + r"))(?![\w\-]|\.[\w\-])",
    re.IGNORECASE,
)

# Labels that hint at production / internal tooling. Low severity: a hint, not proof.
SENSITIVE_HOST_LABELS = (
    "prod", "production", "prd", "internal", "intranet", "corp", "admin", "vpn", "vault",
    "jenkins", "grafana", "kibana", "prometheus", "argocd", "sonar", "nexus", "artifactory",
    "jira", "confluence", "gitlab", "bastion", "jump",
)

# Never flagged as internal / prod
SAFE_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "example.com", "example.org", "example.net",
    "host.docker.internal", "gateway.docker.internal", "kubernetes.default.svc",
    "metadata.google.internal",
}
SAFE_HOST_SUFFIXES = (".example.com", ".example.org", ".example.net", ".example", ".test", ".invalid",
                      ".localhost")

# --------------------------------------------------------------------------- #
# Placeholder detection for generic rules
# --------------------------------------------------------------------------- #
PLACEHOLDER_RE = _re(
    r"(?i)^(?:x+|\*+|\.+|-+|_+|#+|0+|1234.*|changeme|change_me|changeit|example.*|sample.*|dummy.*|fake.*"
    r"|test.*|placeholder.*|redacted|todo|tbd|none|null|nil|undefined|true|false|secret|password"
    r"|pass|passwd|pwd|pass(?:word)?\d?|user(?:name)?|admin|root|guest|same-origin|include|omit"
    r"|your[_\-].*|my[_\-]?(?:secret|password|token|key).*|insert.*|replace.*|enter.*|<.*>|\[.*\]"
    r"|\$\{?.*|\{\{.*|%\(.*|%s|\?+|.*_here|.*xxxx.*)$"
)
# Values that are clearly code references rather than literals
CODE_REF_RE = _re(
    r"(?i)(?:^(?:process\.env|os\.environ|os\.getenv|getenv|env\(|ENV\[|config\.|settings\.|self\.|this\."
    r"|props\.|import\.meta|secrets\.|vars\.|inputs\.|params\.|request\.|req\.)|[()\[\]{}$]|^\w+\.\w+\.\w+)"
)


@dataclass
class CustomRuleSpec:
    """A user-defined content rule coming from .prescan.toml."""
    id: str
    pattern: str
    severity: str = MEDIUM
    description: str = "Custom rule"
    keywords: list[str] = field(default_factory=list)

    def compile(self) -> ContentRule:
        return ContentRule(
            id=self.id,
            description=self.description,
            severity=self.severity,
            pattern=re.compile(self.pattern),
            keywords=tuple(k.lower() for k in self.keywords),
            category="custom",
        )
