"""Pipeline and deployment files: CI/CD, Helm, Kubernetes, IaC, Ansible, Docker/Compose.

These files carry production configuration: environment variables, deployment targets, private
registries. A file classifier decides which context rules run on a file; a few rules (credentials
typed into commands, cloud account IDs) run on every file.

Every rule reports through the scanner's `add(rule_id, category, severity, description, start,
value, display=None)` callback, so redaction, inline ignores and snippets work as everywhere else.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import re
from typing import Callable

from . import rules as R

Add = Callable[..., None]

# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
CI_GLOBS = (
    ".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml",
    ".github/actions/*/action.yaml", ".gitlab-ci.yml", ".gitlab-ci/*.yml", ".gitlab/ci/*.yml",
    "Jenkinsfile", "Jenkinsfile.*", "*.jenkinsfile", "azure-pipelines*.yml", "azure-pipelines*.yaml",
    ".azure-pipelines/*.yml", ".azuredevops/*.yml", "bitbucket-pipelines.yml", ".circleci/config.yml",
    ".travis.yml", ".drone.yml", "buildspec*.yml", "buildspec*.yaml", "cloudbuild*.yaml",
    "cloudbuild*.yml", ".buildkite/*", ".tekton/*", "tekton/*", ".woodpecker.yml", ".woodpecker/*",
)
_CI_KINDS = re.compile(r"(?m)^kind:[ \t]*(?:Pipeline|PipelineRun|Task|TaskRun|Workflow|WorkflowTemplate)\b")
_K8S_API = re.compile(r"(?m)^apiVersion:[ \t]*\S+")
_K8S_KIND = re.compile(r"(?m)^kind:[ \t]*\w+")
_PROD_PATH = re.compile(r"(?:^|[/._\-])(?:prod|production|prd|live)(?:[/._\-]|$)", re.IGNORECASE)
_PROD_TEXT = re.compile(
    r"(?im)^[ \t]*-?[ \t]*(?:environment|env|stage|deploy_env|deployment_environment|ENVIRONMENT|ASPNETCORE_ENVIRONMENT"
    r"|NODE_ENV|SPRING_PROFILES_ACTIVE)[ \t]*[:=][ \t]*[\"']?(?:prod|production|prd)\b"
)


def _path_match(rel: str, glob: str) -> bool:
    if "/" in glob:
        return fnmatch.fnmatchcase(rel, glob) or fnmatch.fnmatchcase(rel, "*/" + glob)
    return fnmatch.fnmatchcase(rel.rsplit("/", 1)[-1], glob)


def classify(rel: str, text: str) -> frozenset[str]:
    name = rel.rsplit("/", 1)[-1]
    lname = name.lower()
    slashed = "/" + rel
    yaml = lname.endswith((".yml", ".yaml"))
    c: set[str] = set()
    if any(_path_match(rel, g) for g in CI_GLOBS) or (
            yaml and _CI_KINDS.search(text) and ("tekton.dev" in text or "argoproj.io" in text)):
        c.add("ci")
    if (name in ("Chart.yaml", "Chart.yml") or fnmatch.fnmatchcase(lname, "values*.y*ml")
            or fnmatch.fnmatchcase(lname, "helmfile*.y*ml")
            or ("/templates/" in slashed and lname.endswith((".yaml", ".yml", ".tpl")))):
        c.add("helm")
    if (yaml and _K8S_API.search(text) and _K8S_KIND.search(text)) or fnmatch.fnmatchcase(lname, "kustomization.y*ml"):
        c.add("k8s")
    if (lname.endswith((".tf", ".tf.json", ".tfvars", ".hcl")) or fnmatch.fnmatchcase(name, "Pulumi*.y*ml")
            or lname in ("serverless.yml", "serverless.yaml") or "AWSTemplateFormatVersion" in text[:4000]):
        c.add("iac")
    if (fnmatch.fnmatchcase(lname, "inventory*") or lname in ("hosts", "hosts.ini", "hosts.yml", "hosts.yaml")
            or "/group_vars/" in slashed or "/host_vars/" in slashed or "/inventories/" in slashed
            or fnmatch.fnmatchcase(lname, "playbook*.y*ml") or lname == "ansible.cfg"):
        c.add("ansible")
    if fnmatch.fnmatchcase(name, "Dockerfile*") or lname.endswith(".dockerfile") or fnmatch.fnmatchcase(name, "Containerfile*"):
        c.add("docker")
    if fnmatch.fnmatchcase(lname, "docker-compose*.y*ml") or fnmatch.fnmatchcase(lname, "compose*.y*ml"):
        c.add("compose")
    return frozenset(c)


def is_production(rel: str, text: str) -> bool:
    return bool(_PROD_PATH.search(rel) or _PROD_TEXT.search(text))


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #
# References to secrets stored elsewhere: CI secret stores, templating, Terraform variables, vaults.
_REFERENCE = re.compile(
    r"\$\{\{|\$\{|\$\(|^\$[A-Za-z_]|\{\{|\(\(|#\{|%\{|secretKeyRef|valueFrom|^vault:|^ref\+|"
    r"arn:aws[\w-]*:(?:secretsmanager|ssm)|^ssm:|^!(?:Ref|Sub|GetAtt|ImportValue|vault)\b|ENC\[|"
    r"credentials\(|^(?:env|secrets|vars|var|local|data|module|each|inputs|matrix|steps|needs)\.|"
    r"lookup\(|^@Microsoft\.KeyVault|^AQ[A-Za-z0-9+/]{100,}|"  # SealedSecret ciphertext
    r"^[\w.]+\(.*\)$|"                                        # function calls: file("x"), jsondecode(...)
    r"^\*[\w\-]+$|"                                          # YAML alias: *default_password
    r"^[a-z_][\w\-]*(?:\.[\w\-]+){2,}$",                        # Terraform refs: random_password.db.result
    re.IGNORECASE,
)
# For hosts, images and targets: only templating counts as "not a real value" (a hostname like
# registry.acme.internal must not be mistaken for a Terraform reference).
_TEMPLATED = re.compile(r"\$|\{\{|\(\(|#\{|%\{|<[^>]+>")

_SENSITIVE_NAME = (
    r"[A-Za-z0-9_.\-]*(?:password|passwd|pwd|_pass|secret|token|api[_\-]?key|apikey|access[_\-]?key"
    r"|private[_\-]?key|client[_\-]?secret|credentials?|passphrase|auth[_\-]?key|connection[_\-]?string)"
    r"[A-Za-z0-9_.\-]*"
)
_NOT_SECRET_NAME = re.compile(
    r"(?:url|uri|path|file|dir|endpoint|name|names|type|length|len|header|field|param|public|regex|pattern"
    r"|format|expires?|expiry|ttl|id|ref|arn|enabled|enable|policy|mode|version|key_id|keyid|ids|count"
    r"|required|rotation|lifetime|duration|timeout|min|max|length)$",
    re.IGNORECASE,
)


def clean_value(raw: str) -> str:
    v = raw.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'`":
        return v[1:-1]
    # unquoted YAML/INI: drop a trailing ` # comment`
    return re.split(r"[ \t]+#", v, maxsplit=1)[0].strip()


def is_literal_secret(value: str) -> bool:
    v = value.strip()
    if len(v) < 3 or v in ("|", ">", "|-", ">-", "~", "{}", "[]", "''", '""'):
        return False
    if _REFERENCE.search(v) or R.PLACEHOLDER_RE.match(v):
        return False
    return True


# --------------------------------------------------------------------------- #
# Rules on every file
# --------------------------------------------------------------------------- #
_Q = r"(?:\"[^\"\n]+\"|'[^'\n]+'|[^\s\"'`|;&)]+)"
CLI_PATTERNS = [
    re.compile(r"\b(?:docker|podman|buildah|nerdctl|helm|oras|skopeo|crane)\b[^\n]*?\blogin\b[^\n]*?"
               r"(?:[ \t]-p|--password)(?:[ \t]+|=)(?P<v>" + _Q + ")"),
    re.compile(r"\bmysql(?:dump|admin)?\b[^\n]*?[ \t]-p(?P<v>[^\s\"'`\-][^\s\"'`]*)"),
    re.compile(r"\b(?:curl|wget|http)\b[^\n]*?(?:[ \t]-u|--user)(?:[ \t]+|=)[\"']?[^\s:\"']+:(?P<v>[^\s\"'@]+)"),
    re.compile(r"(?i)\bAuthorization:[ \t]*(?:Bearer|Basic|Token)[ \t]+(?P<v>[A-Za-z0-9._~+/=\-]{12,})"),
    re.compile(r"\bsshpass\b[^\n]*?[ \t]-p[ \t]*(?P<v>" + _Q + ")"),
    re.compile(r"--from-literal[= ][\w.\-]+=(?P<v>" + _Q + ")"),
    re.compile(r"--set(?:-string)?[ \t]+(?:[\w.\-\[\]]+=[^\s,]*,)*[\w.\-\[\]]*"
               r"(?i:password|secret|token|apikey|api_key|accesskey|access_key)[\w.\-\[\]]*=(?P<v>[^\s,\"'`]+)"),
    re.compile(r"(?<![\w-])--(?:password|passwd|token|api-key|apikey|client-secret|secret-key|access-token"
               r"|auth-token|registry-password)(?:[ \t]+|=)(?P<v>\"[^\"\n]+\"|'[^'\n]+'|[^\s\"'`\-][^\s\"'`]*)"),
    re.compile(r"\b(?:PGPASSWORD|MYSQL_PWD|SSHPASS|REDISCLI_AUTH|ARTIFACTORY_PASSWORD|NPM_TOKEN|NODE_AUTH_TOKEN"
               r"|TWINE_PASSWORD|DOCKER_PASSWORD)=(?P<v>" + _Q + ")"),
]
_CLI_KEYWORDS = ("login", "mysql", "-u", "--user", "authorization", "sshpass", "from-literal", "--set",
                 "--pass", "--token", "--api", "--client", "--secret", "--access", "--auth", "--registry",
                 "password=", "pwd=", "token=", "sshpass=", "auth=")

_CLOUD_IDS = [
    (re.compile(r"arn:aws[\w-]*:[\w-]+:[\w-]*:(\d{12}):"), "AWS account ID"),
    (re.compile(r"\b(\d{12})\.dkr\.ecr\.[\w-]+\.amazonaws\.com"), "AWS account ID"),
    (re.compile(r"(?i)/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
     "Azure subscription ID"),
    (re.compile(r"(?i)(?:subscription|tenant)[_\-]?id[\"']?[ \t]*[:=][ \t]*[\"']?"
                r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"), "Azure subscription/tenant ID"),
]


def _plausible_cli_secret(raw: str, value: str) -> bool:
    """Prose like "the --password option" must not count: an unquoted value needs a digit or a
    symbol, or some length, to look like a credential."""
    quoted = raw.strip()[:1] in ("\"", "'")
    return quoted or len(value) >= 16 or not value.isalpha()


def scan_everywhere(text: str, lower: str, add: Add) -> None:
    if any(k in lower for k in _CLI_KEYWORDS):
        seen: set[int] = set()
        for pat in CLI_PATTERNS:
            for m in pat.finditer(text):
                value = clean_value(m.group("v"))
                start = m.start("v")
                if start in seen or not is_literal_secret(value) or not _plausible_cli_secret(m.group("v"), value):
                    continue
                seen.add(start)
                add("inline-cli-credential", "secret", R.HIGH, "Credential typed into a command", start, value)
    if "arn:aws" in lower or "dkr.ecr" in lower or "subscription" in lower or "tenant" in lower:
        for pat, label in _CLOUD_IDS:
            for m in pat.finditer(text):
                add("cloud-account-id", "infra", R.LOW, f"{label} (identifies your cloud account)",
                    m.start(1), m.group(1), display=m.group(1))


# --------------------------------------------------------------------------- #
# Context rules
# --------------------------------------------------------------------------- #
_ASSIGN = re.compile(
    r"(?m)^[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?(?P<qn>[\"']?)(?P<name>" + _SENSITIVE_NAME + r")(?P=qn)"
    r"[ \t]*(?::=|=|:(?=[ \t]|$))[ \t]*(?P<val>[^\n]*)$",
    re.IGNORECASE,
)
_DOCKER_ASSIGN = re.compile(
    r"(?m)^[ \t]*(?:ENV|ARG)[ \t]+(?P<name>" + _SENSITIVE_NAME + r")(?:[ \t]*=[ \t]*|[ \t]+)(?P<val>\S[^\n]*)$",
    re.IGNORECASE,
)
_K8S_ENV_PAIR = re.compile(
    r"(?m)^[ \t]*-?[ \t]*name:[ \t]*[\"']?(?P<name>" + _SENSITIVE_NAME + r")[\"']?[ \t]*\n"
    r"[ \t]*value:[ \t]*(?P<val>[^\n]*)$",
    re.IGNORECASE,
)

LITERAL_CONTEXTS = {"ci", "helm", "k8s", "iac", "ansible", "docker", "compose"}
IMAGE_CONTEXTS = {"docker", "compose", "k8s", "helm", "ci"}
TARGET_CONTEXTS = {"ci", "ansible", "docker", "compose", "helm", "k8s"}

PUBLIC_REGISTRIES = {
    "docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "quay.io", "gcr.io", "mirror.gcr.io",
    "mcr.microsoft.com", "public.ecr.aws", "registry.access.redhat.com", "registry.redhat.io",
    "registry.k8s.io", "k8s.gcr.io", "docker.elastic.co", "cgr.dev", "nvcr.io", "registry.gitlab.com",
}
PUBLIC_PACKAGE_HOSTS = {
    "pypi.org", "pypi.python.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com",
    "repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com", "proxy.golang.org", "rubygems.org",
    "api.nuget.org", "nuget.org", "conda.anaconda.org", "repo.anaconda.com", "download.pytorch.org",
    "plugins.gradle.org", "jcenter.bintray.com", "dl.google.com", "maven.google.com",
}
PACKAGE_CONFIG_FILES = (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", "settings.xml",
                        "requirements*.txt", "constraints*.txt", ".pypirc", "poetry.toml", "uv.toml")

_IMAGE_PATTERNS = [
    re.compile(r"(?im)^[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(?P<img>[^\s]+)"),
    re.compile(r"(?m)^[ \t]*-?[ \t]*image:[ \t]*[\"']?(?P<img>[^\s\"'#]+)"),
    re.compile(r"(?m)^[ \t]*-?[ \t]*(?:registry|imageRegistry|image_registry):[ \t]*[\"']?(?P<img>[^\s\"'#]+)"),
]
_PACKAGE_PATTERNS = [
    re.compile(r"--(?:extra-)?index-url(?:[ \t]+|=)[\"']?(?P<url>https?://[^\s\"']+)"),
    re.compile(r"(?<![\w-])-i[ \t]+[\"']?(?P<url>https?://[^\s\"']+)"),
    re.compile(r"(?im)^[ \t]*(?:@[\w-]+:)?registry[ \t]*=[ \t]*[\"']?(?P<url>https?://[^\s\"']+)"),
    re.compile(r"(?i)npmRegistryServer:[ \t]*[\"']?(?P<url>https?://[^\s\"']+)"),
    re.compile(r"(?i)(?:npm|yarn|pnpm)[ \t]+config[ \t]+set[ \t]+(?:@[\w-]+:)?registry[ \t]+[\"']?(?P<url>https?://[^\s\"']+)"),
    re.compile(r"(?:GOPROXY|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|NPM_CONFIG_REGISTRY)[ \t]*[=:][ \t]*[\"']?(?P<url>https?://[^\s\"',|]+)"),
    re.compile(r"(?i)<url>[ \t]*(?P<url>https?://[^<\s]+)[ \t]*</url>"),
    re.compile(r"(?im)^[ \t]*(?:index-url|extra-index-url|url)[ \t]*=[ \t]*[\"']?(?P<url>https?://[^\s\"']+)"),
]
_TARGET_PATTERNS = [
    re.compile(r"\b(?:ssh|scp|rsync|sftp)\b[^\n]*?(?<![\w.@-])(?P<v>[\w.\-]+@(?:[\w\-]+\.)+[\w\-]+|[\w.\-]+@\d{1,3}(?:\.\d{1,3}){3})"),
    re.compile(r"(?:--context|--kube-context|--kubecontext)(?:[ \t]+|=)[\"']?(?P<v>[\w.:/@\-]+)"),
    re.compile(r"use-context[ \t]+[\"']?(?P<v>[\w.:/@\-]+)"),
    re.compile(r"(?im)^[ \t]*-?[ \t]*(?:cluster|cluster_name|clusterName|kube_context|kubeContext|kubernetes_cluster)"
               r"[ \t]*:[ \t]*[\"']?(?P<v>[\w.:/@\-]{3,})"),
    re.compile(r"\bansible_host[ \t]*[=:][ \t]*[\"']?(?P<v>[\w.\-]+)"),
]
_PUBLIC_SSH_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "ssh.dev.azure.com", "vs-ssh.visualstudio.com")

_SECRET_FILE_REF = re.compile(
    r"(?<![\w$%{}])("
    r"(?:[~.]{0,2}/)?(?:[\w.@\-]+/)*(?:[\w.@\-]+\.(?:key|p12|pfx|keytab|jks|kdb|sth|ppk|p8)"
    r"|[\w.@\-]*key[\w.@\-]*\.pem)"  # .pem is usually a public cert; only *key*.pem counts
    r"|(?:[~.]{0,2}/)?(?:[\w.@\-]+/)*(?:id_rsa|id_ed25519|id_ecdsa|kubeconfig|credentials\.json"
    r"|service-account[\w.\-]*\.json|client_secret[\w.\-]*\.json)"
    r"|(?:\.{0,2}/)?(?:[\w.@\-]+/)*\.env(?:\.[\w\-]+)?"
    r"|/(?:etc|run|var/run|mnt|vault)/secrets?/(?!kubernetes\.io/|eks\.amazonaws\.com/)\w[\w./\-]*"
    r"|(?:[\w.@\-]+/)*secrets?/[\w.\-]+\.(?:json|ya?ml|env|txt|properties|conf|ini)"
    r")(?![\w.\-/])"
)
_EXAMPLE_SUFFIX = re.compile(r"\.(?:example|sample|template|dist|defaults|tpl|schema)$", re.IGNORECASE)

_DOCKER_UID = [
    re.compile(r"(?im)^[ \t]*USER[ \t]+(?P<v>\d+(?::\d+)?)\b"),
    re.compile(r"\b(?:useradd|adduser|groupadd|addgroup|usermod)\b[^\n]*?(?:[ \t]-u|[ \t]-g|--uid|--gid)"
               r"(?:[ \t]+|=)(?P<v>\d{3,})"),
]
_TF_BACKEND = re.compile(r"\bbackend[ \t]+\"(?P<v>s3|gcs|azurerm|remote|http|consul|pg|cos|oss)\"[ \t]*\{")


def _registry_host(image: str) -> str | None:
    """Registry host of an image reference, or None for Docker Hub / stage names / references."""
    if _TEMPLATED.search(image) or "/" not in image:
        return None
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first.lower()
    return None


def _host_of(url: str) -> str:
    return re.sub(r"^[a-z]+://(?:[^@/]*@)?", "", url.lower()).split("/", 1)[0].split(":", 1)[0]


def _is_public_registry(host: str, extra: set[str]) -> bool:
    bare = host.split(":", 1)[0]
    return bare in PUBLIC_REGISTRIES or bare in extra or bare.endswith((".gcr.io", ".docker.io"))


def scan_context(rel: str, text: str, classes: frozenset[str], add: Add,
                 public_registries: set[str] | None = None) -> None:
    extra = public_registries or set()
    # Encrypted content is recognised per value (SOPS `ENC[...]`, Ansible `!vault`, SealedSecret
    # ciphertext), never per file: SOPS leaves `*_unencrypted` keys in plain text on purpose.

    # 1. literal values under sensitive names
    if classes & LITERAL_CONTEXTS:
        patterns = [_ASSIGN, _K8S_ENV_PAIR] + ([_DOCKER_ASSIGN] if "docker" in classes else [])
        seen: set[int] = set()
        for pat in patterns:
            for m in pat.finditer(text):
                name, raw = m.group("name"), m.group("val")
                if _NOT_SECRET_NAME.search(name.strip("\"'")):
                    continue
                value = clean_value(raw)
                start = m.start("val") + (raw.find(value) if value and value in raw else 0)
                if start in seen or not is_literal_secret(value):
                    continue
                seen.add(start)
                add("ci-literal-env", "secret", R.HIGH,
                    f"Literal secret in a pipeline/deployment file ({name.strip(chr(34) + chr(39))})", start, value)

    # 2. Kubernetes Secret manifests
    if classes & {"k8s", "helm"} and "Secret" in text:
        _scan_k8s_secrets(text, add)

    # 3. images from private registries
    if classes & IMAGE_CONTEXTS:
        for pat in _IMAGE_PATTERNS:
            if pat is _IMAGE_PATTERNS[2] and "helm" not in classes:
                continue
            for m in pat.finditer(text):
                img = m.group("img")
                host = img.lower() if pat is _IMAGE_PATTERNS[2] and "/" not in img else _registry_host(img)
                if host and not _TEMPLATED.search(host) and "." in host and not _is_public_registry(host, extra):
                    add("private-registry-image", "infra", R.MEDIUM,
                        f"Image from a private registry ({host})", m.start("img"), host, display=host)

    # 4. private package registries (Docker/CI files and package-manager config files)
    name = rel.rsplit("/", 1)[-1]
    if classes & {"docker", "ci", "compose"} or any(fnmatch.fnmatchcase(name, g) for g in PACKAGE_CONFIG_FILES):
        for pat in _PACKAGE_PATTERNS:
            for m in pat.finditer(text):
                host = _host_of(m.group("url"))
                if host and host not in PUBLIC_PACKAGE_HOSTS and host not in extra and not _TEMPLATED.search(host):
                    add("private-package-registry", "infra", R.MEDIUM,
                        f"Private package registry ({host})", m.start("url"), host, display=host)

    # 5. deployment targets: SSH targets, kube contexts/clusters, Ansible hosts
    if classes & TARGET_CONTEXTS:
        for pat in _TARGET_PATTERNS:
            for m in pat.finditer(text):
                v = m.group("v").strip("\"'")
                host = v.split("@")[-1].lower()
                if _TEMPLATED.search(v) or host in _PUBLIC_SSH_HOSTS or host in ("localhost", "127.0.0.1") \
                        or R.PLACEHOLDER_RE.match(v):
                    continue
                add("deploy-target", "infra", R.MEDIUM, "Deployment target (host / cluster / context)",
                    m.start("v"), v, display=v)

    # 6. Dockerfile numeric user / group IDs
    if "docker" in classes:
        for pat in _DOCKER_UID:
            for m in pat.finditer(text):
                add("dockerfile-user-id", "infra", R.MEDIUM, "Numeric user/group ID in a Dockerfile",
                    m.start("v"), m.group("v"), display=m.group("v"))

    # 7. Terraform remote state backends (warning)
    if "iac" in classes:
        for m in _TF_BACKEND.finditer(text):
            add("tf-backend", "infra", R.LOW, f"Terraform remote state backend ({m.group('v')})",
                m.start("v"), m.group("v"), display=m.group("v"))

    # 8. references to secret files (warning): reveals where secrets live
    if classes:
        for m in _SECRET_FILE_REF.finditer(text):
            path = m.group(1)
            if _EXAMPLE_SUFFIX.search(path) or len(path) < 5:
                continue
            add("secret-file-reference", "infra", R.LOW, "Reference to a secret file path", m.start(1), path,
                display=path)


# --------------------------------------------------------------------------- #
# Kubernetes Secrets
# --------------------------------------------------------------------------- #
_DATA_HEADER = re.compile(r"(?m)^(?P<indent>[ \t]*)(?P<kind>data|stringData):[ \t]*$")
_DATA_ITEM = re.compile(r"^(?P<indent>[ \t]+)(?P<key>[\w.\-]+):[ \t]*(?P<val>.*?)[ \t]*$")
_KNOWN_TOKEN_RULES = [r for r in R.CONTENT_RULES if not r.generic and r.category == "secret"]


def _decode(value: str) -> str | None:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _scan_k8s_secrets(text: str, add: Add) -> None:
    offset = 0
    for doc in re.split(r"(?m)^---[ \t]*$", text):
        doc_start = text.find(doc, offset) if doc else offset
        offset = doc_start + len(doc)
        if not re.search(r"(?m)^kind:[ \t]*Secret[ \t]*$", doc):
            continue  # also skips SealedSecret, whose values are ciphertext
        for h in _DATA_HEADER.finditer(doc):
            base = len(h.group("indent").expandtabs())
            pos = h.end() + 1
            for line in doc[pos:].split("\n"):
                if not line.strip():
                    pos += len(line) + 1
                    continue
                m = _DATA_ITEM.match(line)
                if not m or len(m.group("indent").expandtabs()) <= base:
                    break
                value = clean_value(m.group("val"))
                if value and value not in ("|", ">", "|-", ">-") and not _REFERENCE.search(value):
                    decoded = _decode(value) if h.group("kind") == "data" else value
                    what = next((r.description for r in _KNOWN_TOKEN_RULES
                                 if decoded and r.pattern.search(decoded)), None)
                    desc = f"Kubernetes Secret value ({m.group('key')})" + (f", decodes to: {what}" if what else "")
                    start = doc_start + pos + m.start("val") + max(m.group("val").find(value), 0)
                    add("k8s-secret-data", "secret", R.HIGH, desc, start, value)
                pos += len(line) + 1
