"""Shared primitives for the vercel-forensics skill: endpoint + query
allowlist, ingress projection, TOCTOU-safe atomic writes, token-source
hierarchy, rate-limit sleep, redacting request logger, advisory lockfile,
and the single-string redactor used by redact.py and log_request.

Python 3.10 stdlib only. Used by every Python script in this skill.

Authoritative contracts: references/allowlist-enforcement.md,
api-endpoint-reference.md, collection-patterns.md.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import sys
import time
import urllib.parse
from dataclasses import dataclass
from getpass import getpass
from typing import Any, Iterable, Optional

__all__ = [
    "PreservationViolation",
    "ALLOWED_PATHS", "SAFE_FIELDS", "REJECTED_QUERY_PARAMS",
    "LOG_REDACT_QUERY_KEYS", "DENY_SUBSTRINGS",
    "validate_url", "project_fields", "atomic_write",
    "get_token", "token_hash", "rate_limit_sleep", "log_request",
    "acquire_lock", "release_lock", "redact_value",
]

@dataclass
class PreservationViolation(Exception):
    """Raised when validate_url rejects a request."""

    reason: str
    offending: str

    def __str__(self) -> str:  # pragma: no cover
        return f"PreservationViolation({self.reason}): {self.offending}"

# Path templates use ":param" placeholders (single non-"/" segment). "decrypt"
# and "reveal" query keys are rejected unconditionally (REJECTED_QUERY_PARAMS)
# regardless of per-path allowance. See allowlist-enforcement.md §1.
ALLOWED_PATHS: dict[str, set[str]] = {
    # Vercel — team context
    "/v2/teams/:tid": {"teamId"},
    "/v2/teams/:tid/members": {"teamId", "limit", "since", "until"},
    "/v1/teams/:tid/audit-log": {"teamId", "limit", "since", "until"},
    "/v5/user/tokens": {"teamId"},
    "/v3/events": {"teamId", "limit", "since", "until", "types", "userId", "next"},
    "/v1/log-drains": {"teamId", "projectId"},
    "/v1/access-groups": {"teamId"},
    "/v1/integrations/configurations": {"teamId", "view"},
    "/v1/integrations/configurations/:cid": {"teamId"},
    "/v5/domains": {"teamId", "limit", "since", "until"},
    "/v4/aliases": {"teamId", "limit", "since", "until", "projectId"},
    "/v4/certs": {"teamId", "limit", "since", "until"},
    "/v1/webhooks": {"teamId"},
    "/v1/edge-config": {"teamId"},
    "/v1/edge-config/:ecid/items": {"teamId"},
    # Vercel — projects
    "/v9/projects": {"teamId", "limit", "since", "until"},
    "/v9/projects/:pid": {"teamId"},
    "/v9/projects/:pid/env": {"teamId"},
    "/v9/projects/:pid/domains": {"teamId"},
    "/v9/projects/:pid/deployment-retention-policy": {"teamId"},
    "/v9/projects/:pid/access-groups": {"teamId"},
    "/v1/projects/:pid/logs": {"teamId", "limit", "since", "until"},
    # Vercel — deployments
    "/v6/deployments": {"teamId", "projectId", "limit", "since", "until", "target", "state"},
    "/v13/deployments/:did": {"teamId"},
    "/v3/deployments/:did/events": {"teamId", "builds", "direction", "limit"},
    "/v6/deployments/:did/files": {"teamId"},
    "/v7/deployments/:did/files/:fid": {"teamId"},
    # Vercel — security / firewall
    "/v1/security/firewall/config/active": {"teamId", "projectId"},
    "/v1/security/firewall/bypass": {"teamId", "projectId"},
    "/v1/security/firewall/attack-status": {"teamId", "projectId"},
    # GitHub — REST
    "/users/:uid": set(),
    "/orgs/:org/audit-log": {"phrase", "include", "per_page", "after", "before", "order"},
    "/enterprises/:ent/audit-log": {"phrase", "include", "per_page", "after", "before", "order"},
    "/orgs/:org/installations": {"per_page", "page"},
    "/repos/:org/:repo": set(),
    "/repos/:org/:repo/hooks": {"per_page", "page"},
    "/repos/:org/:repo/keys": {"per_page", "page"},
    "/repos/:org/:repo/branches/:branch/protection": set(),
    "/repos/:org/:repo/actions/secrets": {"per_page", "page"},
    "/repos/:org/:repo/dependabot/alerts": {"per_page", "page", "state"},
    # GraphQL POSTs are handled outside validate_url; the body is validated
    # separately to refuse operations prefixed "mutation".
}

REJECTED_QUERY_PARAMS: frozenset[str] = frozenset({"decrypt", "reveal"})

# log_request() redacts values of any query param whose key matches here
# (case-insensitive). Distinct from REJECTED_QUERY_PARAMS: those cause the
# request to be refused outright; these only redact the log line.
LOG_REDACT_QUERY_KEYS: frozenset[str] = frozenset({
    "token", "api_key", "apikey", "secret", "access_token",
    "client_secret", "password", "authorization",
})

# project_fields() denylist. A field name that CONTAINS any substring here
# (case-insensitive) is dropped, EXCEPT when the name equals the substring
# exactly — preserves legitimate identifiers like env_var.key.
DENY_SUBSTRINGS: tuple[str, ...] = (
    "secret", "key", "token", "password", "credential",
    "value", "decrypted", "reveal",
)

# Per-resource top-level whitelist; see allowlist-enforcement.md §3.
SAFE_FIELDS: dict[str, set[str]] = {
    "team": {"id", "slug", "name", "createdAt", "updatedAt",
             "billing", "resourceConfig", "saml"},
    "member": {"uid", "email", "role", "confirmed", "createdAt",
               "joinedFrom", "teamRoles", "teamPermissions"},
    "user_token": {"id", "name", "type", "origin", "scopes",
                   "activeAt", "createdAt", "expiresAt"},
    "integration": {"id", "slug", "integrationId", "name", "teamId", "userId",
                    "source", "type", "createdAt", "updatedAt", "scopes",
                    "projects", "permissions", "installationType"},
    "log_drain": {"id", "name", "clientId", "configurationId", "teamId",
                  "createdAt", "deliveryFormat", "sources", "url"},
    "project": {"id", "name", "accountId", "teamId", "createdAt", "updatedAt",
                "link", "framework", "latestDeployments", "targets", "env",
                "ssoProtection", "passwordProtection", "trustedIps",
                "rollingRelease", "gitForkProtection"},
    "env_var": {"id", "key", "type", "target", "gitBranch", "configurationId",
                "createdAt", "updatedAt", "lastUpdatedBy", "lastUpdatedByDisplayName"},
    "deployment": {"uid", "name", "url", "created", "source", "state", "target",
                   "creator", "meta", "inspectorUrl", "projectId", "teamId",
                   "buildingAt", "ready", "readyState"},
    "domain": {"name", "apexName", "projectId", "verified", "verification",
               "createdAt", "updatedAt", "redirect", "redirectStatusCode", "gitBranch"},
    "alias": {"uid", "alias", "deploymentId", "projectId", "createdAt", "protectionBypass"},
    "cert": {"id", "cns", "createdAt", "expiresAt", "autoRenew"},
    "webhook": {"id", "url", "events", "projectIds", "teamId", "createdAt", "updatedAt"},
    "firewall_config": {"version", "updatedAt", "firewallEnabled", "managedRules",
                        "customRules", "ipRules", "crs", "bypass", "attackChallengeMode"},
    "access_group": {"id", "name", "teamId", "createdAt", "membersCount", "projectsCount"},
    "edge_config": {"id", "slug", "createdAt", "updatedAt",
                    "sizeInBytes", "itemCount", "digest"},
    "activity_event": {"id", "type", "principalId", "userId", "createdAt", "payload"},
    "github_audit_event": {"@timestamp", "action", "actor", "actor_ip", "user",
                           "org", "repo", "hashed_token", "business",
                           "created_at", "operation_type"},
    "github_repo_graphql": {"name", "nameWithOwner", "isArchived", "visibility",
                            "pushedAt", "defaultBranchRef", "deployKeys"},
}

_ALLOWED_METHODS: frozenset[str] = frozenset({"GET"})
_ALLOWED_HOSTS: frozenset[str] = frozenset({"api.vercel.com", "api.github.com"})

def _normalize_path(path: str) -> Optional[str]:
    """Match path against ALLOWED_PATHS templates; return template on hit."""
    segments = [s for s in path.split("/") if s != ""]
    for template in ALLOWED_PATHS:
        tpl_segs = [s for s in template.split("/") if s != ""]
        if len(tpl_segs) != len(segments):
            continue
        match = True
        for t, p in zip(tpl_segs, segments):
            if t.startswith(":"):
                if not p:
                    match = False
                    break
                continue
            if t != p:
                match = False
                break
        if match:
            return template
    return None

def validate_url(url: str, method: str = "GET") -> str:
    """Validate url against ALLOWED_PATHS; return url unchanged on success.

    Rejects non-GET, unknown host/path, unknown query param, decrypt/reveal
    (case-insensitive), malformed URL — all via PreservationViolation.
    """
    if method.upper() not in _ALLOWED_METHODS:
        raise PreservationViolation(reason=f"http-verb-not-allowed:{method}", offending=url)
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise PreservationViolation(reason="malformed-url", offending=url) from exc
    if parsed.scheme not in ("http", "https"):
        raise PreservationViolation(reason="scheme-not-allowed", offending=url)
    host = parsed.hostname or ""
    if host not in _ALLOWED_HOSTS:
        raise PreservationViolation(reason=f"host-not-allowed:{host}", offending=url)

    template = _normalize_path(parsed.path)
    if template is None:
        raise PreservationViolation(reason="path-not-in-allowlist", offending=parsed.path)

    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    # Reject rules run BEFORE allowlist check so error names the bad param.
    for key, _ in query_pairs:
        if key.lower() in REJECTED_QUERY_PARAMS:
            raise PreservationViolation(
                reason=f"query-param-explicitly-rejected:{key}",
                offending=url,
            )
    allowed_params = ALLOWED_PATHS[template]
    for key, _ in query_pairs:
        if key not in allowed_params:
            raise PreservationViolation(
                reason=f"query-param-not-in-allowlist:{key} (path={template})",
                offending=url,
            )
    return url

def _field_is_denied(name: str) -> bool:
    """Match compound names (apiKey, clientSecret) but not exact (env_var.key)."""
    lowered = name.lower()
    return any(sub in lowered and lowered != sub for sub in DENY_SUBSTRINGS)

def project_fields(obj: Any, kind: str) -> Any:
    """Project top-level fields per SAFE_FIELDS[kind] + substring denylist.

    Lists preserved; dict elements recursively projected with the same kind.
    Primitives pass through. Unknown kinds raise KeyError.
    """
    if kind not in SAFE_FIELDS:
        raise KeyError(f"project_fields: unknown resource kind '{kind}'")
    allowed = SAFE_FIELDS[kind]
    if isinstance(obj, list):
        return [project_fields(item, kind) for item in obj]
    if not isinstance(obj, dict):
        return obj
    projected: dict[str, Any] = {}
    for field_name, field_value in obj.items():
        if field_name not in allowed:
            continue
        if _field_is_denied(field_name):
            continue
        projected[field_name] = field_value
    return projected

def atomic_write(path: str, content: bytes | str, mode: int = 0o600) -> None:
    """Write content to path atomically. Refuse overwrite and symlink targets.

    Uses .tmp + O_EXCL + fsync + os.rename (atomic on same filesystem).
    str is utf-8 encoded.
    """
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(lst.st_mode):
            raise FileExistsError(f"atomic_write: refuse symlink target: {path}")
        raise FileExistsError(f"atomic_write: refuse overwrite: {path}")

    tmp_path = path + ".tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(tmp_path, flags, mode)
    try:
        data = content.encode("utf-8") if isinstance(content, str) else content
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)

    try:
        os.chmod(tmp_path, mode)
        os.rename(tmp_path, path)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

def _read_token_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()

def get_token(source_priority: Optional[Iterable[str]] = None) -> tuple[str, str]:
    """Return (token, source) where source in {"file", "env", "getpass"}.

    Precedence: --token-file <path> → $VERCEL_TOKEN/$GH_TOKEN → getpass(TTY).
    --token <value> is REJECTED (shell-history + ps(1) leak). source_priority
    overrides the env-var order — pass ("VERCEL_TOKEN",) or ("GH_TOKEN",).
    Prints `Token source: <source>` to stderr; never logs the token value.
    """
    argv = sys.argv[1:]

    if "--token" in argv:
        print(
            "WARN: --token <value> is rejected (shell-history + ps(1) leak). "
            "Use --token-file <path> or $VERCEL_TOKEN / $GH_TOKEN instead.",
            file=sys.stderr,
        )
        raise PreservationViolation(reason="token-cli-arg-rejected", offending="--token")

    if "--token-file" in argv:
        idx = argv.index("--token-file")
        if idx + 1 >= len(argv):
            raise PreservationViolation(reason="token-file-arg-missing-value", offending="--token-file")
        token_path = argv[idx + 1]
        token = _read_token_file(token_path)
        if not token:
            raise PreservationViolation(reason="token-file-empty", offending=token_path)
        print("Token source: file", file=sys.stderr)
        return token, "file"

    env_keys = tuple(source_priority) if source_priority else ("VERCEL_TOKEN", "GH_TOKEN")
    for key in env_keys:
        value = os.environ.get(key)
        if value:
            print(f"Token source: env ({key})", file=sys.stderr)
            return value, "env"

    if sys.stdin.isatty():
        token = getpass("Enter token (input hidden): ").strip()
        if not token:
            raise PreservationViolation(reason="token-getpass-empty", offending="getpass")
        print("Token source: getpass", file=sys.stderr)
        return token, "getpass"

    raise PreservationViolation(reason="no-token-available", offending="get_token")

def token_hash(token: str) -> str:
    """Return 16-char sha256 prefix for lockfile / manifest identification."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

def _header_get(response: Any, name: str) -> Optional[str]:
    """Read a header case-insensitively from urllib or dict-like response."""
    headers = getattr(response, "headers", None)
    if headers is not None:
        try:
            value = headers.get(name)
            if value is not None:
                return str(value)
        except AttributeError:
            pass
    if isinstance(response, dict):
        for k, v in response.items():
            if k.lower() == name.lower():
                return str(v)
    return None

def rate_limit_sleep(response: Any) -> float:
    """Sleep per rate-limit headers; return seconds slept.

    Prefers Retry-After (seconds) over X-RateLimit-Reset (unix-epoch delta).
    Returns 0.0 if neither present. Any 429 forces a minimum 1.0s sleep.
    """
    status = getattr(response, "status", None) or getattr(response, "code", None)
    sleep_for = 0.0
    retry_after = _header_get(response, "Retry-After")
    if retry_after is not None:
        try:
            sleep_for = float(retry_after)
        except ValueError:
            pass
    if sleep_for == 0.0:
        reset = _header_get(response, "X-RateLimit-Reset")
        if reset is not None:
            try:
                delta = float(reset) - time.time()
                if delta > 0:
                    sleep_for = delta
            except ValueError:
                pass
    if status == 429:
        sleep_for = max(sleep_for, 1.0)
    if sleep_for > 0.0:
        time.sleep(sleep_for)
    return sleep_for

# Compiled once. Each entry is (compiled regex, replacement str OR callable).
_REDACTION_RULES: list[tuple[re.Pattern[str], Any]] = [
    (re.compile(r"(https?://discord\.com/api/webhooks/\d+/)([A-Za-z0-9_\-]+)"),
     lambda m: f"{m.group(1)}[REDACTED-{len(m.group(2))}char-discord]"),
    (re.compile(r"https?://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
     "[REDACTED-slack-webhook]"),
    (re.compile(r"(https?://)([^/:@\s]+):([^/@\s]+)@"),
     lambda m: f"{m.group(1)}[REDACTED-basicauth]@"),
    (re.compile(
        r"([?&](?:api_?key|token|secret|access_token|client_secret|password|"
        r"authorization|sig|sv|X-Amz-Signature|X-Amz-Credential)=)"
        r"([^&#\s]+)",
        re.IGNORECASE,
     ), lambda m: f"{m.group(1)}[REDACTED-{len(m.group(2))}char-qs]"),
    (re.compile(r"\b(ghp_|github_pat_|gho_|ghu_|ghs_)[A-Za-z0-9_]{20,255}\b"),
     lambda m: f"{m.group(1)}[REDACTED-ghpat]"),
    (re.compile(r"\b(sk_live_|rk_live_|whsec_)[A-Za-z0-9]{16,}\b"),
     lambda m: f"{m.group(1)}[REDACTED-stripe]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
     "[REDACTED-jwt]"),
    (re.compile(
        r'"private_key"\s*:\s*"-----BEGIN[^"]+?-----\\n[^"]+?-----END[^"]+?-----\\n?"'
     ), '"private_key":"[REDACTED-gcp-sa]"'),
    (re.compile(
        r"\b(?:10(?:\.\d{1,3}){3}|"
        r"192\.168(?:\.\d{1,3}){2}|"
        r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
     ), "[REDACTED-rfc1918]"),
]

def redact_value(s: str) -> str:
    """Apply every redaction rule to s; return the redacted string (idempotent)."""
    if not s:
        return s
    out = s
    for pattern, repl in _REDACTION_RULES:
        out = pattern.sub(repl, out)
    return out

def log_request(url: str, method: str, token_source: str = "?") -> None:
    """Emit a redacted request summary to stderr. No disk, no headers.

    No `headers` parameter by design; the final line is run through
    redact_value() to catch secrets embedded in path segments.
    """
    parsed = urllib.parse.urlsplit(url)
    redacted_pairs: list[tuple[str, str]] = []
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        redacted_pairs.append((key, "[REDACTED]" if key.lower() in LOG_REDACT_QUERY_KEYS else value))
    query_out = urllib.parse.urlencode(redacted_pairs)
    path_with_query = parsed.path + (("?" + query_out) if query_out else "")
    line = f"{method} {path_with_query} (token_source={token_source})"
    print(redact_value(line), file=sys.stderr)

_LOCK_DIR = os.path.expanduser("~/.vercel-forensics")
_lock_fds: dict[str, int] = {}

def _lock_path(token_hash_hex: str) -> str:
    return os.path.join(_LOCK_DIR, f".lock-{token_hash_hex}")

def acquire_lock(token_hash_hex: str) -> bool:
    """Acquire fcntl.flock on ~/.vercel-forensics/.lock-<hash>. Return False if held."""
    os.makedirs(_LOCK_DIR, mode=0o700, exist_ok=True)
    path = _lock_path(token_hash_hex)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    except OSError:
        pass
    _lock_fds[token_hash_hex] = fd
    return True

def release_lock(token_hash_hex: str) -> None:
    """Release the fcntl.flock acquired by acquire_lock."""
    fd = _lock_fds.pop(token_hash_hex, None)
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass

def _self_check() -> int:  # pragma: no cover
    validate_url("https://api.vercel.com/v2/teams/team_abc123?teamId=team_abc123")
    validate_url("https://api.github.com/repos/acme/widgets/hooks")
    for bad_url, expected in (
        ("https://api.vercel.com/v9/projects/p_1/env?teamId=t&decrypt=1", "query-param-explicitly-rejected"),
        ("https://api.vercel.com/v9/projects/p_1/env?teamId=t&Reveal=1", "query-param-explicitly-rejected"),
        ("https://api.evil.example/v2/teams/t", "host-not-allowed"),
        ("https://api.vercel.com/nope/path", "path-not-in-allowlist"),
        ("https://api.vercel.com/v2/teams/t?wat=1", "query-param-not-in-allowlist"),
    ):
        try:
            validate_url(bad_url)
        except PreservationViolation as exc:
            assert exc.reason.startswith(expected), (bad_url, exc)
        else:
            raise AssertionError(f"expected rejection: {bad_url}")
    try:
        validate_url("https://api.vercel.com/v2/teams/t?teamId=t", method="DELETE")
    except PreservationViolation as exc:
        assert exc.reason.startswith("http-verb-not-allowed"), exc
    projected = project_fields(
        {"key": "DB_URL", "value": "leak", "type": "encrypted", "apiKey": "x"}, "env_var",
    )
    assert projected == {"key": "DB_URL", "type": "encrypted"}, projected
    r = redact_value("token=ghp_abcdefghijklmnopqrstuvwxyz012345")
    assert "ghp_abcdefg" not in r
    print("_common.py self-check OK")
    return 0

if __name__ == "__main__":
    sys.exit(_self_check())
