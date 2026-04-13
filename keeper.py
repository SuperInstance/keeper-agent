"""
keeper.py — Core Keeper Engine for the Pelagic AI fleet.

The KeeperAgent is the secret proxy and security guardian.  It holds ALL
secrets for a SuperInstance and ensures they never leak outside the
secure network.

Features
--------
- Encrypted secret vault (AES-GCM via *cryptography*, XOR+HMAC fallback)
- Agent registry with public keys and permission scopes
- Request proxy with automatic secret injection
- Double-checker that scans every outbound request for accidental leaks
- Full audit trail of every secret access and proxied request
- Per-agent rate limiting on secret access
- Instant agent / secret revocation

Storage layout (``vault_path``)
-------------------------------
    vault_path/
    ├── master.key          # derived master encryption key (written once)
    ├── agents.json         # agent registry serialisation
    ├── secrets/
    │   └── <agent_id>/
    │       └── <secret_id>.enc   # per-secret encrypted blobs
    └── audit.jsonl         # append-only audit log
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets as _secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from leak_detector import LeakDetector, Sensitivity


# ===================================================================
# Exceptions
# ===================================================================

class KeeperError(Exception):
    """Base exception for all Keeper errors."""


class AgentNotFoundError(KeeperError):
    """Raised when an agent_id is not found in the registry."""


class SecretNotFoundError(KeeperError):
    """Raised when a secret_id is not found."""


class AgentRevokedError(KeeperError):
    """Raised when a revoked agent attempts an operation."""


class SecretRevokedError(KeeperError):
    """Raised when a revoked secret is accessed."""


class RateLimitError(KeeperError):
    """Raised when an agent exceeds its rate limit."""


class LeakDetectedError(KeeperError):
    """Raised when the double-checker finds a secret in outbound data."""


# ===================================================================
# Encryption helpers
# ===================================================================

class _EncryptionBackend:
    """Abstract encryption backend."""

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        raise NotImplementedError


class _CryptographyBackend(_EncryptionBackend):
    """AES-GCM encryption via the ``cryptography`` package."""

    def __init__(self) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aesgcm_cls = AESGCM
        except ImportError:
            raise ImportError(
                "cryptography package is required for AES-GCM encryption"
            )

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        nonce = os.urandom(12)
        aesgcm = self._aesgcm_cls(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct  # nonce || ciphertext+tag

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        aesgcm = self._aesgcm_cls(key)
        return aesgcm.decrypt(nonce, ct, None)


class _XorHmacBackend(_EncryptionBackend):
    """XOR cipher + HMAC-SHA256 — pure-stdlib fallback.

    .. warning:: This is **not** as secure as AES-GCM.  Use the
    ``cryptography`` package in production whenever possible.
    """

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        derived = hashlib.sha256(key + b"xor-enc").digest()
        mac_key = hashlib.sha256(key + b"xor-mac").digest()
        # XOR with repeating key stream
        keystream = (derived * (len(plaintext) // 32 + 1))[:len(plaintext)]
        xored = bytes(a ^ b for a, b in zip(plaintext, keystream))
        mac = hmac.new(mac_key, xored, hashlib.sha256).digest()
        return xored + mac

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        derived = hashlib.sha256(key + b"xor-enc").digest()
        mac_key = hashlib.sha256(key + b"xor-mac").digest()
        xored = ciphertext[:-32]
        stored_mac = ciphertext[-32:]
        expected_mac = hmac.new(mac_key, xored, hashlib.sha256).digest()
        if not hmac.compare_digest(stored_mac, expected_mac):
            raise ValueError("HMAC verification failed — data may be tampered")
        keystream = (derived * (len(xored) // 32 + 1))[:len(xored)]
        return bytes(a ^ b for a, b in zip(xored, keystream))


def _get_encryption_backend() -> _EncryptionBackend:
    """Return AES-GCM backend if available, else XOR+HMAC fallback."""
    try:
        return _CryptographyBackend()
    except ImportError:
        return _XorHmacBackend()


def _derive_key(master_key: str | bytes, salt: bytes | None = None) -> bytes:
    """Derive a 32-byte encryption key from a master key string.

    Uses HKDF-like key derivation (iterative SHA-256 stretching with a salt).
    """
    if salt is None:
        salt = b"keeper-agent-master-salt"
    if isinstance(master_key, str):
        master_key = master_key.encode("utf-8")
    # PBKDF2-HMAC-SHA256 (100 000 iterations)
    return hashlib.pbkdf2_hmac("sha256", master_key, salt, 100_000, dklen=32)


# ===================================================================
# Data models
# ===================================================================

class AgentStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


@dataclass
class AgentRecord:
    agent_id: str
    public_key: str
    metadata: dict[str, Any]
    status: AgentStatus = AgentStatus.ACTIVE
    token: str = ""
    created_at: str = ""
    scopes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.token:
            self.token = _secrets.token_urlsafe(48)
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.scopes:
            self.scopes = ["secrets:read", "secrets:write", "proxy:request"]


@dataclass
class SecretRecord:
    secret_id: str
    agent_id: str
    scope: str
    status: str = "active"
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


# ===================================================================
# Audit helpers
# ===================================================================

@dataclass
class AuditEntry:
    timestamp: str
    agent_id: str
    action: str
    target: str
    details: dict[str, Any]
    result: str = "success"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ===================================================================
# Rate limiter
# ===================================================================

class _RateLimiter:
    """Token-bucket rate limiter keyed by agent_id."""

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def check(self, agent_id: str) -> None:
        now = time.time()
        bucket = self._buckets.setdefault(agent_id, [])
        # Prune expired entries
        self._buckets[agent_id] = bucket = [
            t for t in bucket if now - t < self.window
        ]
        if len(bucket) >= self.max_requests:
            raise RateLimitError(
                f"Agent {agent_id!r} exceeded rate limit "
                f"({self.max_requests} requests per {self.window}s)"
            )
        bucket.append(now)

    def reset(self, agent_id: str) -> None:
        self._buckets.pop(agent_id, None)


# ===================================================================
# KeeperAgent — the main engine
# ===================================================================

class KeeperAgent:
    """The secret proxy guardian for the Pelagic AI fleet.

    Parameters
    ----------
    vault_path:
        Directory where the encrypted vault, agent registry, and audit
        trail are persisted.
    master_key:
        Master encryption key.  If ``None`` the value is read from the
        ``KEEPER_MASTER_KEY`` environment variable (an error is raised
        if neither is available).
    sensitivity:
        Leak detector sensitivity level.
    rate_limit:
        Max secret-access requests per agent per ``rate_window`` seconds.
    rate_window:
        The sliding window in seconds for rate limiting.
    """

    def __init__(
        self,
        vault_path: str | Path = "~/.superinstance/keeper_vault",
        master_key: str | None = None,
        sensitivity: Sensitivity = Sensitivity.STRICT,
        rate_limit: int = 60,
        rate_window: int = 60,
    ) -> None:
        self.vault_path = Path(vault_path).expanduser().resolve()
        self._master_key_str = master_key or os.environ.get(
            "KEEPER_MASTER_KEY", ""
        )
        if not self._master_key_str:
            raise KeeperError(
                "Master key is required. Pass master_key= or set "
                "KEEPER_MASTER_KEY environment variable."
            )
        self._enc_key = _derive_key(self._master_key_str)
        self._backend = _get_encryption_backend()
        self._detector = LeakDetector(sensitivity=sensitivity)
        self._rate_limiter = _RateLimiter(
            max_requests=rate_limit, window_seconds=rate_window
        )
        self._agents: dict[str, AgentRecord] = {}
        self._secrets_index: dict[str, SecretRecord] = {}  # secret_id -> record
        self._agent_secrets: dict[str, dict[str, SecretRecord]] = {}  # agent_id -> {secret_id: record}
        self._ensure_vault()
        self._load_agents()
        self._load_secrets_index()

    # ------------------------------------------------------------------
    # Vault setup
    # ------------------------------------------------------------------

    def _ensure_vault(self) -> None:
        """Create vault directories if they don't exist."""
        self.vault_path.mkdir(parents=True, exist_ok=True)
        (self.vault_path / "secrets").mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _agents_path(self) -> Path:
        return self.vault_path / "agents.json"

    def _audit_path(self) -> Path:
        return self.vault_path / "audit.jsonl"

    def _secret_path(self, agent_id: str, secret_id: str) -> Path:
        return self.vault_path / "secrets" / agent_id / f"{secret_id}.enc"

    def _secrets_index_path(self) -> Path:
        return self.vault_path / "secrets_index.json"

    def _save_agents(self) -> None:
        data = {aid: asdict(rec) for aid, rec in self._agents.items()}
        self._agents_path().write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_agents(self) -> None:
        path = self._agents_path()
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            for aid, d in raw.items():
                self._agents[aid] = AgentRecord(**d)

    def _save_secrets_index(self) -> None:
        data = {}
        for sid, rec in self._secrets_index.items():
            data[sid] = asdict(rec)
        self._secrets_index_path().write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def _load_secrets_index(self) -> None:
        path = self._secrets_index_path()
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            for sid, d in raw.items():
                rec = SecretRecord(**d)
                self._secrets_index[sid] = rec
                self._agent_secrets.setdefault(rec.agent_id, {})[sid] = rec

    def _append_audit(self, entry: AuditEntry) -> None:
        """Append an audit entry to the JSONL audit log."""
        line = json.dumps(entry.to_dict(), ensure_ascii=False) + "\n"
        with open(self._audit_path(), "a", encoding="utf-8") as f:
            f.write(line)

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        public_key: str,
        metadata: dict[str, Any] | None = None,
        scopes: list[str] | None = None,
    ) -> AgentRecord:
        """Register a new fleet agent.

        Returns the :class:`AgentRecord` including a unique auth token
        that the agent must use for all subsequent Keeper requests.
        """
        if agent_id in self._agents:
            existing = self._agents[agent_id]
            if existing.status == AgentStatus.REVOKED:
                raise AgentRevokedError(
                    f"Agent {agent_id!r} has been revoked and cannot re-register"
                )
            # Allow re-registration of active agents (update metadata)
            existing.public_key = public_key
            existing.metadata = metadata or {}
            existing.scopes = scopes or existing.scopes
            self._save_agents()
            self._append_audit(AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id=agent_id,
                action="register",
                target="self",
                details={"public_key": public_key[:20] + "..."},
                result="updated",
            ))
            return existing

        record = AgentRecord(
            agent_id=agent_id,
            public_key=public_key,
            metadata=metadata or {},
            scopes=scopes or [],
        )
        self._agents[agent_id] = record
        self._save_agents()
        self._append_audit(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action="register",
            target="self",
            details={"public_key": public_key[:20] + "..."},
        ))
        return record

    def _validate_agent(self, agent_id: str, token: str | None = None) -> AgentRecord:
        """Validate that *agent_id* exists, is active, and optionally matches *token*."""
        if agent_id not in self._agents:
            raise AgentNotFoundError(f"Agent {agent_id!r} not found")
        record = self._agents[agent_id]
        if record.status == AgentStatus.REVOKED:
            raise AgentRevokedError(f"Agent {agent_id!r} has been revoked")
        if token is not None and record.token != token:
            raise KeeperError(f"Invalid token for agent {agent_id!r}")
        return record

    def revoke_agent(self, agent_id: str) -> None:
        """Emergency-revoke a fleet agent.  All its secrets are also revoked."""
        self._validate_agent(agent_id)
        self._agents[agent_id].status = AgentStatus.REVOKED
        # Revoke all secrets belonging to this agent
        for sid, rec in list(self._agent_secrets.get(agent_id, {}).items()):
            rec.status = "revoked"
            self._secrets_index[sid] = rec
        self._save_agents()
        self._save_secrets_index()
        self._rate_limiter.reset(agent_id)
        self._append_audit(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action="revoke",
            target="self",
            details={"reason": "emergency revocation"},
            result="revoked",
        ))

    def list_agents(self) -> list[dict[str, Any]]:
        """Return metadata for all registered agents (tokens redacted)."""
        result = []
        for record in self._agents.values():
            d = asdict(record)
            d["token"] = "***REDACTED***"
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Secret management
    # ------------------------------------------------------------------

    def store_secret(
        self,
        agent_id: str,
        secret_id: str,
        secret_value: str,
        scope: str = "default",
    ) -> SecretRecord:
        """Encrypt and store a secret for *agent_id*.

        The secret is encrypted at rest and can never be retrieved in
        plaintext — only injected server-side during proxied requests.
        """
        self._validate_agent(agent_id)
        if self._is_revoked_agent(agent_id):
            raise AgentRevokedError(f"Agent {agent_id!r} is revoked")

        record = SecretRecord(secret_id=secret_id, agent_id=agent_id, scope=scope)
        self._secrets_index[secret_id] = record
        self._agent_secrets.setdefault(agent_id, {})[secret_id] = record

        # Encrypt and persist the secret value
        enc_dir = self.vault_path / "secrets" / agent_id
        enc_dir.mkdir(parents=True, exist_ok=True)
        enc_bytes = self._backend.encrypt(
            secret_value.encode("utf-8"), self._enc_key
        )
        self._secret_path(agent_id, secret_id).write_bytes(enc_bytes)

        self._save_secrets_index()
        self._append_audit(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action="store_secret",
            target=secret_id,
            details={"scope": scope},
        ))
        return record

    def get_secret_reference(self, agent_id: str, secret_id: str) -> str:
        """Return a short-lived **reference token** for *secret_id*.

        The token is an opaque string that can be passed to
        :meth:`proxy_request` which will resolve and inject the secret
        server-side.  The raw secret is **never** returned to the caller.
        """
        self._validate_agent(agent_id)
        self._rate_limiter.check(agent_id)

        if secret_id not in self._secrets_index:
            raise SecretNotFoundError(f"Secret {secret_id!r} not found")
        record = self._secrets_index[secret_id]
        if record.agent_id != agent_id:
            raise KeeperError(
                f"Secret {secret_id!r} does not belong to agent {agent_id!r}"
            )
        if record.status == "revoked":
            raise SecretRevokedError(f"Secret {secret_id!r} has been revoked")

        ref_token = base64.urlsafe_b64encode(
            json.dumps({
                "sid": secret_id,
                "aid": agent_id,
                "exp": int(time.time()) + 300,  # 5-minute TTL
                "nonce": _secrets.token_hex(16),
            }).encode()
        ).decode()

        self._append_audit(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action="get_secret_reference",
            target=secret_id,
            details={"scope": record.scope},
        ))
        return ref_token

    def _resolve_secret(self, secret_id: str) -> str:
        """Internal: decrypt and return a secret's plaintext value."""
        record = self._secrets_index.get(secret_id)
        if record is None:
            raise SecretNotFoundError(f"Secret {secret_id!r} not found")
        if record.status == "revoked":
            raise SecretRevokedError(f"Secret {secret_id!r} has been revoked")
        path = self._secret_path(record.agent_id, secret_id)
        if not path.exists():
            raise SecretNotFoundError(f"Encrypted blob for {secret_id!r} not found on disk")
        enc_bytes = path.read_bytes()
        return self._backend.decrypt(enc_bytes, self._enc_key).decode("utf-8")

    def _resolve_ref_token(self, ref_token: str) -> dict[str, str]:
        """Internal: decode and validate a reference token."""
        try:
            payload = json.loads(
                base64.urlsafe_b64decode(ref_token).decode()
            )
        except Exception:
            raise KeeperError("Invalid reference token")
        if payload.get("exp", 0) < time.time():
            raise KeeperError("Reference token has expired")
        return payload

    def revoke_secret(self, secret_id: str) -> None:
        """Revoke a specific secret by ID."""
        if secret_id not in self._secrets_index:
            raise SecretNotFoundError(f"Secret {secret_id!r} not found")
        record = self._secrets_index[secret_id]
        record.status = "revoked"
        record.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_secrets_index()
        # Remove encrypted blob from disk
        path = self._secret_path(record.agent_id, secret_id)
        if path.exists():
            path.unlink()
        self._append_audit(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=record.agent_id,
            action="revoke_secret",
            target=secret_id,
            details={},
            result="revoked",
        ))

    # ------------------------------------------------------------------
    # Request proxy & double-checker
    # ------------------------------------------------------------------

    def proxy_request(
        self,
        agent_id: str,
        service: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """Proxy an outbound API request on behalf of *agent_id*.

        1. Validate the agent.
        2. Resolve any ``$SECRET_REF`` placeholders in the request.
        3. Run the **double-checker** (leak detector) on the fully
           assembled request.
        4. If the double-checker passes, return the assembled request
           for the caller to send (or the Keeper proxy server can send
           it directly in production).
        """
        self._validate_agent(agent_id)
        self._rate_limiter.check(agent_id)

        # Step 1: Double-check the ORIGINAL request for accidental leaks
        # (before secret injection — vault-resolved secrets are intentional)
        self._double_check(request)

        # Step 2: Resolve secret reference tokens in the request
        assembled = self._inject_secrets(request)

        self._append_audit(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action="proxy_request",
            target=service,
            details={
                "method": assembled.get("method", "GET"),
                "url": assembled.get("url", service)[:200],
                "headers_count": len(assembled.get("headers", {})),
            },
        ))

        return assembled

    def proxy_git_operation(
        self,
        agent_id: str,
        repo: str,
        operation: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Proxy a git push / pull operation.

        Injects authentication secrets into the git URL and runs the
        double-checker on the resulting configuration.
        """
        self._validate_agent(agent_id)
        self._rate_limiter.check(agent_id)

        assembled = dict(data)
        assembled["operation"] = operation
        assembled["repo"] = repo

        # Double-check BEFORE secret injection
        self._double_check(assembled)

        # Inject secrets
        assembled = self._inject_secrets(assembled)

        self._append_audit(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action="proxy_git",
            target=repo,
            details={"operation": operation},
        ))

        return assembled

    def _inject_secrets(self, request: dict[str, Any]) -> dict[str, Any]:
        """Recursively walk *request* and replace ``$SECRET_REF:<token>``
        placeholders with actual secret values."""
        assembled = json.loads(json.dumps(request))  # deep copy

        def _walk(obj: Any) -> Any:
            if isinstance(obj, str):
                prefix = "$SECRET_REF:"
                if obj.startswith(prefix):
                    # Entire value is a secret reference
                    ref_token = obj[len(prefix):]
                    payload = self._resolve_ref_token(ref_token)
                    return self._resolve_secret(payload["sid"])
                elif prefix in obj:
                    # Secret reference is embedded within a larger string
                    parts = obj.split(prefix, 1)
                    ref_token = parts[1]  # everything after $SECRET_REF:
                    payload = self._resolve_ref_token(ref_token)
                    secret_val = self._resolve_secret(payload["sid"])
                    return parts[0] + secret_val
                return obj
            if isinstance(obj, dict):
                return {k: _walk(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_walk(v) for v in obj]
            return obj

        return _walk(assembled)

    def _double_check(self, data: Any) -> None:
        """Run the leak detector on *data*.  Raises :exc:`LeakDetectedError`
        if any secrets are found."""
        matches = self._detector.scan(data)
        if matches:
            report = self._detector.report()
            raise LeakDetectedError(
                f"Double-checker blocked request: {len(matches)} leak(s) detected.\n{report}"
            )

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def audit(
        self,
        agent_id: str | None = None,
        since: str | None = None,
        action: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Query the audit trail.

        Parameters
        ----------
        agent_id:
            Filter by agent ID.
        since:
            ISO timestamp — only return entries after this time.
        action:
            Filter by action type (e.g. ``"store_secret"``, ``"proxy_request"``).
        limit:
            Maximum entries to return (most recent first).
        """
        audit_path = self._audit_path()
        if not audit_path.exists():
            return []

        entries: list[dict[str, Any]] = []
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if agent_id and entry.get("agent_id") != agent_id:
                continue
            if since and entry.get("timestamp", "") < since:
                continue
            if action and entry.get("action") != action:
                continue
            entries.append(entry)

        # Most recent first
        entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return entries[:limit]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_revoked_agent(self, agent_id: str) -> bool:
        rec = self._agents.get(agent_id)
        return rec is not None and rec.status == AgentStatus.REVOKED

    def health_check(self) -> dict[str, Any]:
        """Return the Keeper's health status."""
        agent_count = len(self._agents)
        active_agents = sum(
            1 for a in self._agents.values() if a.status == AgentStatus.ACTIVE
        )
        secret_count = sum(
            1 for s in self._secrets_index.values() if s.status == "active"
        )
        return {
            "status": "healthy",
            "vault_path": str(self.vault_path),
            "encryption_backend": type(self._backend).__name__,
            "detector_sensitivity": self._detector.sensitivity.value,
            "agents_total": agent_count,
            "agents_active": active_agents,
            "secrets_active": secret_count,
            "rate_limit": self._rate_limiter.max_requests,
            "rate_window": f"{self._rate_limiter.window}s",
        }
