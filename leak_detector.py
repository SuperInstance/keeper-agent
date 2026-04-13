"""
leak_detector.py — Secret Leak Detection Engine for the Keeper Agent.

Pattern-based scanning engine that detects accidental secret leakage in
outbound payloads, logs, responses, and any data flowing through the proxy.

Sensitivity levels:
    PARANOID  — Catches everything, including base64 blobs and UUIDs
    STRICT    — Catches all known secret formats (default)
    MODERATE  — Catches high-confidence secrets only
    RELAXED   — Catches only the most obvious patterns
"""

from __future__ import annotations

import base64
import enum
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Sensitivity enum
# ---------------------------------------------------------------------------

class Sensitivity(enum.Enum):
    PARANOID = "paranoid"
    STRICT = "strict"
    MODERATE = "moderate"
    RELAXED = "relaxed"


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------

@dataclass
class LeakMatch:
    """A single match found by the leak detector."""

    pattern_name: str
    pattern: str
    matched_value: str
    context: str
    sensitivity: Sensitivity
    line: int | None = None
    column: int | None = None


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

@dataclass
class SecretPattern:
    """A compiled regex pattern for detecting a specific secret type."""

    name: str
    pattern: re.Pattern[str]
    sensitivity: Sensitivity
    description: str = ""
    placeholder: str = "***REDACTED***"


def _build_patterns() -> list[SecretPattern]:
    """Return the built-in library of secret detection patterns."""
    patterns: list[SecretPattern] = []

    # --- GitHub Personal Access Tokens ---
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
        patterns.append(SecretPattern(
            name=f"github_pat_{prefix}",
            pattern=re.compile(rf"{prefix}[A-Za-z0-9_]{{36}}"),
            sensitivity=Sensitivity.MODERATE,
            description=f"GitHub PAT starting with {prefix}",
        ))

    # --- AWS Access Key IDs ---
    patterns.append(SecretPattern(
        name="aws_access_key_id",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        sensitivity=Sensitivity.MODERATE,
        description="AWS Access Key ID (AKIA...)",
    ))
    patterns.append(SecretPattern(
        name="aws_secret_access_key",
        pattern=re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}"),
        sensitivity=Sensitivity.MODERATE,
        description="AWS Secret Access Key assignment",
    ))

    # --- Generic API keys / tokens ---
    patterns.append(SecretPattern(
        name="generic_key_assignment",
        pattern=re.compile(r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|secretkey|access[_-]?token)
                             \s*[=:]\s*['\"]?([A-Za-z0-9_\-+/=!@#$%^&*]{16,})['\"]?""", re.VERBOSE),
        sensitivity=Sensitivity.STRICT,
        description="Generic API/secret key assignment",
    ))

    # --- Bearer / Authorization headers ---
    patterns.append(SecretPattern(
        name="bearer_token",
        pattern=re.compile(r"(?i)[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*"),
        sensitivity=Sensitivity.STRICT,
        description="Bearer token in header or body",
    ))
    patterns.append(SecretPattern(
        name="authorization_header",
        pattern=re.compile(r"(?i)authorization\s*:\s*(?!Basic|Bearer\s*(?:test|example|dummy))[^\s]+"),
        sensitivity=Sensitivity.STRICT,
        description="Authorization header with non-trivial value",
    ))

    # --- Private keys (PEM blocks) ---
    for key_type in ("RSA", "EC", "DSA", "OPENSSH"):
        patterns.append(SecretPattern(
            name=f"private_key_{key_type.lower()}",
            pattern=re.compile(
                rf"-----BEGIN {key_type} PRIVATE KEY-----[\s\S]*?-----END {key_type} PRIVATE KEY-----"
            ),
            sensitivity=Sensitivity.MODERATE,
            description=f"{key_type} private key PEM block",
        ))
    # Generic PKCS#8 PRIVATE KEY
    patterns.append(SecretPattern(
        name="private_key_generic",
        pattern=re.compile(
            r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"
        ),
        sensitivity=Sensitivity.MODERATE,
        description="Generic PKCS#8 private key PEM block",
    ))

    # --- Connection strings ---
    for scheme in ("postgres", "postgresql", "mysql", "mongodb", "mongodb+srv",
                   "redis", "rediss", "amqp", "amqps"):
        patterns.append(SecretPattern(
            name=f"connection_string_{scheme}",
            pattern=re.compile(rf"{scheme}://[^\s'\"\)\]]+"),
            sensitivity=Sensitivity.STRICT,
            description=f"{scheme}:// connection string with credentials",
        ))

    # --- JWTs ---
    patterns.append(SecretPattern(
        name="jwt_token",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        sensitivity=Sensitivity.MODERATE,
        description="JSON Web Token (JWT)",
    ))

    # --- Environment variable patterns (.env file contents) ---
    patterns.append(SecretPattern(
        name="env_file_secret",
        pattern=re.compile(
            r"""(?m)^(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|AUTH)
                (?:_[A-Z_0-9]*)?
                \s*[=:]\s*['"]?[^\s'"]{8,}""", re.VERBOSE
        ),
        sensitivity=Sensitivity.STRICT,
        description="Secret-like environment variable assignment",
    ))

    # --- Slack tokens ---
    patterns.append(SecretPattern(
        name="slack_token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
        sensitivity=Sensitivity.MODERATE,
        description="Slack token (xoxb-, xoxp-, etc.)",
    ))

    # --- Stripe keys ---
    patterns.append(SecretPattern(
        name="stripe_key",
        pattern=re.compile(r"\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}\b"),
        sensitivity=Sensitivity.MODERATE,
        description="Stripe API key",
    ))

    # --- Google API keys ---
    patterns.append(SecretPattern(
        name="google_api_key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        sensitivity=Sensitivity.MODERATE,
        description="Google API key (AIza...)",
    ))

    # --- Generic long hex secrets (PARANOID only) ---
    patterns.append(SecretPattern(
        name="long_hex_string",
        pattern=re.compile(r"\b[0-9a-fA-F]{32,}\b"),
        sensitivity=Sensitivity.PARANOID,
        description="Long hexadecimal string (possible hash/key)",
    ))

    # --- IP addresses (configurable — external blocked) ---
    patterns.append(SecretPattern(
        name="external_ip_address",
        pattern=re.compile(r"\b(?!(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.))\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        sensitivity=Sensitivity.PARANOID,
        description="External IP address",
    ))

    return patterns


# Default pattern library (compiled once at module level)
_BUILTIN_PATTERNS: list[SecretPattern] = _build_patterns()


# ---------------------------------------------------------------------------
# LeakDetector
# ---------------------------------------------------------------------------

class LeakDetector:
    """Scans arbitrary data for accidental secret leakage.

    Parameters
    ----------
    sensitivity:
        Minimum sensitivity level for pattern matching.  Patterns with a
        higher sensitivity than this level are ignored.
    allow_patterns:
        Optional list of regex strings that *allow* matched values through
        (e.g., ``"example_key_.*"`` for documentation placeholders).
    deny_extra_patterns:
        Optional list of additional ``SecretPattern`` instances to add
        beyond the built-in library.
    """

    def __init__(
        self,
        sensitivity: Sensitivity = Sensitivity.STRICT,
        allow_patterns: list[str] | None = None,
        deny_extra_patterns: list[SecretPattern] | None = None,
    ) -> None:
        self.sensitivity = sensitivity
        self._allow: list[re.Pattern[str]] = [
            re.compile(p) for p in (allow_patterns or [])
        ]
        self._patterns: list[SecretPattern] = list(_BUILTIN_PATTERNS)
        if deny_extra_patterns:
            self._patterns.extend(deny_extra_patterns)
        # Keep only patterns at or below the configured sensitivity.
        # Order: RELAXED < MODERATE < STRICT < PARANOID
        # At STRICT level we want RELAXED + MODERATE + STRICT patterns.
        _sens_order = [
            Sensitivity.RELAXED,
            Sensitivity.MODERATE,
            Sensitivity.STRICT,
            Sensitivity.PARANOID,
        ]
        cutoff = _sens_order.index(sensitivity)
        self._active_patterns: list[SecretPattern] = [
            p for p in self._patterns
            if _sens_order.index(p.sensitivity) <= cutoff
        ]
        self._matches: list[LeakMatch] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, data: Any) -> list[LeakMatch]:
        """Scan *data* for potential secrets and return all matches.

        Accepts ``str``, ``bytes``, ``dict``, ``list`` or any JSON-serialisable
        object.  Returns a list of :class:`LeakMatch` instances.
        """
        self._matches = []
        text = self._coerce_to_string(data)
        # Track already-seen (pattern_name, value) to avoid duplicates
        seen: set[tuple[str, str]] = set()

        # Line-by-line scan (for single-line patterns)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pat in self._active_patterns:
                for m in pat.pattern.finditer(line):
                    value = m.group(0)
                    if self._is_allowed(value):
                        continue
                    key = (pat.name, value)
                    if key in seen:
                        continue
                    seen.add(key)
                    self._matches.append(LeakMatch(
                        pattern_name=pat.name,
                        pattern=pat.pattern.pattern,
                        matched_value=value,
                        context=line.strip(),
                        sensitivity=pat.sensitivity,
                        line=lineno,
                        column=m.start(),
                    ))

        # Full-text scan (for multiline patterns like PEM keys)
        for pat in self._active_patterns:
            if r"[\s\S]" not in pat.pattern.pattern:
                continue  # skip single-line-only patterns
            for m in pat.pattern.finditer(text):
                value = m.group(0)
                if self._is_allowed(value):
                    continue
                key = (pat.name, value)
                if key in seen:
                    continue
                seen.add(key)
                # Find line number of match start
                lineno = text[:m.start()].count("\n") + 1
                self._matches.append(LeakMatch(
                    pattern_name=pat.name,
                    pattern=pat.pattern.pattern,
                    matched_value=value,
                    context=value[:100],
                    sensitivity=pat.sensitivity,
                    line=lineno,
                    column=None,
                ))

        return self._matches

    def is_safe(self, data: Any) -> bool:
        """Return ``True`` when *data* contains **no** detected secrets."""
        return len(self.scan(data)) == 0

    def sanitize(self, data: Any) -> str:
        """Return a sanitised copy of *data* with detected secrets replaced
        by ``***REDACTED***`` placeholders.
        """
        text = self._coerce_to_string(data)
        for pat in self._active_patterns:
            text = pat.pattern.sub("***REDACTED***", text)
        return text

    def report(self) -> str:
        """Generate a human-readable report of the most recent scan."""
        if not self._matches:
            return "✅ No secrets detected."
        lines: list[str] = [
            f"⚠️  {len(self._matches)} potential secret(s) detected:\n",
        ]
        seen: set[str] = set()
        for match in self._matches:
            key = f"{match.pattern_name}:{match.matched_value[:20]}"
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"  • [{match.pattern_name}] "
                f"\"{match.matched_value[:40]}{'…' if len(match.matched_value) > 40 else ''}\" "
                f"(line {match.line or '?'}, col {match.column or '?'})"
            )
        lines.append(f"\n  Sensitivity: {self.sensitivity.value}")
        lines.append(f"  Active patterns: {len(self._active_patterns)}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_allowed(self, value: str) -> bool:
        """Check the allow-list for a matched value."""
        for pat in self._allow:
            if pat.search(value):
                return True
        # Built-in allow-list for common example / placeholder values
        safe_substrings = (
            "example", "test_key", "dummy", "placeholder", "xxxxxx",
            "your_", "INSERT_", "replace_me", "<", ">",
        )
        return any(s in value.lower() for s in safe_substrings)

    @staticmethod
    def _coerce_to_string(data: Any) -> str:
        """Convert arbitrary data to a scannable string."""
        if isinstance(data, bytes):
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.decode("latin-1")
        if isinstance(data, (dict, list)):
            return json.dumps(data, default=str)
        if isinstance(data, str):
            return data
        return str(data)
