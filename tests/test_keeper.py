"""
tests/test_keeper.py — Tests for the Keeper Agent.

Covers secret storage, agent registration, leak detection, proxy
server, double-checker, audit trail, revocation, and rate limiting.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError

# Add parent directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from leak_detector import LeakDetector, Sensitivity, LeakMatch
from keeper import (
    KeeperAgent,
    AgentNotFoundError,
    AgentRevokedError,
    SecretNotFoundError,
    SecretRevokedError,
    RateLimitError,
    LeakDetectedError,
    KeeperError,
    _derive_key,
    _get_encryption_backend,
)


class TestLeakDetector(unittest.TestCase):
    """Tests for the LeakDetector."""

    def setUp(self) -> None:
        self.detector = LeakDetector(sensitivity=Sensitivity.STRICT)

    def test_github_pat_detected(self) -> None:
        data = "token = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0].pattern_name, "github_pat_ghp_")

    def test_aws_key_detected(self) -> None:
        data = "AKIAIOSFODNN7ABCDEFG"  # AKIA + 16 uppercase chars (total 20)
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0].pattern_name, "aws_access_key_id")

    def test_bearer_token_detected(self) -> None:
        data = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        matches = self.detector.scan(data)
        self.assertTrue(any("bearer" in m.pattern_name for m in matches))

    def test_private_key_detected(self) -> None:
        data = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ\n-----END RSA PRIVATE KEY-----"
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)

    def test_connection_string_detected(self) -> None:
        data = "postgres://user:password@db.production.com:5432/mydb"
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)

    def test_jwt_detected(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.abc123def456ghi789"
        matches = self.detector.scan(jwt)
        self.assertTrue(any("jwt" in m.pattern_name for m in matches))

    def test_slack_token_detected(self) -> None:
        data = "xoxb-EXAMPLE-REDACTED-TOKEN-FOR-TESTING-ONLY"
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)

    def test_google_api_key_detected(self) -> None:
        data = "AIzaSyA0123456789abcdefghijklmnopqrstuv"  # AIza + exactly 35 chars
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)

    def test_env_file_secret_detected(self) -> None:
        data = "SECRET_KEY=mySuperSecretValue12345678"
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)

    def test_is_safe_with_clean_data(self) -> None:
        self.assertTrue(self.detector.is_safe("Hello, world!"))
        self.assertTrue(self.detector.is_safe("The quick brown fox jumps over the lazy dog."))

    def test_is_safe_with_secret(self) -> None:
        self.assertFalse(self.detector.is_safe("AKIAIOSFODNN7ABCDEFG"))

    def test_sanitize_removes_secrets(self) -> None:
        data = "key=AKIAIOSFODNN7ABCDEFG and token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
        sanitized = self.detector.sanitize(data)
        self.assertNotIn("AKIAIOSFODNN7ABCDEFG", sanitized)
        self.assertNotIn("ghp_", sanitized)
        self.assertIn("***REDACTED***", sanitized)

    def test_report_with_matches(self) -> None:
        data = "AKIAIOSFODNN7ABCDEFG"
        self.detector.scan(data)
        report = self.detector.report()
        self.assertIn("potential secret", report)
        self.assertIn("aws_access_key_id", report)

    def test_report_no_matches(self) -> None:
        self.detector.scan("Hello world")
        report = self.detector.report()
        self.assertIn("No secrets detected", report)

    def test_allow_list(self) -> None:
        detector = LeakDetector(
            sensitivity=Sensitivity.STRICT,
            allow_patterns=[r"AKIAEXAMPLE.*"],
        )
        matches = detector.scan("key=AKIAEXAMPLE12345678")
        self.assertTrue(len(matches) == 0)

    def test_example_values_allowed(self) -> None:
        """Common example/placeholder values should be allowed through."""
        data = "api_key=example_key_12345 replace_me INSERT_YOUR_KEY_HERE"
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) == 0)

    def test_paranoid_catches_long_hex(self) -> None:
        detector = LeakDetector(sensitivity=Sensitivity.PARANOID)
        data = "hash=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        matches = detector.scan(data)
        self.assertTrue(len(matches) > 0)

    def test_dict_scanning(self) -> None:
        data = {"headers": {"Authorization": "Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"}}
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)

    def test_bytes_scanning(self) -> None:
        data = b"token = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
        matches = self.detector.scan(data)
        self.assertTrue(len(matches) > 0)


class TestEncryption(unittest.TestCase):
    """Tests for encryption backends."""

    def test_derive_key_deterministic(self) -> None:
        k1 = _derive_key("test-master-key", salt=b"test-salt")
        k2 = _derive_key("test-master-key", salt=b"test-salt")
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_derive_key_different_inputs(self) -> None:
        k1 = _derive_key("key-one")
        k2 = _derive_key("key-two")
        self.assertNotEqual(k1, k2)

    def test_backend_encrypt_decrypt_roundtrip(self) -> None:
        backend = _get_encryption_backend()
        key = os.urandom(32)
        plaintext = "Hello, secret world!".encode("utf-8")
        ciphertext = backend.encrypt(plaintext, key)
        self.assertNotEqual(ciphertext, plaintext)
        decrypted = backend.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_xor_hmac_backend(self) -> None:
        from keeper import _XorHmacBackend
        backend = _XorHmacBackend()
        key = os.urandom(32)
        plaintext = b"test secret data"
        ct = backend.encrypt(plaintext, key)
        pt = backend.decrypt(ct, key)
        self.assertEqual(pt, plaintext)

    def test_xor_hmac_tamper_detection(self) -> None:
        from keeper import _XorHmacBackend
        backend = _XorHmacBackend()
        key = os.urandom(32)
        ct = backend.encrypt(b"test", key)
        # Tamper with the ciphertext
        tampered = ct[:-1] + bytes([(ct[-1] + 1) % 256])
        with self.assertRaises(ValueError):
            backend.decrypt(tampered, key)


class TestKeeperAgent(unittest.TestCase):
    """Tests for the core KeeperAgent."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="keeper_test_")
        self.keeper = KeeperAgent(
            vault_path=self.tmpdir,
            master_key="test-master-key-for-unit-tests",
            sensitivity=Sensitivity.STRICT,
            rate_limit=10,
            rate_window=60,
        )

    def test_health_check(self) -> None:
        health = self.keeper.health_check()
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["agents_total"], 0)
        self.assertEqual(health["secrets_active"], 0)

    def test_register_agent(self) -> None:
        record = self.keeper.register_agent(
            agent_id="agent-001",
            public_key="ssh-rsa AAAAB3...",
            metadata={"name": "Test Agent"},
        )
        self.assertEqual(record.agent_id, "agent-001")
        self.assertEqual(record.status, "active")
        self.assertTrue(len(record.token) > 0)
        self.assertIn("secrets:read", record.scopes)

    def test_register_duplicate_agent_updates(self) -> None:
        self.keeper.register_agent("agent-001", "key1")
        record = self.keeper.register_agent("agent-001", "key2", metadata={"updated": True})
        self.assertEqual(record.public_key, "key2")

    def test_store_and_reference_secret(self) -> None:
        self.keeper.register_agent("agent-001", "ssh-rsa AAAA")
        self.keeper.store_secret(
            agent_id="agent-001",
            secret_id="github-token",
            secret_value="ghp_test123456789012345678901234567890",
            scope="github",
        )
        ref = self.keeper.get_secret_reference("agent-001", "github-token")
        self.assertTrue(len(ref) > 0)
        self.assertIn("eyJ", ref)  # base64-encoded JSON

    def test_secret_isolation(self) -> None:
        """Agent A cannot access Agent B's secrets."""
        self.keeper.register_agent("agent-A", "keyA")
        self.keeper.register_agent("agent-B", "keyB")
        self.keeper.store_secret("agent-A", "secret-1", "value-1")
        with self.assertRaises(KeeperError):
            self.keeper.get_secret_reference("agent-B", "secret-1")

    def test_revoke_agent(self) -> None:
        self.keeper.register_agent("agent-001", "ssh-rsa AAAA")
        self.keeper.store_secret("agent-001", "secret-1", "value-1")
        self.keeper.revoke_agent("agent-001")
        with self.assertRaises(AgentRevokedError):
            self.keeper.get_secret_reference("agent-001", "secret-1")

    def test_revoke_agent_blocks_store(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        self.keeper.revoke_agent("agent-001")
        with self.assertRaises(AgentRevokedError):
            self.keeper.store_secret("agent-001", "s1", "v1")

    def test_revoke_secret(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        self.keeper.store_secret("agent-001", "secret-1", "value-1")
        self.keeper.revoke_secret("secret-1")
        with self.assertRaises(SecretRevokedError):
            self.keeper.get_secret_reference("agent-001", "secret-1")
        # Encrypted blob should be removed from disk
        path = self.keeper._secret_path("agent-001", "secret-1")
        self.assertFalse(path.exists())

    def test_revoke_nonexistent_secret(self) -> None:
        with self.assertRaises(SecretNotFoundError):
            self.keeper.revoke_secret("nonexistent")

    def test_audit_trail(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        self.keeper.store_secret("agent-001", "s1", "v1")
        entries = self.keeper.audit()
        self.assertTrue(len(entries) >= 2)
        actions = [e["action"] for e in entries]
        self.assertIn("register", actions)
        self.assertIn("store_secret", actions)

    def test_audit_filter_by_agent(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        self.keeper.register_agent("agent-002", "key")
        entries = self.keeper.audit(agent_id="agent-001")
        for e in entries:
            self.assertEqual(e["agent_id"], "agent-001")

    def test_list_agents(self) -> None:
        self.keeper.register_agent("agent-001", "key1")
        self.keeper.register_agent("agent-002", "key2")
        agents = self.keeper.list_agents()
        self.assertEqual(len(agents), 2)
        # Tokens should be redacted
        for a in agents:
            self.assertEqual(a["token"], "***REDACTED***")

    def test_rate_limiting(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        self.keeper.store_secret("agent-001", "s1", "v1")
        # Drain the rate limit
        for _ in range(10):
            self.keeper.get_secret_reference("agent-001", "s1")
        # Next call should raise
        with self.assertRaises(RateLimitError):
            self.keeper.get_secret_reference("agent-001", "s1")

    def test_proxy_request_with_secret_injection(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        self.keeper.store_secret("agent-001", "api-key", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        ref = self.keeper.get_secret_reference("agent-001", "api-key")

        request = {
            "method": "POST",
            "url": "https://api.github.com/repos/test/test/pulls",
            "headers": {
                "Authorization": f"Bearer $SECRET_REF:{ref}",
            },
        }
        assembled = self.keeper.proxy_request("agent-001", "github", request)
        # The secret should be injected
        self.assertIn("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", assembled["headers"]["Authorization"])

    def test_double_checker_blocks_leaks(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        request = {
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"Authorization": "Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"},
        }
        with self.assertRaises(LeakDetectedError):
            self.keeper.proxy_request("agent-001", "example", request)

    def test_proxy_git_operation(self) -> None:
        self.keeper.register_agent("agent-001", "key")
        result = self.keeper.proxy_git_operation(
            agent_id="agent-001",
            repo="https://github.com/org/repo.git",
            operation="push",
            data={"branch": "main"},
        )
        self.assertEqual(result["operation"], "push")

    def test_unknown_agent_raises(self) -> None:
        with self.assertRaises(AgentNotFoundError):
            self.keeper.store_secret("ghost", "s1", "v1")

    def test_vault_persistence(self) -> None:
        """Verify that agents and secrets survive re-initialisation."""
        self.keeper.register_agent("agent-001", "key")
        self.keeper.store_secret("agent-001", "s1", "value-persisted")

        # Re-create the KeeperAgent with the same vault path
        keeper2 = KeeperAgent(
            vault_path=self.tmpdir,
            master_key="test-master-key-for-unit-tests",
        )
        agents = keeper2.list_agents()
        self.assertEqual(len(agents), 1)
        ref = keeper2.get_secret_reference("agent-001", "s1")
        self.assertTrue(len(ref) > 0)


class TestProxyServer(unittest.TestCase):
    """Integration tests for the HTTP proxy server."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="keeper_proxy_test_")
        self.keeper = KeeperAgent(
            vault_path=self.tmpdir,
            master_key="test-proxy-key",
            sensitivity=Sensitivity.STRICT,
        )

    def tearDown(self) -> None:
        if hasattr(self, "proxy") and self.proxy._server is not None:
            self.proxy.shutdown()

    def _start_proxy(self) -> int:
        """Start the proxy in a background thread and return its port."""
        import socket
        from proxy import KeeperProxy

        # Find a free port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        self.proxy = KeeperProxy(self.keeper, host="127.0.0.1", port=port)
        self.proxy.serve_in_background()
        time.sleep(0.3)  # Wait for server to start
        return port

    def _request(self, port: int, method: str, path: str, data: dict | None = None) -> tuple[int, dict]:
        """Make a request to the proxy and return (status_code, response_body)."""
        url = f"http://127.0.0.1:{port}{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except HTTPError as e:
            body_text = e.read().decode()
            try:
                return e.code, json.loads(body_text)
            except json.JSONDecodeError:
                return e.code, {"error": body_text}

    def test_health_endpoint(self) -> None:
        port = self._start_proxy()
        status, body = self._request(port, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "healthy")

    def test_register_agent_endpoint(self) -> None:
        port = self._start_proxy()
        status, body = self._request(port, "POST", "/register", {
            "agent_id": "agent-http-001",
            "public_key": "ssh-rsa AAAAB3...",
        })
        self.assertEqual(status, 201)
        self.assertEqual(body["agent_id"], "agent-http-001")
        self.assertIn("token", body)

    def test_store_and_reference_secret(self) -> None:
        port = self._start_proxy()
        # Register
        _, reg = self._request(port, "POST", "/register", {
            "agent_id": "http-agent",
            "public_key": "key",
        })
        token = reg["token"]
        # Store secret
        status, body = self._request(port, "POST", "/secret/store", {
            "agent_id": "http-agent",
            "token": token,
            "secret_id": "my-secret",
            "value": "super-secret-value",
        })
        self.assertEqual(status, 201)
        # Get reference
        status, body = self._request(port, "POST", "/secret/reference", {
            "agent_id": "http-agent",
            "token": token,
            "secret_id": "my-secret",
        })
        self.assertEqual(status, 200)
        self.assertIn("reference", body)

    def test_unknown_endpoint_404(self) -> None:
        port = self._start_proxy()
        status, body = self._request(port, "GET", "/nonexistent")
        self.assertEqual(status, 404)

    def test_invalid_token_403(self) -> None:
        port = self._start_proxy()
        self._request(port, "POST", "/register", {
            "agent_id": "auth-test",
            "public_key": "key",
        })
        status, body = self._request(port, "POST", "/secret/store", {
            "agent_id": "auth-test",
            "token": "invalid-token",
            "secret_id": "s1",
            "value": "v1",
        })
        self.assertEqual(status, 403)

    def test_revoke_endpoint(self) -> None:
        port = self._start_proxy()
        self._request(port, "POST", "/register", {
            "agent_id": "revoke-me",
            "public_key": "key",
        })
        status, body = self._request(port, "POST", "/revoke", {
            "type": "agent",
            "id": "revoke-me",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["revoked"], "agent")

    def test_audit_endpoint(self) -> None:
        port = self._start_proxy()
        self._request(port, "POST", "/register", {
            "agent_id": "audit-agent",
            "public_key": "key",
        })
        status, body = self._request(port, "GET", "/audit")
        self.assertEqual(status, 200)
        self.assertTrue(body["count"] >= 1)

    def test_list_agents_endpoint(self) -> None:
        port = self._start_proxy()
        self._request(port, "POST", "/register", {
            "agent_id": "listed-agent",
            "public_key": "key",
        })
        status, body = self._request(port, "GET", "/agents")
        self.assertEqual(status, 200)
        self.assertTrue(len(body["agents"]) >= 1)


class TestAuditTrail(unittest.TestCase):
    """Dedicated tests for audit trail functionality."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="keeper_audit_test_")
        self.keeper = KeeperAgent(
            vault_path=self.tmpdir,
            master_key="audit-test-key",
        )

    def test_empty_audit(self) -> None:
        entries = self.keeper.audit()
        self.assertEqual(len(entries), 0)

    def test_audit_entries_have_required_fields(self) -> None:
        self.keeper.register_agent("a1", "key")
        entries = self.keeper.audit()
        self.assertTrue(len(entries) > 0)
        entry = entries[0]
        for field in ("timestamp", "agent_id", "action", "target", "details"):
            self.assertIn(field, entry)

    def test_audit_filter_by_action(self) -> None:
        self.keeper.register_agent("a1", "key")
        self.keeper.store_secret("a1", "s1", "v1")
        entries = self.keeper.audit(action="store_secret")
        self.assertTrue(len(entries) > 0)
        for e in entries:
            self.assertEqual(e["action"], "store_secret")

    def test_audit_persistence(self) -> None:
        self.keeper.register_agent("a1", "key")
        self.keeper.store_secret("a1", "s1", "v1")

        # Reload
        keeper2 = KeeperAgent(
            vault_path=self.tmpdir,
            master_key="audit-test-key",
        )
        entries = keeper2.audit()
        self.assertTrue(len(entries) >= 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
