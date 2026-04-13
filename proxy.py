"""
proxy.py — HTTP Request Proxy Server for the Keeper Agent.

Fleet agents communicate with the Keeper via this HTTP server.  Every
proxied request is authenticated, secret-injected, and double-checked
for leaks before being forwarded.

Endpoints
---------
POST /register            — register a new fleet agent
POST /secret/store        — store an encrypted secret
POST /secret/reference    — get a secret reference token
POST /proxy/request       — proxy an API request (injects secrets)
POST /proxy/git           — proxy a git operation
GET  /audit               — query the audit trail
POST /revoke              — revoke an agent or secret
GET  /agents              — list registered agents
GET  /health              — health check
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, cast
from urllib.parse import urlparse, parse_qs

from keeper import (
    KeeperAgent,
    KeeperError,
    AgentNotFoundError,
    AgentRevokedError,
    SecretNotFoundError,
    SecretRevokedError,
    RateLimitError,
    LeakDetectedError,
)

logger = logging.getLogger("keeper.proxy")


# ===================================================================
# Request handler
# ===================================================================

class KeeperRequestHandler(BaseHTTPRequestHandler):
    """Handles all incoming HTTP requests from fleet agents."""

    # The KeeperAgent instance is injected by the server factory.
    keeper: KeeperAgent | None = None

    # ------------------------------------------------------------------
    # HTTP method dispatch
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_cors_headers(204)
        self.end_headers()

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        handler_map = {
            "GET": {
                "/health": self._handle_health,
                "/agents": self._handle_list_agents,
                "/audit": self._handle_audit,
            },
            "POST": {
                "/register": self._handle_register,
                "/secret/store": self._handle_store_secret,
                "/secret/reference": self._handle_secret_reference,
                "/proxy/request": self._handle_proxy_request,
                "/proxy/git": self._handle_proxy_git,
                "/revoke": self._handle_revoke,
            },
        }

        handlers = handler_map.get(method, {})
        handler = handlers.get(path)
        if handler is None:
            self._send_json({"error": f"Unknown endpoint: {method} {path}"}, 404)
            return

        try:
            body = self._read_body() if method == "POST" else {}
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            handler(body, query)
        except KeeperError as exc:
            self._send_json({"error": str(exc)}, 403)
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON body"}, 400)
        except Exception as exc:
            logger.exception("Unhandled error")
            self._send_json({"error": f"Internal server error: {exc}"}, 500)

    # ------------------------------------------------------------------
    # Endpoint handlers
    # ------------------------------------------------------------------

    def _handle_health(self, body: dict, query: dict) -> None:
        health = self._keeper().health_check()
        self._send_json(health)

    def _handle_list_agents(self, body: dict, query: dict) -> None:
        agents = self._keeper().list_agents()
        self._send_json({"agents": agents})

    def _handle_audit(self, body: dict, query: dict) -> None:
        entries = self._keeper().audit(
            agent_id=query.get("agent_id"),
            since=query.get("since"),
            action=query.get("action"),
            limit=int(query.get("limit", "1000")),
        )
        self._send_json({"entries": entries, "count": len(entries)})

    def _handle_register(self, body: dict, query: dict) -> None:
        agent_id = body.get("agent_id", "")
        public_key = body.get("public_key", "")
        if not agent_id or not public_key:
            self._send_json({"error": "agent_id and public_key are required"}, 400)
            return
        record = self._keeper().register_agent(
            agent_id=agent_id,
            public_key=public_key,
            metadata=body.get("metadata", {}),
            scopes=body.get("scopes"),
        )
        self._send_json({
            "agent_id": record.agent_id,
            "token": record.token,
            "status": record.status,
            "scopes": record.scopes,
            "created_at": record.created_at,
        }, 201)

    def _handle_store_secret(self, body: dict, query: dict) -> None:
        agent_id = body.get("agent_id", "")
        secret_id = body.get("secret_id", "")
        secret_value = body.get("value", "")
        if not agent_id or not secret_id or not secret_value:
            self._send_json(
                {"error": "agent_id, secret_id, and value are required"}, 400
            )
            return
        self._auth_agent(agent_id, body.get("token"))
        record = self._keeper().store_secret(
            agent_id=agent_id,
            secret_id=secret_id,
            secret_value=secret_value,
            scope=body.get("scope", "default"),
        )
        self._send_json({
            "secret_id": record.secret_id,
            "agent_id": record.agent_id,
            "scope": record.scope,
            "status": record.status,
            "created_at": record.created_at,
        }, 201)

    def _handle_secret_reference(self, body: dict, query: dict) -> None:
        agent_id = body.get("agent_id", "")
        secret_id = body.get("secret_id", "")
        self._auth_agent(agent_id, body.get("token"))
        ref = self._keeper().get_secret_reference(agent_id, secret_id)
        self._send_json({"reference": ref})

    def _handle_proxy_request(self, body: dict, query: dict) -> None:
        agent_id = body.get("agent_id", "")
        service = body.get("service", "")
        request_data = body.get("request", {})
        if not agent_id:
            self._send_json({"error": "agent_id is required"}, 400)
            return
        self._auth_agent(agent_id, body.get("token"))
        assembled = self._keeper().proxy_request(agent_id, service, request_data)
        self._send_json({"status": "assembled", "request": assembled})

    def _handle_proxy_git(self, body: dict, query: dict) -> None:
        agent_id = body.get("agent_id", "")
        repo = body.get("repo", "")
        operation = body.get("operation", "")
        data = body.get("data", {})
        self._auth_agent(agent_id, body.get("token"))
        result = self._keeper().proxy_git_operation(agent_id, repo, operation, data)
        self._send_json({"status": "assembled", "result": result})

    def _handle_revoke(self, body: dict, query: dict) -> None:
        revoke_type = body.get("type", "")
        target_id = body.get("id", "")
        if revoke_type == "agent":
            self._keeper().revoke_agent(target_id)
            self._send_json({"revoked": "agent", "id": target_id})
        elif revoke_type == "secret":
            self._keeper().revoke_secret(target_id)
            self._send_json({"revoked": "secret", "id": target_id})
        else:
            self._send_json(
                {"error": "type must be 'agent' or 'secret'"}, 400
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _keeper(self) -> KeeperAgent:
        k = KeeperRequestHandler.keeper
        if k is None:
            raise RuntimeError("KeeperAgent not initialised")
        return k

    def _auth_agent(self, agent_id: str, token: str | None) -> None:
        """Validate agent token from request body."""
        self._keeper()._validate_agent(agent_id, token=token)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return cast(dict[str, Any], json.loads(raw))

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, default=str, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_cors_headers(self, status: int = 200) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def log_message(self, format: str, *args: Any) -> None:
        logger.info(format % args)


# ===================================================================
# Server with graceful shutdown
# ===================================================================

class KeeperProxy:
    """HTTP proxy server for the Keeper Agent.

    Parameters
    ----------
    keeper:
        The :class:`KeeperAgent` instance to use.
    host:
        Bind address.
    port:
        Bind port.
    """

    def __init__(
        self,
        keeper: KeeperAgent,
        host: str = "0.0.0.0",
        port: int = 8877,
    ) -> None:
        self.keeper = keeper
        self.host = host
        self.port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def serve_forever(self) -> None:
        """Start the proxy server (blocks until interrupted)."""
        KeeperRequestHandler.keeper = self.keeper
        self._server = HTTPServer((self.host, self.port), KeeperRequestHandler)
        logger.info(
            "Keeper proxy listening on %s:%d", self.host, self.port
        )

        # Graceful shutdown on SIGINT / SIGTERM (only in main thread)
        try:
            import threading as _threading
            if _threading.current_thread() is _threading.main_thread():
                original_sigint = signal.getsignal(signal.SIGINT)
                original_sigterm = signal.getsignal(signal.SIGTERM)

                def _shutdown(signum: int, frame: Any) -> None:
                    logger.info("Received signal %d — shutting down…", signum)
                    if self._server:
                        threading.Thread(target=self._server.shutdown, daemon=True).start()

                signal.signal(signal.SIGINT, _shutdown)
                signal.signal(signal.SIGTERM, _shutdown)
        except (ValueError, RuntimeError):
            pass  # Signal handling not available in this context

        try:
            self._server.serve_forever()
        finally:
            self._server.server_close()
            logger.info("Keeper proxy stopped.")

    def serve_in_background(self) -> None:
        """Start the proxy server in a background thread."""
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        logger.info(
            "Keeper proxy started in background on %s:%d", self.host, self.port
        )

    def shutdown(self) -> None:
        """Stop the background proxy server."""
        if self._server:
            threading.Thread(target=self._server.shutdown).start()
            if self._thread:
                self._thread.join(timeout=5)
