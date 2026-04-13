"""
cli.py — Keeper Agent CLI.

Command-line interface for managing the Keeper secret proxy.

Usage
-----
    python -m keeper_agent start [--port PORT] [--vault-path PATH]
    python -m keeper_agent status [--vault-path PATH]
    python -m keeper_agent audit [--agent-id ID] [--since ISO] [--vault-path PATH]
    python -m keeper_agent list-agents [--vault-path PATH]
    python -m keeper_agent revoke-agent <ID> [--vault-path PATH]
    python -m keeper_agent revoke-secret <ID> [--vault-path PATH]
    python -m keeper_agent export-audit [--format json|csv] [--vault-path PATH]
    python -m keeper-agent rotate-key [--vault-path PATH]
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from leak_detector import Sensitivity
from keeper import KeeperAgent


# ===================================================================
# Helpers
# ===================================================================

def _get_keeper(vault_path: str) -> KeeperAgent:
    """Create a KeeperAgent from the given vault path."""
    master_key = os.environ.get("KEEPER_MASTER_KEY", "")
    if not master_key:
        print("ERROR: KEEPER_MASTER_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    return KeeperAgent(
        vault_path=vault_path,
        master_key=master_key,
    )


def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m"


def _green(text: str) -> str:
    return f"\033[32m{text}\033[0m"


def _red(text: str) -> str:
    return f"\033[31m{text}\033[0m"


def _yellow(text: str) -> str:
    return f"\033[33m{text}\033[0m"


# ===================================================================
# Subcommands
# ===================================================================

def cmd_start(args: argparse.Namespace) -> None:
    """Start the Keeper proxy server."""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    from proxy import KeeperProxy

    keeper = _get_keeper(args.vault_path)
    proxy = KeeperProxy(keeper, host=args.host, port=args.port)
    print(f" {_bold('🛡️  Keeper Agent')}  v0.1.0")
    print(f"   Vault:    {keeper.vault_path}")
    print(f"   Backend:  {keeper.health_check()['encryption_backend']}")
    print(f"   Listen:   http://{args.host}:{args.port}")
    print()
    proxy.serve_forever()


def cmd_status(args: argparse.Namespace) -> None:
    """Show Keeper status."""
    keeper = _get_keeper(args.vault_path)
    health = keeper.health_check()
    print(f"\n {_bold('🛡️  Keeper Agent Status')}")
    print(f"   ─────────────────────────────")
    print(f"   Status:       {_green(health['status'])}")
    print(f"   Vault:        {health['vault_path']}")
    print(f"   Encryption:   {health['encryption_backend']}")
    print(f"   Sensitivity:  {health['detector_sensitivity']}")
    print(f"   Agents:       {health['agents_active']} active / {health['agents_total']} total")
    print(f"   Secrets:      {health['secrets_active']} active")
    print(f"   Rate Limit:   {health['rate_limit']} req / {health['rate_window']}")
    print()


def cmd_audit(args: argparse.Namespace) -> None:
    """Review the audit trail."""
    keeper = _get_keeper(args.vault_path)
    entries = keeper.audit(
        agent_id=args.agent_id,
        since=args.since,
        limit=args.limit,
    )
    if not entries:
        print(f"\n {_yellow('No audit entries found.')}")
        return
    print(f"\n {_bold(f'📜  Audit Trail')} ({len(entries)} entries)")
    print(f"   ─────────────────────────────")
    for entry in entries:
        agent = entry.get("agent_id", "?")
        action = entry.get("action", "?")
        target = entry.get("target", "?")
        ts = entry.get("timestamp", "?")[:19]
        result = entry.get("result", "")
        status_icon = "✅" if result in ("success", "") else "🚫"
        print(f"   {status_icon} [{ts}] {agent} → {action} ({target})")
    print()


def cmd_list_agents(args: argparse.Namespace) -> None:
    """List all registered agents."""
    keeper = _get_keeper(args.vault_path)
    agents = keeper.list_agents()
    if not agents:
        print(f"\n {_yellow('No agents registered.')}")
        return
    print(f"\n {_bold(f'🤖  Registered Agents')} ({len(agents)})")
    print(f"   ─────────────────────────────")
    for a in agents:
        status_icon = "🟢" if a["status"] == "active" else "🔴"
        print(f"   {status_icon} {a['agent_id']}")
        print(f"      Token:  {a['token']}")
        print(f"      Status: {a['status']}")
        print(f"      Scopes: {', '.join(a.get('scopes', []))}")
        print(f"      Since:  {a['created_at'][:19]}")
    print()


def cmd_revoke_agent(args: argparse.Namespace) -> None:
    """Revoke an agent."""
    keeper = _get_keeper(args.vault_path)
    try:
        keeper.revoke_agent(args.id)
        print(f" {_red('🚫')} Agent {args.id!r} has been revoked.")
    except Exception as exc:
        print(f" ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_revoke_secret(args: argparse.Namespace) -> None:
    """Revoke a secret."""
    keeper = _get_keeper(args.vault_path)
    try:
        keeper.revoke_secret(args.id)
        print(f" {_red('🚫')} Secret {args.id!r} has been revoked.")
    except Exception as exc:
        print(f" ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_export_audit(args: argparse.Namespace) -> None:
    """Export the audit trail to JSON or CSV."""
    keeper = _get_keeper(args.vault_path)
    entries = keeper.audit(limit=100_000)
    fmt = (args.format or "json").lower()

    if fmt == "json":
        output = json.dumps(entries, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f" Exported {len(entries)} entries to {args.output}")
        else:
            print(output)
    elif fmt == "csv":
        if not entries:
            print(f"\n {_yellow('No audit entries to export.')}")
            return
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=entries[0].keys())
        writer.writeheader()
        writer.writerows(entries)
        output = buf.getvalue()
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f" Exported {len(entries)} entries to {args.output}")
        else:
            print(output, end="")
    else:
        print(f" ERROR: Unsupported format {fmt!r}. Use 'json' or 'csv'.", file=sys.stderr)
        sys.exit(1)


def cmd_rotate_key(args: argparse.Namespace) -> None:
    """Rotate the master encryption key.

    This re-encrypts all secrets with a new key derived from the
    KEEPER_MASTER_KEY environment variable (which should have been
    updated before running this command).
    """
    new_key = os.environ.get("KEEPER_MASTER_KEY", "")
    if not new_key:
        print(" ERROR: Set KEEPER_MASTER_KEY to the new value first.", file=sys.stderr)
        sys.exit(1)
    print(f" {_yellow('⚠️')} Key rotation is a manual operation.")
    print(f"   Ensure KEEPER_MASTER_KEY has been updated, then")
    print(f"   re-store all secrets.  Old encrypted blobs will be")
    print(f"   unreadable with the new key.")
    print(f"   Use 'keeper-agent audit --action store_secret' to")
    print(f"   identify which secrets need re-storing.")


# ===================================================================
# Argument parser
# ===================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keeper-agent",
        description="🛡️  Keeper Agent — secret proxy guardian for the Pelagic AI fleet",
    )
    parser.add_argument(
        "--vault-path",
        default="~/.superinstance/keeper_vault",
        help="Path to the vault directory (default: ~/.superinstance/keeper_vault)",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # start
    p_start = sub.add_parser("start", help="Start the Keeper proxy server")
    p_start.add_argument("--port", type=int, default=8877, help="Server port (default: 8877)")
    p_start.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")

    # status
    sub.add_parser("status", help="Show Keeper status")

    # audit
    p_audit = sub.add_parser("audit", help="Review audit trail")
    p_audit.add_argument("--agent-id", default=None, help="Filter by agent ID")
    p_audit.add_argument("--since", default=None, help="ISO timestamp filter")
    p_audit.add_argument("--limit", type=int, default=50, help="Max entries (default: 50)")

    # list-agents
    sub.add_parser("list-agents", help="List all registered agents")

    # revoke-agent
    p_ra = sub.add_parser("revoke-agent", help="Revoke an agent")
    p_ra.add_argument("id", help="Agent ID to revoke")

    # revoke-secret
    p_rs = sub.add_parser("revoke-secret", help="Revoke a secret")
    p_rs.add_argument("id", help="Secret ID to revoke")

    # export-audit
    p_export = sub.add_parser("export-audit", help="Export audit trail")
    p_export.add_argument("--format", default="json", choices=["json", "csv"], help="Output format")
    p_export.add_argument("--output", default=None, help="Output file path")

    # rotate-key
    sub.add_parser("rotate-key", help="Rotate the master encryption key")

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    commands = {
        "start": cmd_start,
        "status": cmd_status,
        "audit": cmd_audit,
        "list-agents": cmd_list_agents,
        "revoke-agent": cmd_revoke_agent,
        "revoke-secret": cmd_revoke_secret,
        "export-audit": cmd_export_audit,
        "rotate-key": cmd_rotate_key,
    }

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(args)


if __name__ == "__main__":
    main()
