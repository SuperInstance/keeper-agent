"""
__main__.py — Entry point for ``python -m keeper_agent``.

Starts the Keeper proxy server with proper signal handling.
"""

from __future__ import annotations

import signal
import sys

from cli import main


def run() -> None:
    """Run the Keeper Agent CLI.

    Sets up signal handlers for graceful shutdown and delegates to
    the CLI argument parser.
    """

    def _handle_signal(signum: int, frame: object) -> None:
        print(f"\n⏹  Received signal {signum} — shutting down…", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹  Interrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    run()
