"""Run the nemesis demo end to end.

Starts the deliberately vulnerable fixture application, scans it with the
built-in modules, and prints the proof of exploitability for each confirmed
finding.

    python examples/demo.py
"""

from __future__ import annotations

import asyncio
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from nemesis.config import ScanConfig
from nemesis.engine import Engine
from nemesis.reporting.console import print_banner, print_proofs, print_summary
from tests.fixtures.vulnerable_app import Handler


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> int:
    port = free_port()
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)

    target = f"http://127.0.0.1:{port}"
    console = Console()

    try:
        config = ScanConfig(
            target=target,
            scope_rules=[f"127.0.0.1:{port}"],
            profile="full",
            rate={"requests_per_second": 40, "global_concurrency": 10},
            crawl={"max_pages": 40, "max_depth": 3},
        )
        print_banner(console, target, "full", f"127.0.0.1:{port}")
        result = asyncio.run(Engine(config).run())
        print_summary(console, result)
        print_proofs(console, result, limit=6)
    finally:
        httpd.shutdown()
        httpd.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
