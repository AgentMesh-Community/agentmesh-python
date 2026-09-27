"""A throwaway local nats-server for the integration tests.

Found on PATH, at $NATS_SERVER_BIN, or under tools/.bin (where a developer can
unpack a release). When none is found every integration test is skipped. The
server listens on 127.0.0.1 only, with JetStream (for the mailbox) and
WebSocket (so a TypeScript peer can join), and is stopped after the session.
Nothing here touches a real mesh.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def find_nats_server() -> str | None:
    env = os.environ.get("NATS_SERVER_BIN")
    if env and Path(env).exists():
        return env
    on_path = shutil.which("nats-server")
    if on_path:
        return on_path
    for p in sorted((ROOT / "tools" / ".bin").glob("**/nats-server*")):
        if p.is_file() and p.suffix in ("", ".exe"):
            return str(p)
    return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def nats_server(tmp_path_factory):
    binary = find_nats_server()
    if binary is None:
        pytest.skip("no nats-server found (PATH, $NATS_SERVER_BIN or tools/.bin); integration tests skipped")
    port, ws_port = free_port(), free_port()
    store = tmp_path_factory.mktemp("js")
    conf = store / "nats.conf"
    conf.write_text(
        f'listen: "127.0.0.1:{port}"\n'
        f'jetstream {{ store_dir: "{store.as_posix()}" }}\n'
        f'websocket {{ listen: "127.0.0.1:{ws_port}", no_tls: true }}\n',
        encoding="utf-8",
    )
    proc = subprocess.Popen([binary, "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.skip("nats-server did not start")
    yield {"url": f"nats://127.0.0.1:{port}", "ws": f"ws://127.0.0.1:{ws_port}"}
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
