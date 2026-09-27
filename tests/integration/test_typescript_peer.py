"""A Python agent and a TypeScript SDK agent talking on one local nats-server.

The strongest check that the two SDKs agree: each verifies the other's
signatures on live traffic, answers the other's requests, and receives the
other's events. Skipped when node or the AgentMesh repository is not present.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path

import pytest

from agentmesh import connect

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
AM = Path(os.environ.get("AGENTMESH_REPO", ROOT.parent / "AgentMesh"))


class TsPeer:
    def __init__(self, proc):
        self.proc = proc
        self.id = ""

    async def line(self, timeout=60.0) -> dict:
        raw = await asyncio.wait_for(self.proc.stdout.readline(), timeout)
        if not raw:
            raise RuntimeError("the TypeScript peer exited")
        return json.loads(raw)

    async def send(self, cmd: dict) -> dict:
        self.proc.stdin.write((json.dumps(cmd) + "\n").encode())
        await self.proc.stdin.drain()
        return await self.line(30)


@pytest.fixture
async def ts_peer(nats_server):
    node = shutil.which("node")
    if node is None or not (AM / "sdk-typescript" / "src" / "index.ts").exists() or not (AM / "sdk-typescript" / "node_modules" / "esbuild").exists():
        pytest.skip("node or the AgentMesh TypeScript SDK (with its node_modules) is not available")
    proc = await asyncio.create_subprocess_exec(
        node, str(ROOT / "tools" / "ts-peer.mjs"), nats_server["ws"], str(AM),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    peer = TsPeer(proc)
    hello = await peer.line(120)
    assert hello.get("ready"), hello
    peer.id = hello["id"]
    yield peer
    try:
        proc.stdin.write(b'{"quit": true}\n')
        await proc.stdin.drain()
        await asyncio.wait_for(proc.wait(), 10)
    except Exception:
        proc.kill()


async def test_python_asks_typescript(nats_server, ts_peer):
    py = await connect(nats_server["url"], require_named=False)
    try:
        r = await py.request(ts_peer.id, "chat", {"text": "grüße from Python 🐍"}, timeout=10)
        assert r.status == "completed"
        assert r.output["text"] == "ts heard: grüße from Python 🐍"
        assert r.output["trace_id"] == r.envelope["trace"]["trace_id"]  # one trace across languages
    finally:
        await py.close()


async def test_typescript_asks_python(nats_server, ts_peer):
    py = await connect(nats_server["url"], require_named=False, fence_inbound=False)
    py.on_request("chat", lambda input, ctx: {"text": f"py heard: {input['text']}", "ratio": 0.1, "big": 1e21})
    try:
        out = await ts_peer.send({"ask": py.agent_id, "text": "hello from TypeScript"})
        assert out.get("status") == "completed", out
        assert out["answer"] == {"text": "py heard: hello from TypeScript", "ratio": 0.1, "big": 1e21}
    finally:
        await py.close()


async def test_typescript_event_reaches_python(nats_server, ts_peer):
    py = await connect(nats_server["url"], require_named=False, fence_inbound=False)
    got = asyncio.get_running_loop().create_future()

    async def on_event(payload, env):
        if not got.done():
            got.set_result((payload, env))

    try:
        await py.subscribe("interop.>", on_event)
        await asyncio.sleep(0.2)
        assert (await ts_peer.send({"emit": "interop.ping", "data": {"n": 1, "x": 0.000001}}))["emitted"]
        payload, env = await asyncio.wait_for(got, 5)
        assert env["from"] == ts_peer.id and payload["data"] == {"n": 1, "x": 0.000001}
    finally:
        await py.close()
