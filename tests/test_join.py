"""Joining once: the agent key is traded at /v1/bootstrap and everything is saved."""

import json

import httpx
import pytest

from agentmesh import Credentials, join
from agentmesh.credential import format_creds_file
from agentmesh.keys import KeyPair

CONN = KeyPair.create()


def control_plane(status=200, body=None):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, json.loads(request.content)))
        if body is not None:
            return httpx.Response(status, json=body)
        return httpx.Response(200, json={
            "ok": True, "jwt": "e30.e30.c2ln", "seed": CONN.seed, "creds": format_creds_file("e30.e30.c2ln", CONN.seed),
            "label": "my agent", "handle": "kit.owner@example.com", "account_email": "owner@example.com",
            "expires_at": "2026-10-27T00:00:00.000Z", "renew_url": "https://api.test/v1/node-credential",
            "mesh": {"name": "agentmesh.ai", "endpoints": ["nats://mesh.test:4222", "ws://mesh.test:4443"]},
        })

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), seen


async def test_join_trades_the_key_once_and_saves(tmp_path):
    client, seen = control_plane()
    creds = await join("am_test", tmp_path / "agent", api_base="https://api.test", client=client)
    path, body = seen[0]
    assert path == "/v1/bootstrap"
    assert body == {"token": "am_test", "agent_id": creds.agent_id}
    back = Credentials.load(tmp_path / "agent")
    assert back.agent_id == creds.agent_id and back.connection_seed == CONN.seed
    assert back.servers == ["nats://mesh.test:4222", "ws://mesh.test:4443"]
    assert back.handle == "kit.owner@example.com" and back.api_base == "https://api.test"
    # the agent's own key is kept on a second join
    client2, _ = control_plane()
    again = await join("am_second", tmp_path / "agent", api_base="https://api.test", client=client2)
    assert again.agent_id == creds.agent_id


async def test_a_refused_key_says_why(tmp_path):
    client, _ = control_plane(401, {"error": "this agent key was already used"})
    with pytest.raises(RuntimeError, match="already used"):
        await join("am_used", tmp_path / "agent", api_base="https://api.test", client=client)
