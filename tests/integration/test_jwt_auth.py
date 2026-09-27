"""The credential path the real mesh uses, on a local nats-server in operator mode.

The test mints its own operator, account and user JWTs (nothing real), starts a
server that only admits users of that account, and connects the way a joined
agent does: a user JWT bound to a separate connection key, which signs the
server's nonce, while the agent's own key signs its envelopes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time

import pytest
from nacl.signing import SigningKey

from agentmesh import ErrorCode, MeshError, connect
from agentmesh.keys import KeyPair

from .conftest import find_nats_server, free_port

pytestmark = pytest.mark.integration

OPERATOR, ACCOUNT = 14 << 3, 0


def b64(o) -> str:
    raw = o if isinstance(o, bytes) else json.dumps(o, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def mint(issuer: KeyPair, subject: str, nats_claims: dict, **extra) -> str:
    claims = {"iat": int(time.time()), "iss": issuer.public_key, "name": subject[:8], "sub": subject, "nats": nats_claims, **extra}
    claims["jti"] = base64.b32encode(hashlib.sha256(json.dumps(claims, sort_keys=True).encode()).digest()).decode().rstrip("=")
    head = b64({"typ": "JWT", "alg": "ed25519-nkey"})
    body = b64(claims)
    return f"{head}.{body}.{b64(issuer.sign(f'{head}.{body}'.encode()))}"


@pytest.fixture(scope="module")
def auth_server(tmp_path_factory):
    binary = find_nats_server()
    if binary is None:
        pytest.skip("no nats-server found")
    op = KeyPair(SigningKey.generate(), OPERATOR)
    acc = KeyPair(SigningKey.generate(), ACCOUNT)
    op_jwt = mint(op, op.public_key, {"type": "operator", "version": 2})
    unlimited = {k: -1 for k in ("subs", "data", "payload", "imports", "exports", "conn", "leaf", "mem_storage", "disk_storage", "streams", "consumer")}
    acc_jwt = mint(op, acc.public_key, {"limits": {**unlimited, "wildcards": True}, "type": "account", "version": 2})
    d = tmp_path_factory.mktemp("auth")
    (d / "op.jwt").write_text(op_jwt)
    port = free_port()
    (d / "nats.conf").write_text(
        f'listen: "127.0.0.1:{port}"\n'
        f'operator: "{(d / "op.jwt").as_posix()}"\n'
        "resolver: MEMORY\n"
        f"resolver_preload: {{ {acc.public_key}: \"{acc_jwt}\" }}\n"
    )
    proc = subprocess.Popen([binary, "-c", str(d / "nats.conf")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    if proc.poll() is not None:
        pytest.skip("nats-server would not start in operator mode")
    yield {"url": f"nats://127.0.0.1:{port}", "account": acc}
    proc.terminate()
    proc.wait(timeout=5)


def user_jwt(acc: KeyPair, user: KeyPair, exp_in: int = 3600) -> str:
    return mint(acc, user.public_key, {"pub": {}, "sub": {}, "subs": -1, "data": -1, "payload": -1, "type": "user", "version": 2},
                exp=int(time.time()) + exp_in)


async def test_joined_agent_connects_with_a_separate_connection_key(auth_server):
    agent_seed = KeyPair.create().seed
    conn_key = KeyPair.create()
    jwt = user_jwt(auth_server["account"], conn_key)
    a = await connect(auth_server["url"], agent_seed=agent_seed, jwt=jwt, connection_seed=conn_key.seed, require_named=False)
    b = await connect(auth_server["url"], jwt=user_jwt(auth_server["account"], (k := KeyPair.create())), connection_seed=k.seed, require_named=False)
    a.on_request("chat", lambda i, c: "authenticated hello")
    try:
        assert a.agent_id == KeyPair.from_seed(agent_seed).public_key != conn_key.public_key
        assert (await b.request(a.agent_id, "chat", {"text": "hi"}, timeout=5)).output == "authenticated hello"
    finally:
        await a.close(); await b.close()


async def test_wrong_connection_key_is_refused(auth_server):
    jwt = user_jwt(auth_server["account"], KeyPair.create())
    with pytest.raises(MeshError) as e:
        await connect(auth_server["url"], jwt=jwt, connection_seed=KeyPair.create().seed, require_named=False,
                      max_reconnect_attempts=0, connect_timeout=3)
    assert e.value.code == ErrorCode.TRANSPORT_PERMISSION_DENIED


async def test_no_credential_is_refused(auth_server):
    with pytest.raises(MeshError) as e:
        await connect(auth_server["url"], require_named=False, max_reconnect_attempts=0, connect_timeout=3)
    assert e.value.code == ErrorCode.TRANSPORT_PERMISSION_DENIED


async def test_expired_credential_is_refused(auth_server):
    k = KeyPair.create()
    with pytest.raises(MeshError) as e:
        await connect(auth_server["url"], jwt=user_jwt(auth_server["account"], k, exp_in=-60), connection_seed=k.seed,
                      require_named=False, connect_timeout=3)
    assert e.value.code == ErrorCode.TRANSPORT_PERMISSION_DENIED
