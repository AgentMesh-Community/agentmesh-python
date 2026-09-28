"""Credential renewal at two thirds of the credential's own lifetime (SPEC 4.8)."""

import asyncio
import base64
import json

import httpx
import pytest

from agentmesh.attestation import RENEWAL_FRACTION
from agentmesh.credential import (
    CredentialRefusedError,
    CredentialRenewer,
    Credentials,
    RenewalAgent,
    build_credential_request,
    credential_check_interval_ms,
    credential_renew_at,
    decode_credential_claims,
    format_creds_file,
    parse_creds_file,
    renew_node_credential,
)
from agentmesh.keys import KeyPair, verify_signature

AGENT = KeyPair.create()
NODE = KeyPair.create()
DAY = 86400


def jwt(**claims):
    seg = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{seg({'typ': 'JWT'})}.{seg(claims)}.c2ln"


def test_decodes_claims_and_refuses_non_jwts():
    c = decode_credential_claims(jwt(sub="U1", iat=100, exp=200))
    assert (c.sub, c.iat, c.exp) == ("U1", 100, 200)
    for bad in ("", "a.b", "x.y.z", "a.b.c.d"):
        assert decode_credential_claims(bad) is None


def test_missing_exp_is_none_not_invented():
    assert decode_credential_claims(jwt(sub="U", iat=1)).exp is None
    assert credential_renew_at(decode_credential_claims(jwt(sub="U", iat=1))) is None


def test_two_thirds_into_its_own_life():
    iat, exp = 1_790_000_000, 1_790_000_000 + 30 * DAY
    at = credential_renew_at(decode_credential_claims(jwt(iat=iat, exp=exp)))
    assert at == iat * 1000 + (exp - iat) * 1000 * 2 / 3
    assert RENEWAL_FRACTION == 2 / 3  # one schedule for vouch and credential


def test_missing_iat_assumes_thirty_days():
    exp = 1_792_592_000
    at = credential_renew_at(decode_credential_claims(jwt(exp=exp)))
    assert at == (exp * 1000 - 30 * DAY * 1000) + 30 * DAY * 1000 * 2 / 3


def test_check_interval_four_times_in_last_third_capped_hourly():
    assert credential_check_interval_ms(30 * DAY * 1000) == 3600_000
    assert credential_check_interval_ms(3600_000) == 300_000
    assert credential_check_interval_ms(1) == 1


def test_request_signs_sorted_roster_and_each_consent():
    a2 = KeyPair.create()
    body = build_credential_request(NODE.seed, [RenewalAgent(AGENT.public_key, AGENT.seed), RenewalAgent(a2.public_key, a2.seed)], 1234)
    line = ",".join(sorted([AGENT.public_key, a2.public_key]))
    assert verify_signature(NODE.public_key, f"mesh-node-cred-v1:1234:{NODE.public_key}:{line}".encode(), base64.b64decode(body["node_sig"]))
    for entry, kp in zip(body["agents"], (AGENT, a2)):
        assert verify_signature(kp.public_key, f"mesh-node-agent-v1:1234:{NODE.public_key}:{kp.public_key}".encode(), base64.b64decode(entry["sig"]))


def test_request_refuses_mismatched_seed_and_empty_roster():
    with pytest.raises(ValueError):
        build_credential_request(NODE.seed, [RenewalAgent(AGENT.public_key, NODE.seed)], 1)
    with pytest.raises(ValueError):
        build_credential_request(NODE.seed, [], 1)


def mock_mesh(answers):
    """A fake control plane. ``answers`` is a list of (status, body) returned in order."""
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        status, body = answers[min(len(seen) - 1, len(answers) - 1)]
        return httpx.Response(status, json=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), seen


async def test_posts_and_returns_fresh_lease():
    client, seen = mock_mesh([(200, {"jwt": "new.jwt.x", "expires_at": "2026-10-27T00:00:00Z"})])
    fresh = await renew_node_credential("https://api.test", NODE.seed, [RenewalAgent(AGENT.public_key, AGENT.seed)], client=client)
    assert fresh.jwt == "new.jwt.x" and fresh.node_id == NODE.public_key and fresh.agents == [AGENT.public_key]
    assert seen[0]["node_id"] == NODE.public_key


async def test_refusal_is_surfaced_as_the_mesh_said_it():
    client, _ = mock_mesh([(403, {"error": "agent retired"})])
    with pytest.raises(RuntimeError, match="agent retired"):
        await renew_node_credential("https://api.test", NODE.seed, [RenewalAgent(AGENT.public_key, AGENT.seed)], client=client)


async def test_refusal_carries_the_kill_switch_code_so_a_host_waits_instead_of_retrying():
    stopped = [{"id": AGENT.public_key, "code": "agent_paused"}]
    client, _ = mock_mesh([(403, {"error": "Agent UABC... is paused by its owner", "code": "agent_paused",
                                  "retry_after_seconds": 300, "stopped": stopped})])
    with pytest.raises(CredentialRefusedError) as e:
        await renew_node_credential("https://api.test", NODE.seed, [RenewalAgent(AGENT.public_key, AGENT.seed)], client=client)
    err = e.value
    assert isinstance(err, RuntimeError)
    assert err.status == 403 and err.code == "agent_paused" and err.is_stopped
    assert err.retry_after_seconds == 300
    assert err.stopped == stopped
    assert "paused by its owner" in str(err)


async def test_refusal_without_a_code_is_not_the_kill_switch():
    client, _ = mock_mesh([(403, {"error": "agent retired"})])
    with pytest.raises(CredentialRefusedError) as e:
        await renew_node_credential("https://api.test", NODE.seed, [RenewalAgent(AGENT.public_key, AGENT.seed)], client=client)
    assert e.value.code is None and not e.value.is_stopped and e.value.retry_after_seconds is None


async def test_names_the_agents_the_mesh_left_off_because_they_are_stopped():
    stopped = [{"id": AGENT.public_key, "code": "agent_paused"}]
    client, _ = mock_mesh([(200, {"jwt": "x.y.z", "node_id": NODE.public_key, "agents": [], "expires_at": None, "stopped": stopped})])
    r = await renew_node_credential("https://api.test", NODE.seed, [RenewalAgent(AGENT.public_key, AGENT.seed)], client=client)
    assert r.stopped == stopped


def renewer(claims, answers, clock_ms, **kw):
    client, seen = mock_mesh(answers)
    r = CredentialRenewer(api_base="https://api.test", jwt=jwt(**claims), node_seed=NODE.seed,
                          agents=kw.pop("agents", [RenewalAgent(AGENT.public_key, AGENT.seed)]), client=client,
                          clock=lambda: clock_ms[0], **kw)
    return r, seen


async def test_not_due_does_nothing():
    now = [1_790_000_000_000]
    r, seen = renewer({"iat": 1_790_000_000, "exp": 1_790_000_000 + 30 * DAY}, [(200, {"jwt": jwt(iat=1, exp=2)})], now)
    assert await r.renew_if_due() is False
    assert seen == []


async def test_renews_when_due_and_adopts_fresh_credential():
    iat = 1_790_000_000
    now = [iat * 1000 + 21 * DAY * 1000]  # past two thirds of 30 days
    fresh = jwt(sub=NODE.public_key, iat=iat + 21 * DAY, exp=iat + 51 * DAY)
    r, seen = renewer({"iat": iat, "exp": iat + 30 * DAY}, [(200, {"jwt": fresh})], now)
    assert await r.renew_if_due() is True
    assert r.credential == fresh and len(seen) == 1
    assert r.renew_at_ms == (iat + 21 * DAY) * 1000 + 30 * DAY * 1000 * 2 / 3


async def test_renews_an_already_expired_credential():
    iat = 1_790_000_000
    now = [(iat + 40 * DAY) * 1000]
    r, seen = renewer({"iat": iat, "exp": iat + 30 * DAY}, [(200, {"jwt": jwt(iat=iat + 40 * DAY, exp=iat + 70 * DAY)})], now)
    assert r.status()["expired"] is True
    assert await r.renew_if_expiring() is True
    assert r.status()["expired"] is False


async def test_credential_with_no_expiry_is_left_alone():
    now = [10**15]
    r, seen = renewer({"iat": 1}, [(200, {"jwt": "x.y.z"})], now)
    assert await r.renew_if_due() is False and seen == []
    assert r.status()["expires_at"] is None


async def test_does_not_adopt_what_the_host_could_not_persist():
    iat = 1_790_000_000
    now = [(iat + 25 * DAY) * 1000]
    old = {"iat": iat, "exp": iat + 30 * DAY}

    def boom(_):
        raise OSError("disk full")

    warnings = []
    r, _ = renewer(old, [(200, {"jwt": jwt(iat=iat + 25 * DAY, exp=iat + 55 * DAY)})], now, on_renewed=boom, on_warning=warnings.append)
    before = r.credential
    assert await r.renew_if_due() is False
    assert r.credential == before
    assert warnings and warnings[0]["code"] == "credential_renewal_failed"
    assert r.status()["last_error"] == "disk full"


async def test_failure_warns_and_keeps_the_deadline_for_a_retry():
    iat = 1_790_000_000
    now = [(iat + 25 * DAY) * 1000]
    warnings = []
    r, seen = renewer({"iat": iat, "exp": iat + 30 * DAY}, [(500, {}), (200, {"jwt": jwt(iat=iat + 25 * DAY, exp=iat + 55 * DAY)})], now, on_warning=warnings.append)
    deadline = r.renew_at_ms
    assert await r.renew_if_due() is False
    assert r.renew_at_ms == deadline and len(warnings) == 1
    assert await r.renew_if_due() is True
    assert len(seen) == 2


async def test_roster_function_is_read_at_renewal_time():
    iat = 1_790_000_000
    now = [(iat + 25 * DAY) * 1000]
    roster = [RenewalAgent(AGENT.public_key, AGENT.seed)]
    r, seen = renewer({"iat": iat, "exp": iat + 30 * DAY}, [(200, {"jwt": jwt(iat=iat, exp=iat + 90 * DAY)})], now, agents=lambda: list(roster))
    late = KeyPair.create()
    roster.append(RenewalAgent(late.public_key, late.seed))
    await r.renew_if_due()
    assert {a["id"] for a in seen[0]["agents"]} == {AGENT.public_key, late.public_key}


async def test_start_and_stop_do_not_double_up():
    now = [0]
    r, _ = renewer({"iat": 1, "exp": 10**9}, [(200, {"jwt": "a.b.c"})], now)
    r.start()
    first = r._task
    r.start()
    # Task.cancelling() is 3.11+; on 3.10 let the cancel land and check it did.
    for _ in range(3):
        await asyncio.sleep(0)
    assert first.done()
    r.stop()
    await asyncio.sleep(0)
    assert r._task is None


def test_creds_file_round_trip_and_credentials_folder(tmp_path):
    text = format_creds_file("J.W.T", NODE.seed)
    assert parse_creds_file(text) == ("J.W.T", NODE.seed)
    c = Credentials(agent_seed=AGENT.seed, jwt="J.W.T", connection_seed=NODE.seed, servers=["nats://x:4222"], api_base="https://api.test")
    c.save(tmp_path / "agent")
    back = Credentials.load(tmp_path / "agent")
    assert (back.agent_seed, back.jwt, back.connection_seed, back.servers, back.api_base) == (AGENT.seed, "J.W.T", NODE.seed, ["nats://x:4222"], "https://api.test")
    assert AGENT.seed not in repr(back) and "J.W.T" not in repr(back)
