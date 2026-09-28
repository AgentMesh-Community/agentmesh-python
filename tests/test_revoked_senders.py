"""SPEC 5.3: "A message signed by a revoked agent key MUST be rejected."

The receive path asks the registry about each sender (with a short memo),
refuses a revoked one with UNAUTHORIZED / agent_key_revoked and a paused one
with UNAUTHORIZED / agent_paused, lets everyone through when the registry
cannot answer, and never forgets a key it has seen revoked. Mirrors the
TypeScript SDK's revoked-senders.test.ts.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from nats.errors import NoRespondersError

from agentmesh.envelope import create_envelope, decode, encode, sign_envelope
from agentmesh.errors import ErrorCode
from agentmesh.keys import KeyPair
from agentmesh.mesh import AgentMesh
from agentmesh.revoked_senders import RevocationAnswer, RevokedSender, RevokedSenders
from agentmesh.subjects import Subjects

REVOKED_AT = "2026-09-27T00:00:00.000Z"
PAUSED_SINCE = "2026-09-27T10:00:00.000Z"


class FakeNats:
    """A connection whose registry answers ``get`` for keys in ``revoked`` as
    revoked and for keys in ``paused`` with a paused manifest, and can be
    switched to failing."""

    max_payload = 0

    def __init__(self, revoked=(), paused=()):
        self.registry = KeyPair.create()
        self.revoked = set(revoked)
        self.paused = set(paused)
        self.registry_down = False
        self.gets = 0
        self.published: list[tuple[str, bytes]] = []

    def _answer(self, req, **kw):
        env = create_envelope("respond", self.registry.public_key, to=req["from"], in_reply_to=req["id"], **kw)
        return SimpleNamespace(data=encode(sign_envelope(env, self.registry)))

    async def request(self, subject, data, timeout=None):
        req = decode(data)
        assert subject.startswith("mesh.registry.get.")
        self.gets += 1
        if self.registry_down:
            raise NoRespondersError()
        key = subject[len("mesh.registry.get."):]
        if key in self.revoked:
            return self._answer(req, error={
                "code": "UNAUTHORIZED", "message": "revoked", "retryable": False,
                "details": {"reason": "agent_key_revoked", "revoked_at": REVOKED_AT, "replaced_by": "UNEWKEY"},
            })
        if key in self.paused:
            return self._answer(req, payload={"id": key, "status": "paused", "status_since": PAUSED_SINCE})
        return self._answer(req, error={"code": "AGENT_UNAVAILABLE", "message": "not found", "retryable": False})

    async def publish(self, subject, data, headers=None):
        self.published.append((subject, data))


def setup(revoked=(), paused=(), refuse=True):
    nc = FakeNats(revoked, paused)
    kp = KeyPair.create()
    mesh = AgentMesh(nc, kp, kp)  # type: ignore[arg-type]
    if not refuse:
        mesh._revoked_senders = None
    warnings: list[dict] = []
    mesh.on_warning = warnings.append
    handled: list[str] = []

    def chat(input, ctx):
        handled.append(ctx.sender)
        return {"ok": True}

    mesh.on_request("chat", chat)
    return nc, mesh, handled, warnings


async def send(nc: FakeNats, mesh: AgentMesh, sender: KeyPair) -> list[dict]:
    env = sign_envelope(create_envelope("request", sender.public_key, to=mesh.agent_id,
                                        payload={"offering": "chat", "input": {"text": "hi"}}), sender)
    before = len(nc.published)
    await mesh._on_inbound(encode(env), Subjects.agent_inbox(mesh.agent_id), "_INBOX.x", None, False)
    return [decode(d) for s, d in nc.published[before:] if s == Subjects.agent_inbox(sender.public_key)]


# ── the receive path ────────────────────────────────────────────────────────


async def test_refuses_a_revoked_key_and_handles_a_good_one():
    bad, good = KeyPair.create(), KeyPair.create()
    nc, mesh, handled, warnings = setup(revoked=[bad.public_key])

    refused = await send(nc, mesh, bad)
    assert handled == []
    assert len(refused) == 1
    err = refused[0]["error"]
    assert err["code"] == ErrorCode.UNAUTHORIZED
    assert err["retryable"] is False
    assert err["message"] == "The key that signed this message has been revoked, so it is refused (§5.3)."
    assert err["details"] == {"reason": "agent_key_revoked", "revoked_at": REVOKED_AT, "replaced_by": "UNEWKEY"}
    assert any(w["code"] == "revoked_sender" and w["from"] == bad.public_key and "UNEWKEY" in w["message"] for w in warnings)

    await send(nc, mesh, good)
    assert handled == [good.public_key]


async def test_refuses_a_paused_sender():
    stopped = KeyPair.create()
    nc, mesh, handled, warnings = setup(paused=[stopped.public_key])
    refused = await send(nc, mesh, stopped)
    assert handled == []
    err = refused[0]["error"]
    assert err["code"] == ErrorCode.UNAUTHORIZED
    assert err["details"] == {"reason": "agent_paused", "stopped_at": PAUSED_SINCE}
    assert err["message"].startswith("The agent that sent this is paused by its owner or by AgentMesh")
    assert any(w["code"] == "stopped_sender" and w["from"] == stopped.public_key for w in warnings)


async def test_lets_a_sender_through_when_the_registry_cannot_answer():
    sender = KeyPair.create()
    nc, mesh, handled, _ = setup()
    nc.registry_down = True
    await send(nc, mesh, sender)
    assert handled == [sender.public_key]


async def test_keeps_refusing_a_key_it_has_seen_revoked_after_the_registry_goes_quiet():
    bad = KeyPair.create()
    nc, mesh, handled, _ = setup(revoked=[bad.public_key])
    await send(nc, mesh, bad)
    nc.registry_down = True
    again = await send(nc, mesh, bad)
    assert handled == []
    assert again[0]["error"]["details"]["reason"] == "agent_key_revoked"


async def test_asks_once_per_sender_not_once_per_message():
    sender = KeyPair.create()
    nc, mesh, _, _ = setup()
    await send(nc, mesh, sender)
    await send(nc, mesh, sender)
    assert nc.gets == 1


async def test_does_nothing_when_the_host_turned_it_off():
    bad = KeyPair.create()
    nc, mesh, handled, _ = setup(revoked=[bad.public_key], refuse=False)
    await send(nc, mesh, bad)
    assert handled == [bad.public_key]
    assert nc.gets == 0


# ── the memo ────────────────────────────────────────────────────────────────


async def test_reasks_about_a_good_key_once_the_short_memo_runs_out():
    t = [0.0]
    state = {"revoked": False, "calls": 0}

    async def lookup(key):
        state["calls"] += 1
        return RevocationAnswer("revoked" if state["revoked"] else "not_revoked")

    r = RevokedSenders(lookup, lambda: t[0])
    assert await r.check("UK") is None
    state["revoked"] = True
    assert await r.check("UK") is None
    t[0] += RevokedSenders.OK_MS + 1
    assert await r.check("UK") is not None
    assert state["calls"] == 2


async def test_refuses_a_paused_sender_and_lets_it_back_in_within_a_minute_of_the_resume():
    t = [0.0]
    state = {"paused": True}

    async def lookup(key):
        return RevocationAnswer("paused", since=PAUSED_SINCE) if state["paused"] else RevocationAnswer("not_revoked")

    r = RevokedSenders(lookup, lambda: t[0])
    assert await r.check("UP") == RevokedSender(paused=True, since=PAUSED_SINCE)
    state["paused"] = False
    # Still remembered as paused inside the memo, then asked again.
    got = await r.check("UP")
    assert got is not None and got.paused
    t[0] += RevokedSenders.OK_MS + 1
    assert await r.check("UP") is None


async def test_treats_a_lookup_that_never_answers_as_unknown_after_its_own_timeout(monkeypatch):
    monkeypatch.setattr(RevokedSenders, "LOOKUP_TIMEOUT_S", 0.05)

    async def never(key):
        await asyncio.Event().wait()

    r = RevokedSenders(never)
    assert await asyncio.wait_for(r.check("UK"), 1.0) is None


async def test_a_failed_lookup_is_remembered_for_the_short_failure_window_only():
    t = [0.0]
    calls = [0]

    async def failing(key):
        calls[0] += 1
        raise RuntimeError("registry down")

    r = RevokedSenders(failing, lambda: t[0])
    assert await r.check("UK") is None
    assert await r.check("UK") is None
    assert calls[0] == 1
    t[0] += RevokedSenders.FAILED_MS + 1
    assert await r.check("UK") is None
    assert calls[0] == 2


async def test_concurrent_checks_for_one_key_share_one_lookup():
    calls = [0]
    gate = asyncio.Event()

    async def slow(key):
        calls[0] += 1
        await gate.wait()
        return RevocationAnswer("revoked", replaced_by="UNEW")

    r = RevokedSenders(slow)
    checks = [asyncio.ensure_future(r.check("UK")) for _ in range(5)]
    await asyncio.sleep(0)
    gate.set()
    results = await asyncio.gather(*checks)
    assert calls[0] == 1
    assert all(x is not None and x.replaced_by == "UNEW" for x in results)


async def test_a_remembered_revocation_outlives_any_later_answer():
    async def fine(key):
        return RevocationAnswer("not_revoked")

    r = RevokedSenders(fine)
    r.remember("UK", RevokedSender(revoked_at=REVOKED_AT))
    got = await r.check("UK")
    assert got is not None and got.revoked_at == REVOKED_AT
