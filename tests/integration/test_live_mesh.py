"""Two (and more) Python agents on a local nats-server, end to end."""

from __future__ import annotations

import asyncio
import time

import nats
import pytest

from agentmesh import MeshError, RejectedError, connect
from agentmesh.attestation import verify_attestation
from agentmesh.attestation import verify_manifest_signature
from agentmesh.envelope import create_envelope, encode, sign_envelope
from agentmesh.errors import ErrorCode
from agentmesh.keys import KeyPair
from agentmesh.naming import NameCheck
from agentmesh.subjects import Subjects

from .fake_registry import FakeRegistry

pytestmark = pytest.mark.integration


async def agent(server, **kw):
    kw.setdefault("require_named", False)
    return await connect(server["url"], **kw)


@pytest.fixture
async def registry(nats_server):
    reg = await FakeRegistry(nats_server["url"]).start()
    yield reg
    await reg.stop()


async def test_request_and_respond_with_trace(nats_server):
    a, b = await agent(nats_server), await agent(nats_server)
    seen = {}

    @a.on_request("chat")
    async def chat(input, ctx):
        seen["input"], seen["trace"], seen["sender"] = input, ctx.trace, ctx.sender
        return {"text": "hello back"}

    accepted = []
    try:
        r = await b.request(a.agent_id, "chat", {"text": "hello"}, timeout=5, on_accept=accepted.append)
        assert r.text == "hello back" and r.status == "completed" and r.task_id is None
        assert accepted, "a service agent sends the accept signal"
        assert seen["sender"] == b.agent_id
        assert "--- BEGIN SENDER MESSAGE ---" in seen["input"]["text"]  # fenced by default
        # the handler ran as a child span of the request; the reply is its child too
        assert r.envelope["trace"]["trace_id"] == seen["trace"]["trace_id"]
        assert r.envelope["trace"]["parent_span_id"] == seen["trace"]["span_id"]
    finally:
        await a.close(); await b.close()


async def test_sync_handler_and_errors(nats_server):
    a, b = await agent(nats_server, fence_inbound=False), await agent(nats_server)
    a.on_request("upper", lambda input, ctx: input.upper())

    def fail(input, ctx):
        raise MeshError(ErrorCode.INPUT_INVALID, "no thanks")

    def decline(input, ctx):
        raise RejectedError("not my job")

    a.on_request("fail", fail)
    a.on_request("decline", decline)
    try:
        assert (await b.request(a.agent_id, "upper", "abc", timeout=5)).output == "ABC"
        with pytest.raises(MeshError) as e:
            await b.request(a.agent_id, "fail", None, timeout=5)
        assert e.value.code == ErrorCode.INPUT_INVALID and e.value.message == "no thanks"
        r = await b.request(a.agent_id, "decline", None, timeout=5)
        assert r.status == "rejected" and r.payload["message"] == "not my job"
    finally:
        await a.close(); await b.close()


async def test_unserved_offering_without_inbox_is_offering_not_found(nats_server):
    a, b = await agent(nats_server, inbox=False), await agent(nats_server)
    try:
        with pytest.raises(MeshError) as e:
            await b.request(a.agent_id, "nothing-here", {}, timeout=5)
        assert e.value.code == ErrorCode.OFFERING_NOT_FOUND
    finally:
        await a.close(); await b.close()


async def test_nobody_listening_fails_fast(nats_server):
    b = await agent(nats_server)
    ghost = KeyPair.create().public_key
    try:
        t0 = time.monotonic()
        with pytest.raises(MeshError) as e:
            await b.request(ghost, "chat", {"text": "anyone?"}, timeout=10)
        assert e.value.code == ErrorCode.AGENT_UNAVAILABLE
        assert time.monotonic() - t0 < 5, "no-responders should not wait for the timeout"
    finally:
        await b.close()


async def test_inbox_hold_reply_and_late_answer(nats_server):
    a, b = await agent(nats_server), await agent(nats_server)
    try:
        with pytest.raises(MeshError) as e:
            await b.request(a.agent_id, "chat", {"text": "are you there?"}, timeout=1)
        assert e.value.code == ErrorCode.AGENT_UNAVAILABLE
        msg = await a.receive(timeout=3)
        assert msg is not None and msg.kind == "request" and msg.sender == b.agent_id
        assert "are you there?" in msg.text
        await msg.reply({"text": "yes, a bit late"})
        late = await b.receive(timeout=3)
        assert late is not None and late.kind == "reply" and late.text == "yes, a bit late"
        assert late.in_reply_to == e.value.details["request_id"]
        await late.ack()
        assert b.inbox() == [] and a.inbox() == []
    finally:
        await a.close(); await b.close()


async def test_send_without_waiting_and_check_inbox(nats_server):
    a, b = await agent(nats_server), await agent(nats_server)
    try:
        rid = await b.send(a.agent_id, "a note for later")
        await asyncio.sleep(0.3)
        got = await a.check_inbox()
        assert len(got) == 1 and got[0].id == rid and got[0].acked
        await got[0].reply({"text": "noted"})
        await asyncio.sleep(0.3)
        replies = await b.check_inbox()
        assert [m.text for m in replies] == ["noted"]
    finally:
        await a.close(); await b.close()


async def test_emit_and_subscribe(nats_server):
    a, b = await agent(nats_server), await agent(nats_server)
    got = asyncio.get_running_loop().create_future()

    async def on_event(payload, env):
        if not got.done():
            got.set_result((payload, env))

    try:
        await b.subscribe("orders.>", on_event)
        await asyncio.sleep(0.1)
        await a.emit("orders.created", {"text": "order 7", "total": 19.99})
        payload, env = await asyncio.wait_for(got, 3)
        assert env["from"] == a.agent_id
        assert payload["domain"] == "orders" and payload["event_type"] == "created"
        assert "order 7" in payload["data"]["text"] and payload["data"]["total"] == 19.99
    finally:
        await a.close(); await b.close()


async def test_deferred_task_lifecycle(nats_server):
    a, b = await agent(nats_server), await agent(nats_server)

    async def slow(input, ctx):
        await asyncio.sleep(0.6)
        return {"text": "done at last"}

    a.on_request("slow", slow, defer_after=0.1)
    updates = []
    b.on_task_update(lambda payload, env: updates.append(payload.get("status")))
    try:
        r = await b.request(a.agent_id, "slow", {}, timeout=5)
        assert r.status == "working" and r.task_id
        final = await b.await_task(r.task_id, timeout=5)
        assert final["status"] == "completed" and final["output"] == {"text": "done at last"}
        await asyncio.sleep(0.1)
        assert b.get_task(r.task_id).state == "completed"
        assert "completed" in updates
    finally:
        await a.close(); await b.close()


async def test_naming_rule_refuses_before_anything_is_sent(nats_server):
    target = await agent(nats_server)
    received = []
    watcher = await nats.connect(nats_server["url"])

    async def count(m):
        received.append(m)

    await watcher.subscribe(Subjects.agent_inbox(target.agent_id), cb=count)

    async def unnamed(agent_id):
        return NameCheck("unnamed")

    async def named(agent_id):
        return NameCheck("named", "kit.owner@example.com")

    b = await connect(nats_server["url"], name="Kit", owner_email="owner@example.com", name_lookup=unnamed)
    try:
        for attempt in (b.request(target.agent_id, "chat", {"text": "x"}, timeout=1), b.send(target.agent_id, "x")):
            with pytest.raises(MeshError) as e:
                await attempt
            assert e.value.code == ErrorCode.NOT_NAMED
            assert "kit.owner@example.com" in e.value.message
        with pytest.raises(MeshError):
            await b.emit("news.today", {})
        await asyncio.sleep(0.2)
        assert received == [], "a refused send publishes nothing"
        b.naming_gate._lookup = named
        await b.recheck_name()
        await b.send(target.agent_id, "now I have a name")
        await asyncio.sleep(0.2)
        assert len(received) == 1
    finally:
        await b.close(); await target.close(); await watcher.close()


async def test_forged_envelope_is_dropped(nats_server):
    a = await agent(nats_server)
    impostor, victim = KeyPair.create(), KeyPair.create()
    raw = await nats.connect(nats_server["url"])
    try:
        env = create_envelope("request", victim.public_key, to=a.agent_id, payload={"offering": "chat", "input": {"text": "trust me"}})
        sign_envelope(env, impostor)  # signed by the wrong key
        await raw.publish(Subjects.agent_inbox(a.agent_id), encode(env))
        unsigned = create_envelope("request", victim.public_key, to=a.agent_id, payload={"offering": "chat", "input": "x"})
        await raw.publish(Subjects.agent_inbox(a.agent_id), encode(unsigned))
        await asyncio.sleep(0.3)
        assert a.inbox() == []
    finally:
        await a.close(); await raw.close()


async def test_register_discover_presence_and_manifest(nats_server, registry):
    a, b = await agent(nats_server), await agent(nats_server)
    try:
        m = await a.register("vector-agent", description="answers questions",
                             offerings=[{"id": "chat", "name": "Chat", "description": "Talk."}],
                             node_profile={"availability_class": "always_on"})
        assert verify_manifest_signature(m)
        assert verify_attestation(m["node"]["attestation"], a.agent_id)
        assert a.vouch["expires_at"] and a.vouch["renew_at"]
        await asyncio.sleep(0.3)  # the first heartbeat
        found = await b.discover(offering_id="chat")
        assert [x["id"] for x in found] == [a.agent_id]
        assert await b.presence(a.agent_id) == "online"
        assert (await b.get_manifest(a.agent_id))["name"] == "vector-agent"
        await a.deregister()
        assert await b.discover(offering_id="chat") == []
    finally:
        await a.close(); await b.close()


async def test_mailbox_drain_holds_and_acks(nats_server, registry):
    """Mail sent while an agent was away is drained from its mailbox stream;
    a message held in the inbox stays unacknowledged until the app acks it."""
    seed = KeyPair.create().seed
    me = KeyPair.from_seed(seed).public_key
    await registry.ensure_mailbox(me)
    b = await agent(nats_server)
    try:
        with pytest.raises(MeshError):  # nobody home: no responders, but the stream captured it
            await b.request(me, "chat", {"text": "while you were out"}, timeout=1)
        a = await agent(nats_server, agent_seed=seed, mailbox_drain_interval=3600)
        a.on_request("ping", lambda i, c: "pong")
        await a.register("mailbox-agent")
        for _ in range(30):
            if a.inbox():
                break
            await asyncio.sleep(0.1)
        held = a.inbox()
        assert len(held) == 1 and "while you were out" in held[0].text
        js = a._nc.jetstream()
        info = await js.consumer_info(Subjects.inbox_stream(me), Subjects.inbox_durable(me))
        assert info.num_ack_pending == 1, "held, not yet acknowledged"
        await held[0].ack()
        await asyncio.sleep(0.2)
        info = await js.consumer_info(Subjects.inbox_stream(me), Subjects.inbox_durable(me))
        assert info.num_ack_pending == 0 and info.num_pending == 0
        await a.close()
    finally:
        await b.close()


async def test_a_revoked_sender_is_refused_end_to_end(nats_server, registry):
    """SPEC 5.3: the receiver asks the registry about the sender and refuses a
    revoked key with UNAUTHORIZED before its handler runs."""
    a, bad, good = await agent(nats_server), await agent(nats_server), await agent(nats_server)
    registry.revoked[bad.agent_id] = {"revoked_at": "2026-09-27T00:00:00.000Z", "replaced_by": "UNEWKEY"}
    handled = []
    a.on_request("chat", lambda i, c: handled.append(c.sender) or "hi")
    try:
        with pytest.raises(MeshError) as e:
            await bad.request(a.agent_id, "chat", "hello", timeout=5)
        assert e.value.code == ErrorCode.UNAUTHORIZED
        assert e.value.details["reason"] == "agent_key_revoked" and e.value.details["replaced_by"] == "UNEWKEY"
        assert (await good.request(a.agent_id, "chat", "hello", timeout=5)).output == "hi"
        assert handled == [good.agent_id]
    finally:
        await a.close(); await bad.close(); await good.close()
