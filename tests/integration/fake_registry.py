"""A tiny stand-in for the registry service, enough for register/discover/get.

It answers the way the real one does: signed envelopes, ``in_reply_to`` bound
to the request, manifests stamped with availability from heartbeats. It also
creates each registered agent's mailbox stream, as the real registry does.
"""

from __future__ import annotations

from typing import Any

import nats

from agentmesh.envelope import create_envelope, decode, encode, sign_envelope
from agentmesh.keys import KeyPair
from agentmesh.subjects import Subjects


class FakeRegistry:
    def __init__(self, url: str):
        self.url = url
        self.kp = KeyPair.create()
        self.manifests: dict[str, dict[str, Any]] = {}
        self.online: set[str] = set()
        self.nc: Any = None

    async def start(self) -> "FakeRegistry":
        self.nc = await nats.connect(self.url)
        await self.nc.subscribe(Subjects.REGISTRY_REGISTER, cb=self._register)
        await self.nc.subscribe(Subjects.REGISTRY_DISCOVER, cb=self._discover)
        await self.nc.subscribe("mesh.registry.get.*", cb=self._get)
        await self.nc.subscribe(Subjects.REGISTRY_DEREGISTER, cb=self._deregister)
        await self.nc.subscribe("mesh.heartbeat.*", cb=self._heartbeat)
        return self

    async def stop(self) -> None:
        await self.nc.drain()

    def _reply(self, req: dict[str, Any], payload: Any = None, error: dict[str, Any] | None = None) -> bytes:
        env = create_envelope("respond", self.kp.public_key, to=req["from"], in_reply_to=req["id"], payload=payload, error=error)
        return encode(sign_envelope(env, self.kp))

    async def ensure_mailbox(self, agent_id: str) -> None:
        from nats.js.api import StreamConfig

        js = self.nc.jetstream()
        try:
            await js.add_stream(StreamConfig(name=Subjects.inbox_stream(agent_id), subjects=[Subjects.agent_inbox(agent_id)]))
        except Exception:
            pass

    async def _register(self, msg) -> None:
        req = decode(msg.data)
        m = req["payload"]
        if m.get("id") != req["from"]:
            await msg.respond(self._reply(req, error={"code": "IDENTITY_MISMATCH", "message": "manifest id is not the sender", "retryable": False}))
            return
        self.manifests[m["id"]] = m
        await self.ensure_mailbox(m["id"])
        await msg.respond(self._reply(req, {"ok": True}))

    async def _deregister(self, msg) -> None:
        req = decode(msg.data)
        self.manifests.pop(req["from"], None)
        await msg.respond(self._reply(req, {"ok": True}))

    def _stamp(self, m: dict[str, Any]) -> dict[str, Any]:
        return {**m, "availability": "online" if m.get("node", {}).get("id") in self.online else "offline"}

    async def _discover(self, msg) -> None:
        req = decode(msg.data)
        q = req.get("payload") or {}
        agents = [self._stamp(m) for m in self.manifests.values()]
        if q.get("agent_ids"):
            agents = [m for m in agents if m["id"] in q["agent_ids"]]
        if q.get("capabilities"):
            agents = [m for m in agents if set(q["capabilities"]) <= set(m.get("capabilities") or [])]
        if q.get("offering_id"):
            agents = [m for m in agents if any(o.get("id") == q["offering_id"] for o in m.get("offerings") or [])]
        await msg.respond(self._reply(req, {"agents": agents, "total": len(agents)}))

    async def _get(self, msg) -> None:
        req = decode(msg.data)
        agent_id = msg.subject.split(".")[-1]
        m = self.manifests.get(agent_id)
        if m is None:
            await msg.respond(self._reply(req, error={"code": "NOT_FOUND", "message": "no such agent", "retryable": False}))
        else:
            await msg.respond(self._reply(req, self._stamp(m)))

    async def _heartbeat(self, msg) -> None:
        env = decode(msg.data)
        node = msg.subject.split(".")[2]
        if env["from"] == node or (env.get("payload") or {}).get("node") == node:
            self.online.add(node)
