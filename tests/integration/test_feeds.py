"""Feeds (SPEC 6.6a) and the durable feed consumer (SPEC 18.6), on a local nats-server."""

from __future__ import annotations

import asyncio

import nats
import pytest
from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType, StreamConfig

from agentmesh import DurableFeedSubscription, MeshError, connect
from agentmesh.subjects import Subjects

pytestmark = pytest.mark.integration


async def agent(server, **kw):
    kw.setdefault("require_named", False)
    return await connect(server["url"], **kw)


async def feed_stream(server) -> None:
    """MESH_FEED with the platform's configuration (services/src/shared/feed-stream.ts)."""
    nc = await nats.connect(server["url"])
    try:
        js = nc.jetstream()
        try:
            await js.delete_stream("MESH_FEED")
        except Exception:
            pass
        await js.add_stream(StreamConfig(
            name="MESH_FEED", subjects=["mesh.feed.*.*"], retention=RetentionPolicy.INTEREST,
            discard=DiscardPolicy.OLD, storage=StorageType.FILE, max_age=24 * 3600, duplicate_window=120,
        ))
    finally:
        await nc.close()


def test_feed_subjects_and_consumer_name():
    owner = "U" + "A" * 55
    assert Subjects.feed(owner, "ring-round") == f"mesh.feed.{owner}.ring-round"
    assert Subjects.feed_pattern(owner, "*") == f"mesh.feed.{owner}.*"
    assert Subjects.feed_consumer(owner) == f"mesh_feed_{owner}"
    with pytest.raises(MeshError):
        Subjects.feed(owner, "ring.round")


async def test_live_feed(nats_server):
    owner, reader = await agent(nats_server), await agent(nats_server)
    got = asyncio.get_running_loop().create_future()
    try:
        await reader.subscribe_feed(owner.agent_id, "news", lambda p, e: got.done() or got.set_result((p, e)))
        await asyncio.sleep(0.1)
        await owner.publish_feed("news", {"n": 1}, kind="stream")
        payload, env = await asyncio.wait_for(got, 3)
        assert env["from"] == owner.agent_id
        assert payload["topic"] == "news" and payload["kind"] == "stream" and payload["data"] == {"n": 1}
    finally:
        await owner.close(); await reader.close()


async def test_durable_feed_delivers_what_was_published_while_away(nats_server):
    await feed_stream(nats_server)
    owner = await agent(nats_server)
    reader = await agent(nats_server)
    got: list = []
    try:
        sub = await reader.subscribe_feed(owner.agent_id, "ring-round", lambda p, e: got.append(p["data"]), durable=True)
        assert isinstance(sub, DurableFeedSubscription)
        assert sub.durable == f"mesh_feed_{reader.agent_id}"
        await owner.publish_feed("ring-round", {"n": 1}, kind="stream")
        for _ in range(40):
            if got:
                break
            await asyncio.sleep(0.1)
        assert got == [{"n": 1}]
        rid = reader.agent_id
        seed = reader._kp.seed
        await reader.close()

        await owner.publish_feed("ring-round", {"n": 2}, kind="stream")
        await owner.publish_feed("ring-round", {"n": 3}, kind="stream")
        await asyncio.sleep(0.3)

        got.clear()
        reader = await agent(nats_server, agent_seed=seed)
        assert reader.agent_id == rid
        await reader.subscribe_feed(owner.agent_id, "ring-round", lambda p, e: got.append(p["data"]), durable=True)
        for _ in range(80):
            if len(got) >= 2:
                break
            await asyncio.sleep(0.1)
        assert got == [{"n": 2}, {"n": 3}]

        # A second feed goes onto the same consumer's filters.
        got2: list = []
        await reader.subscribe_feed(owner.agent_id, "other", lambda p, e: got2.append(p["data"]), durable=True)
        await owner.publish_feed("other", {"m": 1}, kind="stream")
        for _ in range(40):
            if got2:
                break
            await asyncio.sleep(0.1)
        assert got2 == [{"m": 1}]
        nc = await nats.connect(nats_server["url"])
        try:
            info = await nc.jetstream().consumer_info("MESH_FEED", f"mesh_feed_{rid}")
            assert sorted(info.config.filter_subjects) == sorted([
                f"mesh.feed.{owner.agent_id}.ring-round", f"mesh.feed.{owner.agent_id}.other"])
        finally:
            await nc.close()
    finally:
        await owner.close(); await reader.close()


async def test_durable_feed_refuses_without_the_stream(nats_server):
    nc = await nats.connect(nats_server["url"])
    try:
        try:
            await nc.jetstream().delete_stream("MESH_FEED")
        except Exception:
            pass
    finally:
        await nc.close()
    owner, reader = await agent(nats_server), await agent(nats_server)
    try:
        with pytest.raises(MeshError, match="renewed"):
            await reader.subscribe_feed(owner.agent_id, "ring-round", lambda p, e: None, durable=True)
    finally:
        await owner.close(); await reader.close()
