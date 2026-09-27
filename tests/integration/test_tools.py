"""The four framework tools, and their LangChain and CrewAI shapes, live."""

from __future__ import annotations

import asyncio
import importlib.util

import pytest

from agentmesh import connect
from agentmesh.sync import connect as connect_sync
from agentmesh.tools import MeshTools

from .fake_registry import FakeRegistry

pytestmark = pytest.mark.integration


async def test_async_tools(nats_server):
    reg = await FakeRegistry(nats_server["url"]).start()
    helper = await connect(nats_server["url"], require_named=False, fence_inbound=False)
    me = await connect(nats_server["url"], require_named=False)
    helper.on_request("chat", lambda i, c: {"text": f"helper says: {i['text']}"})
    await helper.register("weather-helper", description="Knows the weather in Denver",
                          offerings=[{"id": "chat", "name": "Chat", "description": "Talk."}], capabilities=["weather"])
    tools = MeshTools(me, ask_timeout=5)
    try:
        assert await tools.ask_agent(helper.agent_id, "is it sunny?") == "helper says: is it sunny?"
        assert "weather-helper" in await tools.find_agent("weather")
        assert helper.agent_id in await tools.find_agent("denver weather")
        assert "No agent matches" in await tools.find_agent("submarines")
        assert "Your inbox is empty." == await tools.check_inbox()
        sent = await tools.send_to_agent(helper.agent_id, "thanks")
        assert sent.startswith(f"Sent to {helper.agent_id}")
        await asyncio.sleep(0.3)
        inbox = await tools.check_inbox()
        assert "answer from" in inbox and "helper says: thanks" in inbox
        # blocking forms, called from a worker thread, run on the agent's loop
        send, ask, check, find = tools.functions(sync=True)
        assert await asyncio.to_thread(ask, helper.agent_id, "from a thread") == "helper says: from a thread"
        assert find.__doc__ and ask.__name__ == "ask_agent"
    finally:
        await me.close(); await helper.close(); await reg.stop()


async def test_unknown_target_is_a_readable_answer_not_an_exception(nats_server):
    me = await connect(nats_server["url"], require_named=False)
    try:
        tools = MeshTools(me, ask_timeout=1)
        out = await tools.ask_agent("UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "hi")
        assert out.startswith("No answer from")
    finally:
        await me.close()


def test_sync_client_and_tools(nats_server):
    helper = connect_sync(nats_server["url"], require_named=False, fence_inbound=False)
    me = connect_sync(nats_server["url"], require_named=False)
    helper.on_request("chat", lambda i, c: {"text": "sync hello"})
    try:
        assert me.ask(helper.agent_id, "hi", timeout=5) == "sync hello"
        tools = MeshTools(me, ask_timeout=5)
        _, ask, _, _ = tools.functions(sync=True)
        assert ask(helper.agent_id, "again") == "sync hello"
    finally:
        me.close(); helper.close()


@pytest.mark.skipif(importlib.util.find_spec("langchain_core") is None, reason="langchain-core not installed")
async def test_langchain_tools(nats_server):
    from agentmesh.integrations.langchain import mesh_tools

    helper = await connect(nats_server["url"], require_named=False, fence_inbound=False)
    me = await connect(nats_server["url"], require_named=False)
    helper.on_request("chat", lambda i, c: {"text": f"lc: {i['text']}"})
    try:
        tools = {t.name: t for t in mesh_tools(me, ask_timeout=5)}
        assert set(tools) == {"send_to_agent", "ask_agent", "check_inbox", "find_agent"}
        assert set(tools["ask_agent"].args) == {"to", "question"}
        assert await tools["ask_agent"].ainvoke({"to": helper.agent_id, "question": "async"}) == "lc: async"
        out = await asyncio.to_thread(tools["ask_agent"].invoke, {"to": helper.agent_id, "question": "sync"})
        assert out == "lc: sync"
    finally:
        await me.close(); await helper.close()


@pytest.mark.skipif(importlib.util.find_spec("crewai") is None, reason="crewai not installed")
def test_crewai_tools(nats_server):
    from agentmesh.integrations.crewai import mesh_tools

    helper = connect_sync(nats_server["url"], require_named=False, fence_inbound=False)
    me = connect_sync(nats_server["url"], require_named=False)
    helper.on_request("chat", lambda i, c: {"text": f"crew: {i['text']}"})
    try:
        tools = {t.name: t for t in mesh_tools(me, ask_timeout=5)}
        assert set(tools) == {"send_to_agent", "ask_agent", "check_inbox", "find_agent"}
        assert tools["ask_agent"].run(to=helper.agent_id, question="hello") == "crew: hello"
        assert tools["check_inbox"].run() == "Your inbox is empty."
    finally:
        me.close(); helper.close()
