"""The mesh tools as plain functions, for Google ADK, AutoGen and LlamaIndex.

Those frameworks turn a typed, documented Python function into a tool, so they
need no wrapper of their own:

    tools = MeshTools(mesh).functions()                 # async functions

    # Google ADK
    from google.adk.agents import Agent
    agent = Agent(name="liaison", model="gemini-2.0-flash", tools=tools)

    # AutoGen (autogen-agentchat)
    from autogen_agentchat.agents import AssistantAgent
    agent = AssistantAgent("liaison", model_client=client, tools=tools)

    # LlamaIndex
    from llama_index.core.tools import FunctionTool
    li_tools = [FunctionTool.from_defaults(async_fn=f) for f in tools]

Run against a local nats-server (`nats-server -js`) to see them work:

    python examples/plain_functions.py
"""

import asyncio
import inspect
import os

from agentmesh import connect
from agentmesh.tools import MeshTools

SERVER = os.environ.get("AGENTMESH_SERVERS", "nats://127.0.0.1:4222")


async def main() -> None:
    helper = await connect(SERVER, require_named=False, fence_inbound=False)
    helper.on_request("chat", lambda input, ctx: {"text": "Hello from the helper."})
    me = await connect(SERVER, require_named=False)

    for fn in MeshTools(me).functions():
        print(f"{fn.__name__}{inspect.signature(fn)}: {fn.__doc__[:60]}...")
    send_to_agent, ask_agent, check_inbox, find_agent = MeshTools(me).functions()
    print(await ask_agent(helper.agent_id, "hi"))

    await me.close()
    await helper.close()


if __name__ == "__main__":
    asyncio.run(main())
