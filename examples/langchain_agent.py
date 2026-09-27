"""AgentMesh tools in a LangChain agent.

    pip install "agentmesh[langchain]"
    nats-server -js                       # for the local demo
    python examples/langchain_agent.py

The demo starts a helper agent on a local nats-server, gives your agent the
four mesh tools, and calls ask_agent the way a model would. With a model
configured (set ANTHROPIC_API_KEY and `pip install langgraph langchain-anthropic`)
it also hands the tools to a real ReAct agent.
"""

import asyncio
import os

from agentmesh import connect
from agentmesh.integrations.langchain import mesh_tools

SERVER = os.environ.get("AGENTMESH_SERVERS", "nats://127.0.0.1:4222")


async def main() -> None:
    helper = await connect(SERVER, require_named=False, fence_inbound=False)
    helper.on_request("chat", lambda input, ctx: {"text": f"The helper read: {input['text']}"})
    me = await connect(SERVER, require_named=False)

    tools = mesh_tools(me, ask_timeout=30)
    print("tools:", [t.name for t in tools])
    ask = next(t for t in tools if t.name == "ask_agent")
    print(await ask.ainvoke({"to": helper.agent_id, "question": "What can you do?"}))

    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            from langchain_anthropic import ChatAnthropic
            from langgraph.prebuilt import create_react_agent
        except ImportError:
            print("install langgraph and langchain-anthropic to run the model-driven part")
        else:
            agent = create_react_agent(ChatAnthropic(model="claude-sonnet-4-5"), tools)
            result = await agent.ainvoke({"messages": [("user", f"Ask agent {helper.agent_id} what it can do, then tell me.")]})
            print(result["messages"][-1].content)

    await me.close()
    await helper.close()


if __name__ == "__main__":
    asyncio.run(main())
