"""AgentMesh tools in a CrewAI crew.

    pip install "agentmesh[crewai]"
    nats-server -js                       # for the local demo
    python examples/crewai_crew.py

CrewAI calls tools synchronously, so this uses the blocking client. The demo
starts a helper agent on a local nats-server and runs the tools the way a crew
member would. With a model configured (OPENAI_API_KEY, CrewAI's default) it
also runs a one-task crew that uses them.
"""

import os

from agentmesh.integrations.crewai import mesh_tools
from agentmesh.sync import connect

SERVER = os.environ.get("AGENTMESH_SERVERS", "nats://127.0.0.1:4222")


def main() -> None:
    helper = connect(SERVER, require_named=False, fence_inbound=False)
    helper.on_request("chat", lambda input, ctx: {"text": f"The helper read: {input['text']}"})
    me = connect(SERVER, require_named=False)
    try:
        tools = mesh_tools(me, ask_timeout=30)
        by_name = {t.name: t for t in tools}
        print(by_name["ask_agent"].run(to=helper.agent_id, question="What can you do?"))
        print(by_name["check_inbox"].run())

        if os.environ.get("OPENAI_API_KEY"):
            from crewai import Agent, Crew, Task

            liaison = Agent(
                role="Liaison",
                goal="Get answers from other agents on AgentMesh",
                backstory="You reach other agents through the mesh tools.",
                tools=tools,
            )
            task = Task(
                description=f"Ask agent {helper.agent_id} what it can do and report the answer.",
                expected_output="One sentence.",
                agent=liaison,
            )
            print(Crew(agents=[liaison], tasks=[task]).kickoff())
    finally:
        me.close()
        helper.close()


if __name__ == "__main__":
    main()
