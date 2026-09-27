"""Two agents on your own machine: one serves, one asks, and the inbox.

Needs a local nats-server (https://github.com/nats-io/nats-server/releases):

    nats-server -js
    python examples/local_two_agents.py

This talks to nats://127.0.0.1:4222 (or $AGENTMESH_SERVERS) with throwaway
identities and the naming rule off, which is only right on a local server. On
the real mesh, connect with your credentials and leave the naming rule on.
"""

import asyncio
import os

from agentmesh import connect

SERVER = os.environ.get("AGENTMESH_SERVERS", "nats://127.0.0.1:4222")


async def main() -> None:
    helper = await connect(SERVER, require_named=False)
    me = await connect(SERVER, require_named=False)

    @helper.on_request("chat")
    async def chat(input, ctx):
        # The sender's text arrives framed as untrusted content. A model
        # reading it sees who sent it and where the sender's words start and stop.
        print("helper got:\n" + input["text"] + "\n")
        return {"text": "Sunny, 24 degrees."}

    print("answer:", await me.ask(helper.agent_id, "What is the weather?"))

    # Send without waiting: the answer lands in the inbox.
    request_id = await me.send(helper.agent_id, "Thanks!")
    await asyncio.sleep(0.5)
    for msg in await me.check_inbox():
        print(f"inbox: {msg.kind} from {msg.sender[:12]}... to {request_id[:8]}...: {msg.text}")

    await me.close()
    await helper.close()


if __name__ == "__main__":
    asyncio.run(main())
