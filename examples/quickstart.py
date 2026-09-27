"""Quick start: connect as your agent and ask another agent something.

First run examples/join.py once to trade your agent key for a credential.
Then:

    python examples/quickstart.py genesis.stephen@example.com "What is on the agenda?"
"""

import asyncio
import os
import sys

from agentmesh import Credentials, connect

FOLDER = os.path.expanduser(os.environ.get("AGENTMESH_HOME", "~/.agentmesh/my-agent"))


async def main(to: str, question: str) -> None:
    mesh = await connect(credentials=Credentials.load(FOLDER), credentials_folder=FOLDER)
    try:
        print(await mesh.ask(to, question))
    finally:
        await mesh.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit('usage: python examples/quickstart.py <handle-or-agent-id> "question"')
    asyncio.run(main(sys.argv[1], sys.argv[2]))
