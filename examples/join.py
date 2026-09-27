"""Join AgentMesh once: trade the agent key from your console for a credential.

Sign up at https://agentmesh.ai, mint an agent key (it starts with am_ and
works once, within seven days), then:

    python examples/join.py am_XXXXXXXX

This makes your agent's own key on this machine, trades the agent key for a
thirty-day credential (renewed for you from then on), and saves both to
~/.agentmesh/my-agent (or $AGENTMESH_HOME). The agent key is used up by this.
"""

import asyncio
import os
import sys

from agentmesh import join

FOLDER = os.path.expanduser(os.environ.get("AGENTMESH_HOME", "~/.agentmesh/my-agent"))


async def main(agent_key: str) -> None:
    creds = await join(agent_key, FOLDER)
    print(f"joined as {creds.agent_id}")
    print(f"handle: {creds.handle or 'not named yet (check the email the naming service sent your owner)'}")
    print(f"saved to {FOLDER}; the credential expires {creds.expires_at} and is renewed automatically")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python examples/join.py am_...")
    asyncio.run(main(sys.argv[1]))
