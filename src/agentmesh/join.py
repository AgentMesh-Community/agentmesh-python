"""Joining a mesh the first time: make an identity, trade the agent key, save.

    import asyncio
    from agentmesh import join

    creds = asyncio.run(join("am_...", "~/.agentmesh/my-agent"))

After that, every start is ``connect(credentials=Credentials.load(folder),
credentials_folder=folder)``, and the saved credential is renewed in place.
"""

from __future__ import annotations

from pathlib import Path

from .credential import Credentials, exchange_agent_key
from .keys import KeyPair, load_or_create_seed

__all__ = ["join", "DEFAULT_API_BASE"]

DEFAULT_API_BASE = "https://api.agentmesh.ai"


async def join(agent_key: str, folder: str | Path, *, api_base: str = DEFAULT_API_BASE) -> Credentials:
    """Trade a console-minted agent key for a durable credential, and save it.

    The agent's own key is made here (or reused, when ``folder`` already holds
    one) and never leaves this machine. The agent key is single use.
    """
    d = Path(folder).expanduser()
    seed = load_or_create_seed(d / "agent.seed")
    result = await exchange_agent_key(api_base, agent_key, KeyPair.from_seed(seed).public_key)
    creds = Credentials.from_bootstrap(seed, result, api_base)
    creds.save(d)
    return creds
