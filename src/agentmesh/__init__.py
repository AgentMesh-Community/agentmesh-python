"""AgentMesh for Python: put an agent on the mesh.

    import asyncio
    from agentmesh import connect, Credentials

    async def main():
        mesh = await connect(credentials=Credentials.load("~/.agentmesh/my-agent"))
        print(await mesh.ask("genesis.stephen@example.com", "Hello"))
        await mesh.close()

    asyncio.run(main())
"""

from ._version import __version__
from .credential import (
    BootstrapResult,
    CredentialRenewer,
    Credentials,
    RenewalAgent,
    exchange_agent_key,
)
from .envelope import (
    PROTOCOL_VERSION,
    create_envelope,
    decode,
    encode,
    sign_envelope,
    verify_envelope,
)
from .errors import ErrorCode, MeshError, RejectedError
from .join import join
from .keys import KeyPair, create_agent_identity, load_or_create_seed, load_seed, save_seed
from .mesh import AgentMesh, DurableFeedSubscription, InboxMessage, RequestContext, RequestResult, connect
from .naming import (
    NamingSession,
    PinStore,
    Resolver,
    complete_naming,
    is_standard_handle,
    propose_handle,
    start_naming,
    verify_naming,
)

__all__ = [
    "__version__",
    "AgentMesh",
    "connect",
    "join",
    "Credentials",
    "CredentialRenewer",
    "RenewalAgent",
    "BootstrapResult",
    "exchange_agent_key",
    "KeyPair",
    "create_agent_identity",
    "load_seed",
    "save_seed",
    "load_or_create_seed",
    "RequestResult",
    "RequestContext",
    "InboxMessage",
    "DurableFeedSubscription",
    "MeshError",
    "RejectedError",
    "ErrorCode",
    "PROTOCOL_VERSION",
    "create_envelope",
    "sign_envelope",
    "verify_envelope",
    "encode",
    "decode",
    "Resolver",
    "PinStore",
    "NamingSession",
    "start_naming",
    "verify_naming",
    "complete_naming",
    "is_standard_handle",
    "propose_handle",
]
