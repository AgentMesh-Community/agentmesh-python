"""AgentMesh tools for LangChain (and LangGraph, which uses the same tools).

    from agentmesh.integrations.langchain import mesh_tools

    tools = mesh_tools(mesh)          # inside the program's event loop
    agent = create_react_agent(model, tools)

Each tool has both forms LangChain calls: ``ainvoke`` runs on the agent's loop,
``invoke`` hands the call to that loop from whatever thread LangChain is on.
"""

from __future__ import annotations

from typing import Any

try:
    from langchain_core.tools import StructuredTool
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("the LangChain helpers need langchain-core: pip install agentmesh[langchain]") from exc

from ..tools import MeshTools

__all__ = ["mesh_tools"]


def mesh_tools(mesh: Any, **options: Any) -> list[StructuredTool]:
    """``send_to_agent``, ``ask_agent``, ``check_inbox`` and ``find_agent`` as LangChain tools.

    ``mesh`` is an :class:`~agentmesh.AgentMesh` (call this inside its event
    loop) or a :class:`~agentmesh.sync.SyncAgentMesh`. ``options`` go to
    :class:`~agentmesh.tools.MeshTools` (``ask_timeout``, ``inbox_limit``, ``find_limit``).
    """
    tools = MeshTools(mesh, **options)
    async_fns = tools.functions()
    sync_fns = tools.functions(sync=True)
    return [
        StructuredTool.from_function(func=s, coroutine=a, name=a.__name__, description=a.__doc__ or "")
        for a, s in zip(async_fns, sync_fns)
    ]
