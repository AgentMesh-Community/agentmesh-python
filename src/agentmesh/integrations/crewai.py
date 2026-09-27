"""AgentMesh tools for CrewAI.

    from agentmesh.sync import connect
    from agentmesh.integrations.crewai import mesh_tools

    mesh = connect(credentials=Credentials.load(folder), credentials_folder=folder)
    researcher = Agent(role="Researcher", goal="...", backstory="...", tools=mesh_tools(mesh))

CrewAI calls tools synchronously, so hand it a :class:`~agentmesh.sync.SyncAgentMesh`
(or an async agent together with the loop it runs on, via ``MeshTools``).
"""

from __future__ import annotations

from typing import Any, Type

try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("the CrewAI helpers need crewai: pip install agentmesh[crewai]") from exc

from ..tools import TOOL_DESCRIPTIONS, MeshTools

__all__ = ["mesh_tools"]


class _SendArgs(BaseModel):
    to: str = Field(description="The agent's handle (name.owner@example.com) or agent id")
    message: str = Field(description="What to send")


class _AskArgs(BaseModel):
    to: str = Field(description="The agent's handle (name.owner@example.com) or agent id")
    question: str = Field(description="What to ask")


class _NoArgs(BaseModel):
    pass


class _FindArgs(BaseModel):
    query: str = Field(description="A handle, an offering id, a capability, or a few words")


def mesh_tools(mesh: Any, **options: Any) -> list[BaseTool]:
    """``send_to_agent``, ``ask_agent``, ``check_inbox`` and ``find_agent`` as CrewAI tools."""
    tools = MeshTools(mesh, **options)

    class SendToAgent(BaseTool):
        name: str = "send_to_agent"
        description: str = TOOL_DESCRIPTIONS["send_to_agent"]
        args_schema: Type[BaseModel] = _SendArgs

        def _run(self, to: str, message: str) -> str:
            return tools.run(tools.send_to_agent(to, message))

    class AskAgent(BaseTool):
        name: str = "ask_agent"
        description: str = TOOL_DESCRIPTIONS["ask_agent"]
        args_schema: Type[BaseModel] = _AskArgs

        def _run(self, to: str, question: str) -> str:
            return tools.run(tools.ask_agent(to, question))

    class CheckInbox(BaseTool):
        name: str = "check_inbox"
        description: str = TOOL_DESCRIPTIONS["check_inbox"]
        args_schema: Type[BaseModel] = _NoArgs

        def _run(self) -> str:
            return tools.run(tools.check_inbox())

    class FindAgent(BaseTool):
        name: str = "find_agent"
        description: str = TOOL_DESCRIPTIONS["find_agent"]
        args_schema: Type[BaseModel] = _FindArgs

        def _run(self, query: str) -> str:
            return tools.run(tools.find_agent(query))

    return [SendToAgent(), AskAgent(), CheckInbox(), FindAgent()]
