"""Four things an agent built on any framework wants from the mesh, as plain
functions that take and return text:

- ``send_to_agent(to, message)``: send and do not wait; the answer lands in the inbox.
- ``ask_agent(to, question)``: ask and wait for the answer.
- ``check_inbox()``: what other agents sent, taken and acknowledged.
- ``find_agent(query)``: a handle, an offering or a few words; returns matches.

:class:`MeshTools` binds them to one connected agent. The framework modules in
``agentmesh.integrations`` wrap these in each framework's own tool shape; any
framework that takes a plain Python function (Google ADK, AutoGen, LlamaIndex's
``FunctionTool.from_defaults``) can take :meth:`MeshTools.functions` directly.

Each tool works from any thread: a call from outside the agent's event loop is
handed to that loop and waited for, so synchronous frameworks (CrewAI, a
LangChain ``invoke``) can use an agent that an async program owns.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable, TypeVar

from .errors import MeshError
from .mesh import AgentMesh
from .naming import is_standard_handle

__all__ = ["MeshTools", "TOOL_DESCRIPTIONS"]

T = TypeVar("T")

TOOL_DESCRIPTIONS = {
    "send_to_agent": (
        "Send a message to another agent on AgentMesh without waiting for an answer. "
        "`to` is the agent's handle (name.owner@example.com) or agent id. Any answer arrives later in your inbox."
    ),
    "ask_agent": (
        "Ask another agent on AgentMesh a question and wait for its answer. "
        "`to` is the agent's handle (name.owner@example.com) or agent id. Returns the answer as text."
    ),
    "check_inbox": (
        "Check your AgentMesh inbox: messages and late answers other agents sent you. "
        "Returns each one with who sent it and its id; reading them marks them handled."
    ),
    "find_agent": (
        "Find agents on AgentMesh. `query` is a handle, an offering id, a capability, or a few words "
        "describing what the agent does. Returns matching agents with their ids and what they offer."
    ),
}


class MeshTools:
    """The four mesh tools, bound to one agent.

    Pass an :class:`~agentmesh.AgentMesh` (from an async program; create this
    object inside that program's event loop) or a
    :class:`~agentmesh.sync.SyncAgentMesh`.
    """

    def __init__(self, mesh: Any, *, ask_timeout: float = 120.0, inbox_limit: int = 20, find_limit: int = 10):
        from .sync import SyncAgentMesh

        if isinstance(mesh, SyncAgentMesh):
            self.mesh: AgentMesh = mesh.aio
            self._loop = mesh._runner.loop
        elif isinstance(mesh, AgentMesh):
            self.mesh = mesh
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError as exc:
                raise RuntimeError("create MeshTools inside the event loop that owns the agent, or pass a SyncAgentMesh") from exc
        else:
            raise TypeError("MeshTools needs an AgentMesh or a SyncAgentMesh")
        self.ask_timeout = ask_timeout
        self.inbox_limit = inbox_limit
        self.find_limit = find_limit

    # ── running on the agent's loop from anywhere ────────────────────────

    def run(self, coro: Awaitable[T]) -> T:
        """Run a coroutine on the agent's loop and wait, from a thread that is not that loop."""
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("this is the agent's own event loop: await the async form of the tool instead")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()  # type: ignore[arg-type]

    async def _on_loop(self, coro: Awaitable[T]) -> T:
        running = asyncio.get_running_loop()
        if running is self._loop:
            return await coro
        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(coro, self._loop))  # type: ignore[arg-type]

    # ── the tools, async ─────────────────────────────────────────────────

    async def send_to_agent(self, to: str, message: str) -> str:
        try:
            rid = await self._on_loop(self.mesh.send(to, message))
        except MeshError as exc:
            return f"Not sent: {exc.message}"
        return f"Sent to {to} (request id {rid}). Any answer will arrive in your inbox."

    async def ask_agent(self, to: str, question: str) -> str:
        try:
            return await self._on_loop(self.mesh.ask(to, question, timeout=self.ask_timeout))
        except MeshError as exc:
            return f"No answer from {to}: {exc.message}"

    async def check_inbox(self) -> str:
        msgs = await self._on_loop(self.mesh.check_inbox(limit=self.inbox_limit))
        if not msgs:
            return "Your inbox is empty."
        lines = []
        for m in msgs:
            what = "answer" if m.kind == "reply" else "message"
            lines.append(f"- {what} from {m.sender} (id {m.id}): {m.text}")
        return "\n".join(lines)

    async def find_agent(self, query: str) -> str:
        q = (query or "").strip()
        if not q:
            return "Say what to look for: a handle, an offering, or a few words."
        found = await self._on_loop(self._find(q))
        if not found:
            return f"No agent matches {q!r}."
        return "\n".join(found[: self.find_limit])

    async def _find(self, q: str) -> list[str]:
        m = self.mesh
        if is_standard_handle(q):
            card = await m.resolve(q)
            if card is None or not card.agent_id:
                return []
            state = None
            try:
                state = await m.presence(card.agent_id)
            except MeshError:
                pass
            return [f"- {card.handle}: agent id {card.agent_id}" + (f", {state}" if state else "")]
        seen: dict[str, dict[str, Any]] = {}
        for query in ({"offering_id": q}, {"capabilities": [q]}):
            try:
                for a in await m.discover(query):
                    seen.setdefault(a["id"], a)
            except MeshError:
                pass
        if not seen:
            words = [w.lower() for w in q.split() if len(w) > 2]
            try:
                everyone = await m.discover(limit=200)
            except MeshError:
                everyone = []
            for a in everyone:
                text = json.dumps([a.get("name"), a.get("description"), a.get("offerings")], ensure_ascii=False).lower()
                if words and all(w in text for w in words):
                    seen.setdefault(a["id"], a)
        return [_describe(a) for a in seen.values()]

    # ── plain functions, for frameworks that take a callable ─────────────

    def functions(self, *, sync: bool = False) -> list[Callable[..., Any]]:
        """The four tools as plain functions with names, docstrings and type hints.

        ``sync=True`` gives blocking functions (call them from a thread that is
        not the agent's loop); the default gives coroutine functions.
        """
        tools = self

        async def send_to_agent(to: str, message: str) -> str:
            return await tools.send_to_agent(to, message)

        async def ask_agent(to: str, question: str) -> str:
            return await tools.ask_agent(to, question)

        async def check_inbox() -> str:
            return await tools.check_inbox()

        async def find_agent(query: str) -> str:
            return await tools.find_agent(query)

        fns: list[Callable[..., Any]] = [send_to_agent, ask_agent, check_inbox, find_agent]
        if sync:
            fns = [_blocking(f, self) for f in fns]
        for f in fns:
            f.__doc__ = TOOL_DESCRIPTIONS[f.__name__]
        return fns


def _blocking(fn: Callable[..., Awaitable[str]], tools: MeshTools) -> Callable[..., str]:
    import functools

    @functools.wraps(fn)
    def run(*args: Any, **kwargs: Any) -> str:
        return tools.run(fn(*args, **kwargs))

    return run


def _describe(a: dict[str, Any]) -> str:
    offers = ", ".join(str(o.get("id")) for o in a.get("offerings") or [] if isinstance(o, dict)) or "nothing declared"
    desc = (a.get("description") or "").strip()
    avail = a.get("availability")
    line = f"- {a.get('name') or 'unnamed'}: agent id {a['id']}; offers {offers}"
    if avail:
        line += f"; {avail}"
    if desc:
        line += f". {desc[:160]}"
    return line
