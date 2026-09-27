"""A blocking wrapper, for scripts and other code that is not async.

    from agentmesh.sync import connect

    mesh = connect(credentials=Credentials.load("~/.agentmesh/my-agent"))
    print(mesh.ask("genesis.stephen@example.com", "What is on the agenda?"))
    mesh.close()

The async client runs on its own event loop in a background thread; each method
here submits one call to it and waits. Handlers registered with
:meth:`SyncAgentMesh.on_request` run on that loop's worker threads, so they may
block.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable, Sequence

from .mesh import AgentMesh, InboxMessage, RequestResult

__all__ = ["SyncAgentMesh", "connect"]


class _LoopThread:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="agentmesh-loop", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def call(self, coro: Any, timeout: float | None = None) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=5)


class SyncAgentMesh:
    """The same agent as :class:`AgentMesh`, one blocking call at a time."""

    def __init__(self, mesh: AgentMesh, runner: _LoopThread):
        self._mesh = mesh
        self._runner = runner

    @property
    def agent_id(self) -> str:
        return self._mesh.agent_id

    @property
    def aio(self) -> AgentMesh:
        """The async client underneath, for anything not wrapped here."""
        return self._mesh

    def _call(self, coro: Any) -> Any:
        return self._runner.call(coro)

    def register(self, name: str, **kwargs: Any) -> dict[str, Any]:
        return self._call(self._mesh.register(name, **kwargs))

    def deregister(self) -> None:
        self._call(self._mesh.deregister())

    def discover(self, query: dict[str, Any] | None = None, **filters: Any) -> list[dict[str, Any]]:
        return self._call(self._mesh.discover(query, **filters))

    def request(self, to: str, offering: str, input: Any = None, **kwargs: Any) -> RequestResult:
        return self._call(self._mesh.request(to, offering, input, **kwargs))

    def ask(self, to: str, text: str, **kwargs: Any) -> str:
        return self._call(self._mesh.ask(to, text, **kwargs))

    def send(self, to: str, text: str | None = None, **kwargs: Any) -> str:
        return self._call(self._mesh.send(to, text, **kwargs))

    def emit(self, topic: str, data: Any) -> None:
        self._call(self._mesh.emit(topic, data))

    def subscribe(self, pattern: str, handler: Callable[[dict[str, Any], dict[str, Any]], Any]) -> Any:
        return self._call(self._mesh.subscribe(pattern, handler))

    def on_request(self, offering: str, handler: Callable[..., Any] | None = None, **kwargs: Any) -> Any:
        return self._mesh.on_request(offering, handler, **kwargs)

    def inbox(self) -> list[InboxMessage]:
        return self._mesh.inbox()

    def receive(self, timeout: float | None = None) -> InboxMessage | None:
        return self._call(self._mesh.receive(timeout))

    def check_inbox(self, **kwargs: Any) -> list[InboxMessage]:
        return self._call(self._mesh.check_inbox(**kwargs))

    def reply(self, message: InboxMessage, output: Any) -> None:
        self._call(message.reply(output))

    def ack(self, message: InboxMessage) -> None:
        self._call(message.ack())

    def await_task(self, task_id: str, timeout: float = 300.0) -> dict[str, Any]:
        return self._call(self._mesh.await_task(task_id, timeout))

    def presence(self, agent: str) -> str | None:
        return self._call(self._mesh.presence(agent))

    def resolve(self, handle: str) -> Any:
        return self._call(self._mesh.resolve(handle))

    def whois(self, agent_id: str) -> Any:
        return self._call(self._mesh.whois(agent_id))

    def naming_status(self) -> Any:
        return self._mesh.naming_status()

    def close(self) -> None:
        try:
            self._call(self._mesh.close())
        finally:
            self._runner.stop()

    def __enter__(self) -> "SyncAgentMesh":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def connect(servers: str | Sequence[str] | None = None, **kwargs: Any) -> SyncAgentMesh:
    """Blocking :func:`agentmesh.connect`. Same arguments."""
    runner = _LoopThread()
    try:
        mesh = runner.call(AgentMesh.connect(servers, **kwargs))
    except BaseException:
        runner.stop()
        raise
    return SyncAgentMesh(mesh, runner)
