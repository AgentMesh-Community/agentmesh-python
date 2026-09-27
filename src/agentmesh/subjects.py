"""NATS subjects (SPEC.md 18.1). Every id put into a subject must be one token.

A dot in an id does not break a subject, it extends it into a neighbouring
namespace, and ``*`` or ``>`` widen a subscription into everyone else's. So
every builder here checks its ids, the same rule as the TypeScript SDK.
"""

from __future__ import annotations

import re

from .errors import ErrorCode, MeshError

__all__ = ["Subjects", "is_subject_token", "is_publishable_subject"]

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_PRINTABLE = re.compile(r"^[\x21-\x7e]+$")


def is_subject_token(value: object) -> bool:
    return isinstance(value, str) and bool(_TOKEN.match(value))


def is_publishable_subject(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 512:
        return False
    return all(t and _PRINTABLE.match(t) and "*" not in t and ">" not in t for t in value.split("."))


def _token(kind: str, value: str) -> str:
    if not is_subject_token(value):
        raise MeshError(
            ErrorCode.INVALID_ENVELOPE,
            f"{kind} is not a single NATS subject token (SPEC 18.1): {str(value)[:64]!r}",
        )
    return value


class Subjects:
    REGISTRY_REGISTER = "mesh.registry.register"
    REGISTRY_DEREGISTER = "mesh.registry.deregister"
    REGISTRY_DISCOVER = "mesh.registry.discover"
    PRESENCE_GET = "mesh.presence.get"
    FEED_GET = "mesh.feed.get"

    @staticmethod
    def registry_get(agent_id: str) -> str:
        return f"mesh.registry.get.{_token('agent id', agent_id)}"

    @staticmethod
    def agent_inbox(agent_id: str) -> str:
        return f"mesh.agent.{_token('agent id', agent_id)}.inbox"

    @staticmethod
    def agent_outbox(agent_id: str) -> str:
        return f"mesh.agent.{_token('agent id', agent_id)}.outbox"

    @staticmethod
    def task_update(task_id: str) -> str:
        return f"mesh.task.{_token('task id', task_id)}.update"

    @staticmethod
    def task_stream(task_id: str) -> str:
        return f"mesh.task.{_token('task id', task_id)}.stream"

    @staticmethod
    def event(topic: str) -> str:
        """Event subjects are dotted by design, and a subscribe pattern may use
        ``*`` and ``>``; the token rule does not apply to the topic."""
        if not isinstance(topic, str) or not topic or any(c.isspace() for c in topic):
            raise MeshError(ErrorCode.INVALID_ENVELOPE, f"not an event topic: {str(topic)[:64]!r}")
        return f"mesh.event.{topic}"

    @staticmethod
    def heartbeat(node_id: str) -> str:
        return f"mesh.heartbeat.{_token('node id', node_id)}"

    @staticmethod
    def inbox_stream(agent_id: str) -> str:
        """The JetStream mailbox that holds mail while the agent is away (SPEC 16.4)."""
        return f"MESH_INBOX_{_token('agent id', agent_id)}"

    @staticmethod
    def inbox_durable(agent_id: str) -> str:
        return f"inbox_{_token('agent id', agent_id)}"
