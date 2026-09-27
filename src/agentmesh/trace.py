"""W3C trace context in every envelope (SPEC.md 13.1).

Every envelope carries ``trace``: a trace id, its own span id and its parent's.
An envelope built while a request handler is running becomes a child span of
the request that started it, so a chain of agents calling agents stays one
trace. In Python that is a ``contextvars.ContextVar``, which asyncio carries
into every task a handler starts.

``to_traceparent`` and ``from_traceparent`` convert to and from the HTTP
``traceparent`` header, for joining a trace that began outside the mesh (an
incoming web request) or handing one to an HTTP call.
"""

from __future__ import annotations

import contextvars
import re
import secrets
from contextlib import contextmanager
from typing import Any, Iterator, Optional

__all__ = [
    "new_trace_context",
    "child_span",
    "is_valid_trace_context",
    "to_traceparent",
    "from_traceparent",
    "current_trace",
    "use_trace",
]

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_MAX_TRACESTATE = 512

_ambient: contextvars.ContextVar[Optional[dict[str, Any]]] = contextvars.ContextVar("agentmesh_trace", default=None)


def _rand_hex(nbytes: int) -> str:
    while True:
        s = secrets.token_hex(nbytes)
        if s.strip("0"):
            return s  # W3C forbids the all-zero id


def new_trace_context() -> dict[str, Any]:
    """A new root: fresh trace id, fresh span id, no parent."""
    return {"trace_id": _rand_hex(16), "span_id": _rand_hex(8), "parent_span_id": None}


def is_valid_trace_context(t: Any) -> bool:
    if not isinstance(t, dict):
        return False
    tid, sid = t.get("trace_id"), t.get("span_id")
    if not isinstance(tid, str) or not _TRACE_ID.match(tid) or not tid.strip("0"):
        return False
    if not isinstance(sid, str) or not _SPAN_ID.match(sid) or not sid.strip("0"):
        return False
    parent = t.get("parent_span_id")
    if parent is not None and (not isinstance(parent, str) or not _SPAN_ID.match(parent)):
        return False
    if "tracestate" in t and (not isinstance(t["tracestate"], str) or len(t["tracestate"]) > _MAX_TRACESTATE):
        return False
    return True


def child_span(parent: Any) -> dict[str, Any]:
    """A new span in the parent's trace. An invalid parent starts a new root."""
    if not is_valid_trace_context(parent):
        return new_trace_context()
    child: dict[str, Any] = {
        "trace_id": parent["trace_id"],
        "span_id": _rand_hex(8),
        "parent_span_id": parent["span_id"],
    }
    if "tracestate" in parent:
        child["tracestate"] = parent["tracestate"]
    return child


def to_traceparent(t: dict[str, Any]) -> str:
    """The version-00 W3C ``traceparent`` header value for a context."""
    return f"00-{t['trace_id']}-{t['span_id']}-01"


def from_traceparent(traceparent: str, tracestate: str | None = None) -> dict[str, Any] | None:
    """Join a trace from an HTTP ``traceparent`` header. None if it is malformed.

    The result is a child of the header's span: a new span id whose parent is
    the span that sent the header.
    """
    m = _TRACEPARENT.match(traceparent.strip())
    if not m:
        return None
    ctx: dict[str, Any] = {"trace_id": m.group(1), "span_id": _rand_hex(8), "parent_span_id": m.group(2)}
    if tracestate is not None:
        ctx["tracestate"] = tracestate
    return ctx


def current_trace() -> dict[str, Any] | None:
    """The trace of the inbound message being handled right now, if any."""
    return _ambient.get()


@contextmanager
def use_trace(trace: dict[str, Any] | None) -> Iterator[None]:
    """Make envelopes built inside the block children of ``trace``."""
    token = _ambient.set(trace)
    try:
        yield
    finally:
        _ambient.reset(token)
