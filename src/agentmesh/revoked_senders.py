"""Refusing a revoked or paused sender (SPEC.md 5.3, 4.12).

SPEC 5.3: "A message signed by a revoked agent key MUST be rejected." An
envelope signature proves which key signed it, not that the key is still its
owner's. When an owner reports a key leaked, the registry marks it revoked and
from then on answers a ``get`` for that key with ``UNAUTHORIZED``,
``details.reason: agent_key_revoked``. A stopped agent (the kill switch, 4.12)
is refused too: its manifest says ``status: paused`` until it is resumed.

:class:`RevokedSenders` asks that question about each sender before its message
is handled, with a short memo. It is fail safe in both directions:

- a check that cannot answer (registry down, slow, no responders) does not
  block anyone, so a known-good contact keeps working through a registry
  outage;
- a key already seen revoked stays refused for the life of the process,
  whatever the registry says or fails to say later, because revocation is
  permanent.

"Not revoked" answers are kept for :attr:`RevokedSenders.OK_MS`, so a
revocation reaches a receiver that already knows the sender within a minute.
Failed lookups are kept for :attr:`RevokedSenders.FAILED_MS` so an outage does
not add a timeout to every message. A pause is lifted, so it is remembered for
``OK_MS`` only, never for the life of the process.

This mirrors the TypeScript SDK's ``internal/revoked-senders.ts``.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

__all__ = ["RevocationAnswer", "RevokedSender", "RevokedSenders"]


@dataclass(frozen=True)
class RevocationAnswer:
    """What one registry lookup said about a key.

    ``kind`` is ``"revoked"``, ``"paused"``, ``"not_revoked"`` or ``"unknown"``
    (the lookup could not answer: treated as "let it through").
    """

    kind: str
    revoked_at: Optional[str] = None
    replaced_by: Optional[str] = None
    since: Optional[str] = None


@dataclass(frozen=True)
class RevokedSender:
    """Why a sender is refused. ``paused`` means the kill switch paused it
    (``since`` is when); otherwise its key is revoked."""

    revoked_at: Optional[str] = None
    replaced_by: Optional[str] = None
    paused: bool = False
    since: Optional[str] = None


Lookup = Callable[[str], Awaitable[RevocationAnswer]]


def _monotonic_ms() -> float:
    return time.monotonic() * 1000


class RevokedSenders:
    """A memo of registry answers about sender keys."""

    OK_MS = 60_000
    FAILED_MS = 15_000
    LOOKUP_TIMEOUT_S = 2.0
    MAX = 5_000

    def __init__(self, lookup: Lookup, now: Callable[[], float] = _monotonic_ms):
        self._lookup = lookup
        self._now = now
        self._revoked: dict[str, RevokedSender] = {}
        self._not_revoked: dict[str, float] = {}
        self._paused: dict[str, tuple[Optional[str], float]] = {}
        self._in_flight: dict[str, asyncio.Future[Optional[RevokedSender]]] = {}

    async def check(self, key: str) -> Optional[RevokedSender]:
        """The refusal for ``key``, or None when it is not known to be revoked or paused."""
        known = self._revoked.get(key)
        if known is not None:
            return known
        pause = self._paused.get(key)
        if pause is not None and pause[1] > self._now():
            return RevokedSender(paused=True, since=pause[0])
        until = self._not_revoked.get(key)
        if until is not None and until > self._now():
            return None
        pending = self._in_flight.get(key)
        if pending is None:
            pending = asyncio.ensure_future(self._ask(key))
            self._in_flight[key] = pending

            def forget(f: asyncio.Future[Optional[RevokedSender]]) -> None:
                if self._in_flight.get(key) is f:
                    del self._in_flight[key]

            pending.add_done_callback(forget)
        # Shielded: one caller giving up must not cancel the lookup the others share.
        return await asyncio.shield(pending)

    def remember(self, key: str, r: RevokedSender) -> None:
        """Record a revocation learned some other way (an answer to a request, a
        refusal seen elsewhere)."""
        self._revoked[key] = r
        self._not_revoked.pop(key, None)

    async def _ask(self, key: str) -> Optional[RevokedSender]:
        try:
            answer = await asyncio.wait_for(self._lookup(key), self.LOOKUP_TIMEOUT_S)
        except Exception:
            answer = RevocationAnswer("unknown")
        if answer.kind == "revoked":
            r = RevokedSender(revoked_at=answer.revoked_at, replaced_by=answer.replaced_by)
            self.remember(key, r)
            return r
        if answer.kind == "paused":
            if len(self._paused) > self.MAX:
                self._paused.clear()
            self._paused[key] = (answer.since, self._now() + self.OK_MS)
            self._not_revoked.pop(key, None)
            return RevokedSender(paused=True, since=answer.since)
        self._paused.pop(key, None)
        if len(self._not_revoked) > self.MAX:
            self._not_revoked.clear()
        ttl = self.FAILED_MS if answer.kind == "unknown" else self.OK_MS
        self._not_revoked[key] = self._now() + ttl
        return None
