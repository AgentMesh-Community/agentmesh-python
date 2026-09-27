"""Names: the naming rule, resolving handles, and naming an agent.

**The rule** (decided 2026-09-25): every agent's handle follows one global
standard, the agent's name, a dot and its owner's email
(``genesis.stephen@example.com``), registered with the naming service. An agent
without one sends nothing. :class:`NamingGate` enforces it on the sending side;
:func:`agentmesh.connect` turns it on by default and ``require_named=False``
turns it off, for tests only.

**Resolving** (SPEC-NAMING 5): a handle resolves to a signed card at the
registrar; an agent id reverse-resolves to the card bound to it.
:class:`Resolver` checks what the spec says a consumer MUST check: the card is
signed, the signing key is one the registrar publishes at ``/api/registrar-key``
(fetched separately, never trusted from the same response), the signature
verifies over the canonical JSON of the card, and the card has not expired. It
then **pins** ``handle -> agent key`` and each registrar's signing key on first
sight, and refuses (keeping the old pin) when either changes.

**Naming an agent** (SPEC-NAMING 3 and 4.1): :func:`start_naming` emails the
owner a code, :func:`verify_naming` trades it for a session,
:func:`complete_naming` claims the handle and pairs it with the agent's key.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote, urlparse

import httpx

from .canonical import canonical_bytes
from .envelope import parse_iso
from .errors import ErrorCode, MeshError
from .keys import KeyPair, is_agent_id, verify_signature

__all__ = [
    "DEFAULT_REGISTRAR",
    "NAMING_STANDARD_WORDS",
    "NAMED_TTL_MS",
    "UNNAMED_TTL_MS",
    "is_standard_handle",
    "propose_handle",
    "not_named_error",
    "NameCheck",
    "NamingStatus",
    "NamingGate",
    "registrar_name_lookup",
    "Resolver",
    "PinStore",
    "ResolvedCard",
    "NamingSession",
    "start_naming",
    "verify_naming",
    "complete_naming",
]

DEFAULT_REGISTRAR = "https://naming.agentmesh.ai"

#: The platform's words, so every door says the same (conformance/naming-gate.json).
NAMING_STANDARD_WORDS = (
    "AgentMesh uses one global standard for agent names: the agent's name, a dot, and its owner's email. "
    "That way no two agents anywhere have the same name. This agent does not have one yet, so nothing was sent."
)

#: How long an answer is kept: a handle does not change while a process runs;
#: "not named" is kept briefly so an agent named a moment ago sends at once.
NAMED_TTL_MS = 30 * 60_000
UNNAMED_TTL_MS = 5_000

_STANDARD = re.compile(r"^[^\s@.]+\.[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$")
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def is_standard_handle(h: object) -> bool:
    """A name with no dot, a dot, then the owner's email."""
    return isinstance(h, str) and bool(_STANDARD.match(h))


@dataclass(frozen=True)
class ProposedHandle:
    name: Optional[str]
    email: Optional[str]
    handle: str


def _js_trim(s: str) -> str:
    # JavaScript's String.prototype.trim strips the same whitespace class that
    # Python's str.strip() does for every character a name will realistically
    # carry; the conformance proposals cover the cases that matter.
    return s.strip()


def propose_handle(name: str | None = None, email: str | None = None) -> ProposedHandle:
    """The handle proposed from the name the agent already has.

    Lower case, anything the naming service would refuse turned into a dash,
    and the owner's email after the dot when it is known.
    """
    n = _js_trim(str(name if name is not None else "")).lower()
    n = re.sub(r"[^a-z0-9_-]+", "-", n)
    n = re.sub(r"-{2,}", "-", n)
    n = re.sub(r"^-+|-+$", "", n)[:64]
    e = None
    if isinstance(email, str) and _EMAIL.match(_js_trim(email)):
        e = _js_trim(email).lower()
    return ProposedHandle(name=n or None, email=e, handle=f"{n or _NAME_PLACEHOLDER}.{e or _EMAIL_PLACEHOLDER}")


_NAME_PLACEHOLDER = "<agent name>"
_EMAIL_PLACEHOLDER = "<owner's email>"


def not_named_error(name: str | None = None, email: str | None = None) -> MeshError:
    """The refusal an unnamed agent gets: the owner's words, then the proposal."""
    p = propose_handle(name, email)
    if p.email:
        confirm = f"The proposed name is {p.handle}, and {p.email} confirms it with a code we email."
    else:
        confirm = f"The proposed name is {p.handle}, and the owner confirms it with a code we email."
    named = f' and the name "{p.name}"' if p.name else ""
    how = (
        f"To name it, call start_naming with the owner's email and then complete_naming with the code{named}, "
        "or run agentmesh join."
    )
    return MeshError(
        ErrorCode.NOT_NAMED,
        f"{NAMING_STANDARD_WORDS} {confirm} {how}",
        retryable=False,
        details={
            "proposed_handle": p.handle,
            "naming": {"sdk": ["start_naming", "verify_naming", "complete_naming"], "cli": "agentmesh join"},
        },
    )


# ── the gate ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NameCheck:
    """One look at the naming service: ``named``, ``unnamed`` or ``unreachable``."""

    status: str
    handle: Optional[str] = None


NameLookup = Callable[[str], Awaitable[NameCheck]]


@dataclass(frozen=True)
class NamingStatus:
    named: bool
    handle: Optional[str]
    checked_at: float
    #: True when the naming service did not answer: the agent may send (an
    #: outage is not evidence of no name) and ``handle`` is the last verified one.
    unchecked: bool = False


class NamingGate:
    """The one check every send runs, with its cache (conformance/naming-gate.json)."""

    def __init__(
        self,
        agent_id: str,
        lookup: NameLookup,
        *,
        name: str | None = None,
        owner_email: str | None = None,
        last_verified: str | None = None,
        now: Callable[[], float] | None = None,
    ):
        self.agent_id = agent_id
        self._lookup = lookup
        self._name = name
        self._email = owner_email
        self._last_verified = last_verified if is_standard_handle(last_verified) else None
        self._now = now or (lambda: time.time() * 1000)
        self._status: NamingStatus | None = None
        self._in_flight: asyncio.Future[NamingStatus] | None = None

    def current(self) -> NamingStatus | None:
        return self._status

    def _fresh(self, s: NamingStatus) -> bool:
        ttl = NAMED_TTL_MS if s.named and not s.unchecked else UNNAMED_TTL_MS
        return self._now() - s.checked_at < ttl

    async def check(self) -> NamingStatus:
        s = self._status
        if s is not None and self._fresh(s):
            return s
        if self._in_flight is not None:
            return await asyncio.shield(self._in_flight)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[NamingStatus] = loop.create_future()
        self._in_flight = fut
        try:
            try:
                c = await self._lookup(self.agent_id)
            except Exception:
                c = NameCheck("unreachable")
            at = self._now()
            if c.status == "named" and is_standard_handle(c.handle):
                self._last_verified = c.handle
                nxt = NamingStatus(named=True, handle=c.handle, checked_at=at)
            elif c.status == "unreachable":
                nxt = NamingStatus(named=True, handle=self._last_verified, checked_at=at, unchecked=True)
            else:
                nxt = NamingStatus(named=False, handle=c.handle, checked_at=at)
            self._status = nxt
            fut.set_result(nxt)
            return nxt
        except BaseException as exc:
            if not fut.done():
                fut.set_exception(exc)
            raise
        finally:
            self._in_flight = None

    def forget(self) -> None:
        self._status = None

    def refusal(self) -> MeshError:
        return not_named_error(self._name, self._email)

    async def require(self) -> None:
        """Raise NOT_NAMED unless this agent may send."""
        s = await self.check()
        if not s.named:
            raise self.refusal()

    def require_cached(self) -> None:
        """The same, for a send that cannot wait (emit): judged on the last
        answer, with a fresh one asked for in the background when stale."""
        s = self._status
        if s is None or not self._fresh(s):
            try:
                asyncio.get_running_loop().create_task(self.check())
            except RuntimeError:
                pass
        if s is not None and not s.named:
            raise self.refusal()


def registrar_name_lookup(registrar: str = DEFAULT_REGISTRAR, *, client: httpx.AsyncClient | None = None) -> NameLookup:
    """The naming service's reverse lookup, verified as SPEC-NAMING 5.3 says.

    A 404 is "not named"; anything that is not a verified card bound to the key
    asked about is "unreachable", never "named".
    """
    base = registrar.rstrip("/")
    keys: dict[str, Any] = {}

    async def signing_keys(http: httpx.AsyncClient) -> list[str]:
        if keys and time.time() - keys["at"] < 3600:
            return keys["list"]
        r = await http.get(f"{base}/api/registrar-key", timeout=5.0)
        doc = r.json() if r.is_success else None
        found = _published_keys(doc)
        if found:
            keys.update(at=time.time(), list=found)
        return found

    async def lookup(agent_id: str) -> NameCheck:
        http = client or httpx.AsyncClient()
        try:
            r = await http.get(f"{base}/api/resolve?agent_id={quote(agent_id)}", timeout=8.0)
            if r.status_code == 404:
                return NameCheck("unnamed", None)
            if not r.is_success:
                return NameCheck("unreachable")
            data = r.json()
            card = data.get("card") if isinstance(data, dict) else None
            if not card or not data.get("registrar_sig") or not data.get("registrar_key"):
                return NameCheck("unreachable")
            if str(data["registrar_key"]) not in await signing_keys(http):
                return NameCheck("unreachable")
            if not verify_signature(str(data["registrar_key"]), canonical_bytes(card), base64.b64decode(str(data["registrar_sig"]))):
                return NameCheck("unreachable")
            if not _bound_to(card, agent_id):
                return NameCheck("unreachable")
            handle = card.get("handle") if isinstance(card.get("handle"), str) else None
            return NameCheck("named", handle) if is_standard_handle(handle) else NameCheck("unnamed", handle)
        except Exception:
            return NameCheck("unreachable")
        finally:
            if client is None:
                await http.aclose()

    return lookup


def _published_keys(doc: Any) -> list[str]:
    if not isinstance(doc, dict):
        return []
    out: list[str] = []
    if isinstance(doc.get("keys"), list):
        out += [k for k in doc["keys"] if isinstance(k, str) and k]
    if isinstance(doc.get("key_set"), list):
        out += [k.get("key") for k in doc["key_set"] if isinstance(k, dict) and isinstance(k.get("key"), str) and k.get("key")]
    return out


def _bound_to(card: dict[str, Any], agent_id: str) -> bool:
    return any(
        isinstance(e, dict) and e.get("protocol") == "agentmesh" and e.get("agent_id") == agent_id
        for e in (card.get("endpoints") or [])
    )


def _card_agent_id(card: dict[str, Any]) -> str | None:
    for e in card.get("endpoints") or []:
        if isinstance(e, dict) and e.get("protocol") == "agentmesh" and isinstance(e.get("agent_id"), str):
            return e["agent_id"]
    return None


# ── the resolver ────────────────────────────────────────────────────────────


class PinStore:
    """Where pins live: ``handle -> agent key`` and ``registrar origin -> signing key``.

    In memory by default. Give it a path and it is kept in a JSON file, so a
    restart does not forget what it has seen (a resolver that forgets its pins
    on every start has no alarm for a change made while it was down).
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path).expanduser() if path else None
        self.handles: dict[str, str] = {}
        self.authorities: dict[str, str] = {}
        self.conflicts: dict[str, dict[str, Any]] = {}
        if self.path and self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.handles = dict(data.get("handles") or {})
            self.authorities = dict(data.get("authorities") or {})
            self.conflicts = dict(data.get("conflicts") or {})

    def save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps({"handles": self.handles, "authorities": self.authorities, "conflicts": self.conflicts}, indent=2),
                encoding="utf-8",
            )

    def confirm(self, handle: str) -> None:
        """Accept a pending handle move after checking with the owner out of band."""
        c = self.conflicts.pop(handle.lower(), None)
        if c:
            self.handles[handle.lower()] = c["offered"]
            self.save()


@dataclass(frozen=True)
class ResolvedCard:
    handle: Optional[str]
    agent_id: Optional[str]
    card: dict[str, Any] = field(repr=False)
    registrar: str = ""

    @property
    def operator(self) -> Optional[str]:
        op = self.card.get("operator")
        return op.get("name") if isinstance(op, dict) else None

    @property
    def encryption_key(self) -> Optional[str]:
        k = self.card.get("encryption_key")
        return k if isinstance(k, str) else None


Warn = Callable[[dict[str, Any]], None]

#: Clock-skew grace on a card's ``expires_at`` (SPEC-NAMING 5.3 recommends at most 60s).
CARD_EXPIRY_GRACE = timedelta(seconds=60)


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}".lower() if p.scheme and p.netloc else url.lower()


class Resolver:
    """Resolve handles to agent ids and back, verified and pinned (SPEC-NAMING 5.3)."""

    def __init__(
        self,
        registrar: str = DEFAULT_REGISTRAR,
        *,
        pins: PinStore | None = None,
        on_warning: Warn | None = None,
        client: httpx.AsyncClient | None = None,
        now: Callable[[], datetime] | None = None,
    ):
        self.registrar = registrar.rstrip("/")
        self.pins = pins or PinStore()
        self._warn = on_warning or (lambda w: None)
        self._client = client
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._key_cache: dict[str, tuple[float, list[str]]] = {}

    async def _http(self) -> tuple[httpx.AsyncClient, bool]:
        return (self._client, False) if self._client else (httpx.AsyncClient(), True)

    async def _signing_keys(self, http: httpx.AsyncClient, origin: str) -> list[str]:
        hit = self._key_cache.get(origin)
        if hit and time.time() - hit[0] < 3600:
            return hit[1]
        try:
            r = await http.get(f"{origin}/api/registrar-key", timeout=5.0)
            found = _published_keys(r.json() if r.is_success else None)
        except Exception:
            found = []
        if found:
            self._key_cache[origin] = (time.time(), found)
        return found

    async def resolve(self, handle: str) -> ResolvedCard | None:
        """A handle's verified card, or None when it does not resolve or does not verify."""
        return await self._resolve(f"handle={quote(handle)}")

    async def reverse(self, agent_id: str) -> ResolvedCard | None:
        """The verified card bound to an agent id, or None."""
        card = await self._resolve(f"agent_id={quote(agent_id)}")
        if card is not None and card.agent_id != agent_id:
            self._warn({"code": "card_not_bound", "message": f"the card returned for {agent_id[:12]}... is bound to a different key", "subject": agent_id})
            return None
        return card

    async def agent_id_for(self, target: str) -> str:
        """An agent id for a handle or an agent id. Raises NOT_FOUND when a handle does not resolve."""
        if is_agent_id(target):
            return target
        card = await self.resolve(target)
        if card is None or not card.agent_id:
            raise MeshError(ErrorCode.NOT_FOUND, f"{target} does not resolve to an agent (or its card did not verify)", retryable=False)
        return card.agent_id

    async def _resolve(self, query: str) -> ResolvedCard | None:
        http, owned = await self._http()
        try:
            try:
                r = await http.get(f"{self.registrar}/api/resolve?{query}", timeout=8.0)
            except Exception:
                return None
            if not r.is_success:
                return None
            try:
                doc = r.json()
            except ValueError:
                return None
            return await self.verify_and_pin(doc, _origin(self.registrar), http)
        finally:
            if owned:
                await http.aclose()

    async def verify_and_pin(self, doc: Any, source: str, http: httpx.AsyncClient | None = None) -> ResolvedCard | None:
        """Check a resolve response and update the pins. None means do not use it."""
        card = doc.get("card") if isinstance(doc, dict) else None
        if not isinstance(card, dict):
            return None
        label = card.get("handle") or "card"
        key, sig = doc.get("registrar_key"), doc.get("registrar_sig")
        if not key or not sig:
            self._warn({"code": "card_unsigned", "message": f"card for {label} is unsigned; discarded (SPEC-NAMING 5.3)"})
            return None
        owned = False
        if http is None:
            http, owned = await self._http()
        try:
            published = await self._signing_keys(http, source)
        finally:
            if owned:
                await http.aclose()
        if not published:
            self._warn({"code": "registrar_keys_unavailable", "message": f"{source} publishes no card-signing key, so {label} cannot be verified"})
            return None
        if str(key) not in published:
            self._warn({"code": "card_key_unpublished", "message": f"{label} was signed with a key {source} does not publish; discarded"})
            return None
        try:
            ok = verify_signature(str(key), canonical_bytes(card), base64.b64decode(str(sig)))
        except Exception:
            ok = False
        if not ok:
            self._warn({"code": "card_signature_invalid", "message": f"card signature for {label} does not verify; discarded"})
            return None
        exp = parse_iso(card.get("expires_at", "")) if card.get("expires_at") else None
        if exp is not None and exp + CARD_EXPIRY_GRACE < self._now():
            self._warn({"code": "card_expired", "message": f"card for {label} expired at {card.get('expires_at')}; discarded"})
            return None
        pinned_key = self.pins.authorities.get(source)
        if pinned_key and pinned_key != key:
            # SPEC-NAMING 5.3: a changed signing key is never re-pinned silently.
            # It is accepted only as an additive rotation: the registrar's own
            # published set carries both the pinned key and the new one.
            if pinned_key in published:
                self._warn({"code": "registrar_key_rotated", "message": f"{source} now signs with {str(key)[:12]}... (was {pinned_key[:12]}...); both are in its published key set"})
                self.pins.authorities[source] = str(key)
            else:
                self._warn({
                    "code": "registrar_key_changed",
                    "message": f"REFUSING {label}: {source} signed with {str(key)[:12]}... but this resolver pinned {pinned_key[:12]}..., which the registrar no longer publishes. Verify out of band at {source}/api/registrar-key.",
                })
                return None
        elif not pinned_key:
            self.pins.authorities[source] = str(key)
        handle = card.get("handle") if isinstance(card.get("handle"), str) else None
        aid = _card_agent_id(card)
        if handle and aid:
            h = handle.lower()
            prev = self.pins.handles.get(h)
            if prev and prev != aid:
                self.pins.conflicts[h] = {"pinned": prev, "offered": aid, "source": source, "seen_at": self._now().isoformat()}
                self.pins.save()
                self._warn({
                    "code": "handle_key_changed",
                    "message": (
                        f"REFUSING {handle}: it now resolves to a different agent key (pinned {prev[:12]}..., offered {aid[:12]}...). "
                        "A re-pairing looks like this, and so does a registrar compromise. Confirm with the owner, then call "
                        f"resolver.pins.confirm({handle!r})."
                    ),
                    "subject": handle,
                })
                return None
            self.pins.handles[h] = aid
            self.pins.conflicts.pop(h, None)
        self.pins.save()
        return ResolvedCard(handle=handle, agent_id=aid, card=card, registrar=source)


# ── naming an agent ─────────────────────────────────────────────────────────


@dataclass
class NamingSession:
    registrar: str
    token: str
    email: str

    def __repr__(self) -> str:
        return f"NamingSession(registrar={self.registrar!r}, email={self.email!r})"


async def _post(http: httpx.AsyncClient, url: str, body: Any, token: str | None = None) -> dict[str, Any]:
    headers = {"authorization": f"Bearer {token}"} if token else {}
    r = await http.post(url, json=body, headers=headers, timeout=15.0)
    try:
        data = r.json()
    except ValueError:
        data = {}
    if not r.is_success:
        raise MeshError(ErrorCode.UNAUTHORIZED if r.status_code in (401, 403) else ErrorCode.INTERNAL_ERROR,
                        (data.get("error") if isinstance(data, dict) else None) or f"HTTP {r.status_code}")
    return data if isinstance(data, dict) else {}


async def start_naming(email: str, *, registrar: str = DEFAULT_REGISTRAR, client: httpx.AsyncClient | None = None) -> None:
    """Email the owner a confirmation code."""
    http = client or httpx.AsyncClient()
    try:
        await _post(http, f"{registrar.rstrip('/')}/api/handles/start", {"email": email})
    finally:
        if client is None:
            await http.aclose()


async def verify_naming(email: str, code: str, *, registrar: str = DEFAULT_REGISTRAR, client: httpx.AsyncClient | None = None) -> NamingSession:
    """Trade the emailed code for a naming session."""
    http = client or httpx.AsyncClient()
    try:
        data = await _post(http, f"{registrar.rstrip('/')}/api/handles/verify", {"email": email, "code": code})
    finally:
        if client is None:
            await http.aclose()
    if not data.get("token"):
        raise MeshError(ErrorCode.UNAUTHORIZED, "verification did not return a session")
    return NamingSession(registrar=registrar.rstrip("/"), token=data["token"], email=email)


def pair_line(code: str, agent_id: str) -> str:
    """The line an agent signs to pair a handle with its key (SPEC-NAMING 4.1)."""
    return f"pan-pair-v1:{str(code).upper()}:{agent_id}"


async def complete_naming(
    session: NamingSession,
    name: str,
    agent_seed: str,
    *,
    operator_name: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Claim ``name.<email>`` and pair it with the agent's key. Returns the handle."""
    kp = KeyPair.from_seed(agent_seed)
    agent_id = kp.public_key
    http = client or httpx.AsyncClient()
    try:
        body: dict[str, Any] = {"name": name}
        if operator_name:
            body["operator_name"] = operator_name
        claim = await _post(http, f"{session.registrar}/api/handles/claim", body, session.token)
        handle = claim["handle"]
        pair = await _post(http, f"{session.registrar}/api/pair/start", {"handle": handle}, session.token)
        signature = base64.b64encode(kp.sign(pair_line(pair["code"], agent_id).encode("utf-8"))).decode("ascii")
        await _post(http, f"{session.registrar}/api/pair/complete", {"code": pair["code"], "agent_id": agent_id, "signature": signature})
        return handle
    finally:
        if client is None:
            await http.aclose()
