"""The AgentMesh client: connect, register, discover, request, respond, emit,
subscribe, inbox, names and presence (SPEC.md 6, 16, 18).

One :class:`AgentMesh` is one agent on one NATS connection. Its identity is an
Ed25519 key; its agent id is the public key; it signs every envelope it sends
and checks the signature on every envelope it receives.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Optional, Sequence, Union

import nats
from nats.aio.client import Client as NATS
from nats.aio.msg import Msg
from nats.errors import NoRespondersError
from nats.errors import TimeoutError as NatsTimeoutError

from ._version import __version__
from .attestation import (
    DEFAULT_VOUCH_TTL_MS,
    EPHEMERAL_VOUCH_TTL_MS,
    RENEWAL_FRACTION,
    create_attestation,
    sign_manifest,
)
from .credential import CredentialRenewer, Credentials, RenewalAgent, RenewedCredential
from .envelope import (
    PROTOCOL_VERSION,
    create_envelope,
    decode,
    encode,
    iso_now,
    parse_iso,
    sign_envelope,
    uuid7,
)
from .errors import ErrorCode, MeshError, RejectedError
from .fence import fence_inbound_input, inbound_text_length
from .keys import KeyPair, is_agent_id
from .naming import (
    DEFAULT_REGISTRAR,
    NameLookup,
    NamingGate,
    NamingSession,
    NamingStatus,
    PinStore,
    ResolvedCard,
    Resolver,
    complete_naming,
    registrar_name_lookup,
)
from .subjects import Subjects, is_publishable_subject, is_subject_token
from .tasks import TERMINAL_STATES, Task, TaskTracker
from .trace import child_span, use_trace

__all__ = [
    "AgentMesh",
    "connect",
    "RequestResult",
    "RequestContext",
    "InboxMessage",
    "Warning",
]

# ── numbers (the TypeScript SDK's constants, same values) ───────────────────
DEFAULT_REQUEST_TIMEOUT_S = 30.0
SERVICE_TIMEOUT_S = 5.0
DEFAULT_HEARTBEAT_INTERVAL_S = 30.0
MAX_CLOCK_SKEW_AHEAD_MS = 5 * 60_000
MAX_CLOCK_SKEW_BEHIND_MS = 10 * 60_000
MAX_MAILBOX_AGE_MS = 7 * 24 * 60 * 60_000
MAILBOX_DRAIN_BATCH = 100
MAILBOX_DRAIN_EXPIRES_S = 5.0
DEFAULT_MAILBOX_DRAIN_INTERVAL_S = 60.0
MAX_SEEN_IDS = 5_000
DEFAULT_MAX_INBOUND_CHARS = 64 * 1024
MANIFEST_CACHE_MAX = 500
DEFAULT_INBOX_CAPACITY = 1_000
MAX_HOPS = 3
PROBE_OFFERING = "__registry_probe__"
SDK_CLIENT = f"sdk-python/{__version__}"

Warning = dict[str, Any]
Handler = Callable[[Any, "RequestContext"], Union[Any, Awaitable[Any]]]
EventHandler = Callable[[dict[str, Any], dict[str, Any]], Union[None, Awaitable[None]]]


# ── results and contexts ────────────────────────────────────────────────────


@dataclass
class RequestResult:
    """What :meth:`AgentMesh.request` returns.

    ``task_id`` is None for a bare reply (the work finished in one hop) and set
    when the responder opened a Task it will progress over time; wait for it with
    :meth:`AgentMesh.await_task`.
    """

    task_id: Optional[str]
    payload: dict[str, Any]
    envelope: dict[str, Any] = field(repr=False)
    artifacts: Optional[list[dict[str, Any]]] = None

    @property
    def status(self) -> Optional[str]:
        return self.payload.get("status") if isinstance(self.payload, dict) else None

    @property
    def output(self) -> Any:
        return self.payload.get("output") if isinstance(self.payload, dict) else None

    @property
    def text(self) -> str:
        """The answer as text, for the common ``{"text": ...}`` or string output."""
        out = self.output
        if isinstance(out, str):
            return out
        if isinstance(out, dict):
            for k in ("text", "reply", "message", "answer"):
                if isinstance(out.get(k), str):
                    return out[k]
        return "" if out is None else str(out)


@dataclass
class RequestContext:
    """What a request handler gets beside the input."""

    envelope: dict[str, Any] = field(repr=False)
    task_id: str
    offering: str
    sender: str
    trace: dict[str, Any]
    budget: Optional[dict[str, Any]] = None
    context_id: Optional[str] = None


@dataclass
class InboxMessage:
    """A message waiting in this agent's inbox.

    ``kind`` is ``"request"`` (someone asked this agent something and no
    handler took it: answer with :meth:`reply`) or ``"reply"`` (an answer that
    arrived after the ask stopped waiting, or to a :meth:`AgentMesh.send`).

    Messages drained from the mesh mailbox stay unacknowledged there until
    :meth:`ack` (or :meth:`reply`), so a crash before then means the mesh
    delivers them again.
    """

    kind: str
    id: str
    sender: str
    envelope: dict[str, Any] = field(repr=False)
    input: Any = None
    offering: Optional[str] = None
    in_reply_to: Optional[str] = None
    context_id: Optional[str] = None
    received_at: str = ""
    _mesh: Optional["AgentMesh"] = field(default=None, repr=False, compare=False)
    _js_msg: Any = field(default=None, repr=False, compare=False)
    _acked: bool = field(default=False, repr=False, compare=False)

    @property
    def text(self) -> str:
        """The sender's text (framed, for requests, unless fencing is off)."""
        v = self.input
        if self.kind == "reply":
            p = self.envelope.get("payload") or {}
            v = p.get("output") if isinstance(p, dict) else None
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            for k in ("text", "message", "prompt", "reply"):
                if isinstance(v.get(k), str):
                    return v[k]
        return "" if v is None else str(v)

    @property
    def acked(self) -> bool:
        return self._acked

    async def ack(self) -> None:
        """Mark handled: removes it from the inbox and acknowledges it to the mailbox."""
        if self._acked:
            return
        self._acked = True
        if self._mesh is not None:
            self._mesh._forget_inbox_item(self)
        if self._js_msg is not None:
            try:
                await self._js_msg.ack()
            except Exception:
                pass

    async def reply(self, output: Any, *, status: str = "completed") -> None:
        """Answer a request, then acknowledge it."""
        if self.kind != "request":
            raise MeshError(ErrorCode.INVALID_ENVELOPE, "only a request can be replied to")
        if self._mesh is None:
            raise MeshError(ErrorCode.INTERNAL_ERROR, "this message is not attached to a connection")
        await self._mesh._send_respond(self.envelope, {"status": status, "output": output})
        await self.ack()


@dataclass
class _Pending:
    request: dict[str, Any]
    agent_id: str
    future: "asyncio.Future[dict[str, Any]]"
    accepted: bool = False
    on_accept: Optional[Callable[[dict[str, Any]], None]] = None
    reset: Optional[Callable[[], None]] = None


class _Seen:
    """A bounded memory of ``(from, id)`` pairs (SPEC 22.2)."""

    def __init__(self, cap: int = MAX_SEEN_IDS):
        self._cap = cap
        self._d: OrderedDict[str, None] = OrderedDict()

    def remember(self, key: str) -> bool:
        if key in self._d:
            return False
        self._d[key] = None
        if len(self._d) > self._cap:
            self._d.popitem(last=False)
        return True

    def __contains__(self, key: str) -> bool:
        return key in self._d


async def _maybe_await(v: Any) -> Any:
    return await v if inspect.isawaitable(v) else v


def _now_ms() -> float:
    return time.time() * 1000


# ── the client ──────────────────────────────────────────────────────────────


class AgentMesh:
    """One agent on the mesh. Make one with :func:`agentmesh.connect`."""

    def __init__(self, nc: NATS, kp: KeyPair, node_kp: KeyPair, *, owns_connection: bool = True):
        self._nc = nc
        self._kp = kp
        self._node_kp = node_kp
        self._owns = owns_connection
        self.agent_id = kp.public_key
        self._manifest: dict[str, Any] | None = None
        self._register_args: dict[str, Any] | None = None
        self._handlers: dict[str, Handler] = {}
        self._handler_opts: dict[str, dict[str, Any]] = {}
        self._default_handler: Handler | None = None
        self._pending: dict[str, _Pending] = {}
        self._sent: OrderedDict[str, str] = OrderedDict()  # request id -> agent id, for late replies
        self._seen_inbox = _Seen()
        self._seen_events = _Seen()
        self._tasks = TaskTracker()
        self._task_subs: dict[str, Any] = {}
        self._task_update_handler: Callable[[dict[str, Any], dict[str, Any]], Any] | None = None
        self._manifest_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._service_pins: dict[str, str] = {}
        self._intermediary_pin: str | None = None
        self._inbox_items: list[InboxMessage] = []
        self._inbox_by_key: dict[str, InboxMessage] = {}
        self._inbox_cond = asyncio.Condition()
        self._background: set[asyncio.Task[Any]] = set()
        self._loops: list[asyncio.Task[Any]] = []
        self._drain_lock = asyncio.Lock()
        self._inbox_sub: Any = None
        self._event_subs: list[Any] = []
        self._closed = False
        self._vouch_expires_at: str | None = None
        self._vouch_renew_at_ms: float | None = None
        self._vouch_last_error: str | None = None
        # set by connect()
        self.fence_inbound = True
        self.max_inbound_chars = DEFAULT_MAX_INBOUND_CHARS
        self.inbox_enabled = True
        self.inbox_capacity = DEFAULT_INBOX_CAPACITY
        self.mailbox_drain_interval = DEFAULT_MAILBOX_DRAIN_INTERVAL_S
        self.vouch_ttl_ms: int | None = None
        self.service_keys: dict[str, str] = {}
        self.intermediary_keys: set[str] | None = None
        self.on_warning: Callable[[Warning], None] | None = None
        self.naming_gate: NamingGate | None = None
        self.resolver: Resolver = Resolver()
        self.credential_renewer: CredentialRenewer | None = None

    # ── connecting ───────────────────────────────────────────────────────

    @classmethod
    async def connect(
        cls,
        servers: str | Sequence[str] | None = None,
        *,
        credentials: Credentials | None = None,
        agent_seed: str | None = None,
        jwt: str | None = None,
        connection_seed: str | None = None,
        node_seed: str | None = None,
        api_base: str | None = None,
        on_credential_renewed: Callable[[RenewedCredential], Any] | None = None,
        credentials_folder: str | None = None,
        require_named: bool = True,
        name: str | None = None,
        owner_email: str | None = None,
        registrar: str = DEFAULT_REGISTRAR,
        name_lookup: NameLookup | None = None,
        pin_store: PinStore | str | None = None,
        fence_inbound: bool = True,
        max_inbound_chars: int = DEFAULT_MAX_INBOUND_CHARS,
        inbox: bool = True,
        inbox_capacity: int = DEFAULT_INBOX_CAPACITY,
        mailbox_drain_interval: float = DEFAULT_MAILBOX_DRAIN_INTERVAL_S,
        vouch_ttl_ms: int | None = None,
        service_keys: dict[str, str] | None = None,
        intermediary_keys: Iterable[str] | None = None,
        on_warning: Callable[[Warning], None] | None = None,
        connect_timeout: float = 10.0,
        max_reconnect_attempts: int = 10,
        reconnect_time_wait: float = 2.0,
        nats_options: dict[str, Any] | None = None,
    ) -> "AgentMesh":
        """Connect one agent to the mesh.

        Credentials, in order of preference:

        - ``credentials=Credentials.load(folder)`` (what :func:`agentmesh.join`
          saved): the agent key, the connection credential, the servers and the
          control plane in one object. Renewal runs on its own and a renewed
          credential is written back to ``credentials_folder`` when given.
        - ``agent_seed`` plus ``jwt`` and ``connection_seed`` (the seed of the
          key the JWT is bound to; defaults to ``agent_seed``).
        - ``agent_seed`` alone, or nothing: an unauthenticated connection, for a
          local nats-server in development. A fresh identity is made when no seed
          is given.

        ``require_named`` is the naming rule and is on by default: every send
        this agent starts is refused with NOT_NAMED until its handle follows the
        global standard at the naming service. ``False`` is for tests only.
        """
        if credentials is not None:
            agent_seed = agent_seed or credentials.agent_seed
            jwt = jwt or credentials.jwt
            connection_seed = connection_seed or credentials.connection_seed
            api_base = api_base or credentials.api_base
            if servers is None:
                servers = credentials.servers
        if servers is None or (not isinstance(servers, str) and not list(servers)):
            raise ValueError("connect() needs the mesh's servers (or credentials that carry them)")
        server_list = _pick_servers([servers] if isinstance(servers, str) else list(servers))

        kp = KeyPair.from_seed(agent_seed) if agent_seed else KeyPair.create()
        node_kp = KeyPair.from_seed(node_seed) if node_seed else kp
        agent_id = kp.public_key

        renewer: CredentialRenewer | None = None
        if jwt and api_base:
            cred_seed = connection_seed or kp.seed

            async def persist(fresh: RenewedCredential) -> None:
                if credentials is not None and credentials_folder:
                    credentials.update_jwt(credentials_folder, fresh.jwt, fresh.expires_at)
                if on_credential_renewed is not None:
                    await _maybe_await(on_credential_renewed(fresh))

            renewer = CredentialRenewer(
                api_base=api_base,
                jwt=jwt,
                node_seed=cred_seed,
                agents=[RenewalAgent(id=agent_id, seed=kp.seed)],
                on_renewed=persist,
                on_warning=on_warning,
            )
            # Heal a credential that lapsed while this host was off, before
            # anything tries to connect with it.
            await renewer.renew_if_expiring()

        opts: dict[str, Any] = dict(
            servers=server_list,
            name=name or f"agentmesh-python {agent_id[:12]}",
            connect_timeout=connect_timeout,
            max_reconnect_attempts=max_reconnect_attempts,
            reconnect_time_wait=reconnect_time_wait,
            allow_reconnect=True,
        )
        if jwt:
            auth_kp = KeyPair.from_seed(connection_seed) if connection_seed else kp

            def user_jwt_cb() -> bytearray:
                current = renewer.credential if renewer else jwt
                return bytearray(current.encode("ascii"))

            def signature_cb(nonce: str) -> bytes:
                return base64.b64encode(auth_kp.sign(nonce.encode("ascii")))

            opts["user_jwt_cb"] = user_jwt_cb
            opts["signature_cb"] = signature_cb

        holder: dict[str, AgentMesh] = {}

        async def reconnected_cb() -> None:
            m = holder.get("mesh")
            if m is not None and m._manifest is not None:
                m._spawn(m.drain_mailbox())

        refused: asyncio.Event = asyncio.Event()
        refusal: list[str] = []

        async def error_cb(exc: Exception) -> None:
            text = str(exc)
            if holder.get("mesh") is None and ("uthorization" in text or "xpired" in text):
                refusal.append(text)
                refused.set()
            m = holder.get("mesh")
            if m is not None and m.on_warning is not None:
                m.on_warning({"code": "transport_error", "message": text})

        opts["reconnected_cb"] = reconnected_cb
        opts["error_cb"] = error_cb
        if nats_options:
            opts.update(nats_options)
        # nats-py keeps retrying a first connection the server refuses for
        # authorization, so a revoked or wrong credential would hang here. Race
        # the connect against the first refusal and an overall deadline instead.
        attempt = asyncio.ensure_future(nats.connect(**opts))
        watch = asyncio.ensure_future(refused.wait())
        deadline = connect_timeout * max(1, len(server_list)) * 2 + 5
        done, _ = await asyncio.wait({attempt, watch}, timeout=deadline, return_when=asyncio.FIRST_COMPLETED)
        watch.cancel()
        if attempt not in done:
            attempt.cancel()
            if refusal:
                raise MeshError(ErrorCode.TRANSPORT_PERMISSION_DENIED,
                                f"{', '.join(server_list)} refused this credential: {refusal[0]}. "
                                "A refusal after joining means the credential was revoked or does not match its key.",
                                retryable=False)
            raise MeshError(ErrorCode.AGENT_UNAVAILABLE, f"could not connect to {', '.join(server_list)} within {deadline:g}s")
        try:
            nc = attempt.result()
        except Exception as exc:
            raise MeshError(ErrorCode.TRANSPORT_PERMISSION_DENIED if "uthoriz" in str(exc) else ErrorCode.AGENT_UNAVAILABLE,
                            f"could not connect to {', '.join(server_list)}: {exc}") from exc

        mesh = cls(nc, kp, node_kp)
        holder["mesh"] = mesh
        mesh.fence_inbound = fence_inbound
        mesh.max_inbound_chars = max_inbound_chars
        mesh.inbox_enabled = inbox
        mesh.inbox_capacity = inbox_capacity
        mesh.mailbox_drain_interval = max(1.0, mailbox_drain_interval)
        mesh.vouch_ttl_ms = vouch_ttl_ms
        mesh.service_keys = dict(service_keys or {})
        mesh.intermediary_keys = set(intermediary_keys) if intermediary_keys is not None else None
        mesh.on_warning = on_warning
        pins = pin_store if isinstance(pin_store, PinStore) else PinStore(pin_store)
        mesh.resolver = Resolver(registrar, pins=pins, on_warning=mesh._warn)
        mesh.credential_renewer = renewer
        if renewer is not None:
            renewer.start()
        await mesh._listen_inbox()
        if require_named:
            mesh.naming_gate = NamingGate(
                agent_id,
                name_lookup or registrar_name_lookup(registrar),
                name=name,
                owner_email=owner_email,
                last_verified=credentials.handle if credentials else None,
            )
            await mesh.naming_gate.check()
        return mesh

    # ── small helpers ────────────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self.agent_id

    @property
    def node_id(self) -> str:
        return self._node_kp.public_key

    @property
    def registered(self) -> bool:
        return self._manifest is not None

    @property
    def is_closed(self) -> bool:
        return self._closed

    def _warn(self, w: Warning) -> None:
        if self.on_warning is not None:
            try:
                self.on_warning(w)
            except Exception:
                pass

    def _spawn(self, coro: Awaitable[Any]) -> asyncio.Task[Any]:
        t = asyncio.ensure_future(coro)
        self._background.add(t)
        t.add_done_callback(self._background.discard)
        return t

    def _envelope(self, type_: str, **kw: Any) -> dict[str, Any]:
        return sign_envelope(create_envelope(type_, self.agent_id, **kw), self._kp)  # type: ignore[arg-type]

    def sign_detached(self, message: str) -> str:
        """Standard-base64 Ed25519 signature of ``message`` by this agent's key."""
        return base64.b64encode(self._kp.sign(message.encode("utf-8"))).decode("ascii")

    async def _publish(self, subject: str, env: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        data = encode(env)
        mp = getattr(self._nc, "max_payload", 0) or 0
        if mp and len(data) > mp:
            raise MeshError(ErrorCode.PAYLOAD_TOO_LARGE, f"the envelope is {len(data)} bytes; this mesh accepts at most {mp}", retryable=False)
        await self._nc.publish(subject, data, headers=headers)

    async def _service_request(self, subject: str, env: dict[str, Any], timeout: float, pin_as: str | None = None) -> dict[str, Any]:
        try:
            msg = await self._nc.request(subject, encode(env), timeout=timeout)
        except NoRespondersError as exc:
            raise MeshError(ErrorCode.TRANSPORT_NO_RESPONDERS, f"nothing answers on {subject}") from exc
        except (NatsTimeoutError, asyncio.TimeoutError) as exc:
            raise MeshError(ErrorCode.TRANSPORT_TIMEOUT, f"Request timed out on subject '{subject}'") from exc
        resp = decode(msg.data)
        self._bind_response(resp, env, subject=pin_as or subject)
        if resp.get("error"):
            raise MeshError.from_error_object(resp["error"])
        return resp

    async def service_request(self, subject: str, payload: Any, timeout: float = 30.0) -> Any:
        """A signed request to a platform service; returns the reply's payload."""
        env = self._envelope("request", payload=payload)
        resp = await self._service_request(subject, env, timeout)
        return resp.get("payload")

    # ── response binding (SPEC 6.2) ─────────────────────────────────────

    def _bind_response(self, resp: dict[str, Any], request: dict[str, Any], *, agent: str | None = None, subject: str | None = None) -> None:
        if resp.get("in_reply_to") != request.get("id"):
            raise MeshError(ErrorCode.IDENTITY_MISMATCH, "Response is not bound to this request (in_reply_to does not match)", details={"from": resp.get("from")})
        if "to" in resp and resp.get("to") != self.agent_id:
            raise MeshError(ErrorCode.IDENTITY_MISMATCH, f"Response was addressed to {resp.get('to')}, not to this agent")
        if agent is not None and resp.get("from") != agent:
            self._require_intermediary(str(resp.get("from")), agent)
        elif subject is not None:
            self._check_service_key(subject, str(resp.get("from")))

    def _require_intermediary(self, frm: str, for_agent: str) -> None:
        if self.intermediary_keys is not None:
            if frm not in self.intermediary_keys:
                raise MeshError(ErrorCode.IDENTITY_MISMATCH, f"{frm} answered for {for_agent} but is not a configured mesh intermediary")
            return
        if self._intermediary_pin is None:
            self._intermediary_pin = frm
            self._warn({"code": "intermediary_pinned", "message": f"{frm} answered a request addressed to {for_agent}; pinned as this connection's mesh intermediary", "subject": for_agent, "from": frm})
            return
        if self._intermediary_pin != frm:
            raise MeshError(ErrorCode.IDENTITY_MISMATCH, f"{frm} answered for {for_agent}, but this connection's mesh intermediary is {self._intermediary_pin}")

    def _check_service_key(self, subject: str, frm: str) -> None:
        configured = self.service_keys.get(subject)
        if configured is not None:
            if configured != frm:
                raise MeshError(ErrorCode.IDENTITY_MISMATCH, f"{subject} was answered by {frm}, not by the configured service key")
            return
        pinned = self._service_pins.get(subject)
        if pinned is None:
            self._service_pins[subject] = frm
        elif pinned != frm:
            self._service_pins[subject] = frm
            self._warn({"code": "service_key_changed", "message": f"{subject} is now answered by {frm} (was {pinned})", "subject": subject, "from": frm, "previous": pinned})

    # ── naming ───────────────────────────────────────────────────────────

    def naming_status(self) -> NamingStatus | None:
        """Where this agent stands under the naming rule, as last checked."""
        return self.naming_gate.current() if self.naming_gate else None

    async def recheck_name(self) -> NamingStatus | None:
        """Ask the naming service again now (call after naming the agent)."""
        if self.naming_gate is None:
            return None
        self.naming_gate.forget()
        return await self.naming_gate.check()

    async def complete_naming(self, session: NamingSession, name: str, *, operator_name: str | None = None) -> str:
        """Claim ``name.<owner email>`` for this agent and pair it with its key."""
        handle = await complete_naming(session, name, self._kp.seed, operator_name=operator_name)
        await self.recheck_name()
        return handle

    async def resolve(self, handle: str) -> ResolvedCard | None:
        """A handle's verified card (SPEC-NAMING 5), pinned on first sight."""
        return await self.resolver.resolve(handle)

    async def whois(self, agent_id: str) -> ResolvedCard | None:
        """Reverse resolution: the verified card bound to an agent id."""
        return await self.resolver.reverse(agent_id)

    async def _target(self, to: str) -> str:
        return await self.resolver.agent_id_for(to)

    async def _gate(self) -> None:
        if self.naming_gate is not None:
            await self.naming_gate.require()

    # ── register / deregister ────────────────────────────────────────────

    def _build_manifest(self, a: dict[str, Any]) -> dict[str, Any]:
        profile = {"client": SDK_CLIENT}
        if sys.platform in ("darwin", "win32", "linux"):
            profile["platform"] = sys.platform
        profile.update(a.get("node_profile") or {})
        if self.vouch_ttl_ms is not None:
            ttl = self.vouch_ttl_ms
        else:
            ttl = DEFAULT_VOUCH_TTL_MS if profile.get("availability_class") else EPHEMERAL_VOUCH_TTL_MS
        inbox = Subjects.agent_inbox(self.agent_id)
        m: dict[str, Any] = {
            "id": self.agent_id,
            "name": a["name"],
            "description": a.get("description") or "",
            "version": a.get("version") or "0.1.0",
            "protocol_version": PROTOCOL_VERSION,
            "owner": self._node_kp.public_key,
            "endpoint": inbox,
            "endpoints": {"inbox": inbox},
            "node": {
                "id": self._node_kp.public_key,
                "attestation": create_attestation(self._node_kp, self.agent_id, ttl),
                "profile": profile,
            },
            "capabilities": list(a.get("capabilities") or []),
            "offerings": list(a.get("offerings") or []),
        }
        for k in ("visibility", "interaction", "harness", "harness_version", "model", "provider",
                  "default_input_modes", "default_output_modes", "works_with", "data_use", "public",
                  "cost", "rate_limits", "meta", "extensions"):
            if a.get(k) is not None:
                m[k] = a[k]
        if a.get("limits") is not None:
            m["limits"] = a["limits"]
        elif self.max_inbound_chars != DEFAULT_MAX_INBOUND_CHARS:
            m["limits"] = {"max_inbound_chars": self.max_inbound_chars}
        for k, v in (a.get("extra") or {}).items():
            m.setdefault(k, v)
        sign_manifest(m, self._kp)
        return m

    async def register(
        self,
        name: str,
        *,
        description: str = "",
        version: str = "0.1.0",
        offerings: Sequence[dict[str, Any]] | None = None,
        capabilities: Sequence[str] | None = None,
        visibility: str | None = None,
        interaction: str | None = None,
        harness: str | None = None,
        harness_version: str | None = None,
        model: str | None = None,
        provider: dict[str, Any] | None = None,
        node_profile: dict[str, Any] | None = None,
        default_input_modes: Sequence[str] | None = None,
        default_output_modes: Sequence[str] | None = None,
        works_with: Sequence[dict[str, Any]] | None = None,
        data_use: dict[str, Any] | None = None,
        public: dict[str, Any] | None = None,
        limits: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        heartbeat: bool = True,
    ) -> dict[str, Any]:
        """Say "I exist, here is my manifest" (primitive 1). Makes the agent discoverable.

        Offerings are ``{"id", "name", "description"}`` dicts. ``node_profile``
        with an ``availability_class`` earns the 30-day vouch lease; without one
        the lease is 72 hours (renewed while the process runs either way).
        ``interaction="interactive"`` says a person is in the loop, so the SDK
        sends no accept signal and requesters expect a slow answer.
        """
        args = {k: v for k, v in locals().items() if k not in ("self", "heartbeat")}
        manifest = self._build_manifest(args)
        env = self._envelope("register", payload=manifest)
        try:
            await self._service_request(Subjects.REGISTRY_REGISTER, env, SERVICE_TIMEOUT_S)
        except MeshError as exc:
            if exc.code != ErrorCode.TRANSPORT_NO_RESPONDERS:
                raise
            await self._publish(Subjects.REGISTRY_REGISTER, env)
        self._manifest = manifest
        self._register_args = args
        self._note_vouch(manifest)
        self._start_loop("mailbox", self._mailbox_loop())
        self._start_loop("vouch", self._vouch_loop())
        if heartbeat and self._owns:
            self._start_loop("heartbeat", self._heartbeat_loop())
        return manifest

    async def deregister(self) -> None:
        env = self._envelope("register", payload={"deregister": True})
        await self._service_request(Subjects.REGISTRY_DEREGISTER, env, SERVICE_TIMEOUT_S)
        self._manifest = None
        self._stop_loops({"vouch", "heartbeat", "mailbox"})

    def _note_vouch(self, manifest: dict[str, Any]) -> None:
        att = manifest["node"]["attestation"]
        self._vouch_expires_at = att["expires_at"]
        iss, exp = parse_iso(att["issued_at"]), parse_iso(att["expires_at"])
        if iss and exp:
            life = (exp - iss).total_seconds() * 1000
            self._vouch_renew_at_ms = iss.timestamp() * 1000 + life * RENEWAL_FRACTION

    @property
    def vouch(self) -> dict[str, Any]:
        """The node vouch lease: ``expires_at``, ``renew_at``, ``last_error``."""
        renew = None
        if self._vouch_renew_at_ms is not None:
            renew = iso_now(datetime.fromtimestamp(self._vouch_renew_at_ms / 1000, tz=timezone.utc))
        return {"expires_at": self._vouch_expires_at, "renew_at": renew, "last_error": self._vouch_last_error}

    @property
    def credential(self) -> dict[str, Any] | None:
        """The connection credential lease, or None when nothing renews it."""
        return self.credential_renewer.status() if self.credential_renewer else None

    async def renew_vouch(self) -> dict[str, Any]:
        """Re-register now under a freshly signed vouch."""
        if self._register_args is None:
            raise MeshError(ErrorCode.INVALID_MANIFEST, "this agent is not registered")
        return await self.register(**{k: v for k, v in self._register_args.items()}, heartbeat=True)

    async def _vouch_loop(self) -> None:
        while not self._closed:
            # Compare the clock against the deadline on a periodic tick rather than
            # sleeping until it, so a host that slept through it renews on waking.
            wait = 3600.0 if self._vouch_renew_at_ms is None else (self._vouch_renew_at_ms - _now_ms()) / 1000
            await asyncio.sleep(min(3600.0, max(1.0, wait)))
            if self._vouch_renew_at_ms is not None and _now_ms() >= self._vouch_renew_at_ms and self._register_args:
                try:
                    manifest = self._build_manifest(self._register_args)
                    env = self._envelope("register", payload=manifest)
                    await self._service_request(Subjects.REGISTRY_REGISTER, env, SERVICE_TIMEOUT_S)
                    self._manifest = manifest
                    self._note_vouch(manifest)
                    self._vouch_last_error = None
                except Exception as exc:
                    self._vouch_last_error = str(exc)
                    self._warn({"code": "vouch_renewal_failed", "message": f"could not renew this agent's node vouch: {exc}. It expires {self._vouch_expires_at}.", "subject": self.agent_id})

    # ── heartbeat and presence (SPEC 9.6) ────────────────────────────────

    async def send_heartbeat(self, availability: str = "online") -> None:
        """Say this node is alive. ``online``, ``busy``, ``degraded`` or ``offline``."""
        env = self._envelope("emit", payload={"node": self.node_id, "availability": availability})
        await self._publish(Subjects.heartbeat(self.node_id), env)

    async def _heartbeat_loop(self) -> None:
        while not self._closed:
            try:
                await self.send_heartbeat()
            except Exception:
                pass
            await asyncio.sleep(DEFAULT_HEARTBEAT_INTERVAL_S)

    async def presence(self, agent: str) -> str | None:
        """An agent's availability as the registry sees it now (``online``,
        ``busy``, ``degraded``, ``offline``), or None when it is not registered.
        Takes a handle or an agent id."""
        agent_id = await self._target(agent)
        found = await self.discover(agent_ids=[agent_id])
        for m in found:
            if m.get("id") == agent_id:
                a = m.get("availability")
                return a if isinstance(a, str) else None
        return None

    # ── discover (primitive 2) ───────────────────────────────────────────

    async def discover(self, query: dict[str, Any] | None = None, **filters: Any) -> list[dict[str, Any]]:
        """Who can do X? Returns manifests.

        Filters: ``capabilities``, ``offering_id``, ``availability``, ``tags``,
        ``node``, ``owner``, ``agent_ids``, ``limit`` and the rest of SPEC 9.3.
        """
        q = {**(query or {}), **{k: v for k, v in filters.items() if v is not None}}
        env = self._envelope("discover", payload=q)
        resp = await self._service_request(Subjects.REGISTRY_DISCOVER, env, DEFAULT_REQUEST_TIMEOUT_S)
        payload = resp.get("payload") or {}
        agents = payload.get("agents") if isinstance(payload, dict) else None
        agents = agents if isinstance(agents, list) else []
        for m in agents:
            self._cache_manifest(m)
        return agents

    async def get_manifest(self, agent: str) -> dict[str, Any]:
        """One agent's manifest, by handle or agent id."""
        agent_id = await self._target(agent)
        env = self._envelope("discover", payload={"agent_id": agent_id})
        resp = await self._service_request(Subjects.registry_get(agent_id), env, DEFAULT_REQUEST_TIMEOUT_S, pin_as="mesh.registry.get")
        m = resp.get("payload")
        if isinstance(m, dict) and m.get("id") == agent_id:
            self._cache_manifest(m)
        return m  # type: ignore[return-value]

    def _cache_manifest(self, m: Any) -> None:
        if not isinstance(m, dict) or not isinstance(m.get("id"), str) or not m["id"]:
            return
        if m.get("offerings") is None and isinstance(m.get("skills"), list):
            m["offerings"] = m["skills"]
        self._manifest_cache.pop(m["id"], None)
        self._manifest_cache[m["id"]] = m
        while len(self._manifest_cache) > MANIFEST_CACHE_MAX:
            self._manifest_cache.popitem(last=False)

    def _resolved_inbox(self, agent_id: str) -> str:
        m = self._manifest_cache.get(agent_id) or {}
        cand = (m.get("endpoints") or {}).get("inbox") if isinstance(m.get("endpoints"), dict) else None
        cand = cand or m.get("endpoint")
        return cand if is_publishable_subject(cand) else Subjects.agent_inbox(agent_id)

    # ── request (primitive 3) ────────────────────────────────────────────

    async def request(
        self,
        to: str,
        offering: str,
        input: Any = None,
        *,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_S,
        context_id: str | None = None,
        budget: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
        trace: dict[str, Any] | None = None,
        accepted_output: Sequence[str] | None = None,
        on_accept: Callable[[dict[str, Any]], None] | None = None,
    ) -> RequestResult:
        """Ask another agent to do something and wait for the answer.

        ``to`` is a handle (``name.owner@example.com``) or an agent id. The
        answer arrives at this agent's own inbox and is matched by
        ``in_reply_to``. If the target accepts the work (SPEC 6.4a) the timeout
        restarts. If the target's node queues it for later, this raises
        REQUEST_QUEUED, and the reply, when it comes, lands in :meth:`receive`.
        """
        await self._gate()
        agent_id = await self._target(to)
        if budget is not None and budget.get("revision", 0) != 0:
            raise MeshError(ErrorCode.INVALID_ENVELOPE, "budget.revision must be 0 on an initiating request (SPEC 7.7)", retryable=False)
        self._preflight_text(agent_id, input)
        config: dict[str, Any] = {"timeout_ms": int(timeout * 1000)}
        if accepted_output:
            config["accepted_output"] = list(accepted_output)
        env = self._envelope(
            "request",
            to=agent_id,
            context_id=context_id,
            trace=child_span(trace) if trace else None,
            budget=budget,
            payload={"offering": offering, "input": input, "config": config},
            meta=meta,
            include_null_payload=True,
        )
        try:
            resp = await self._await_reply(self._resolved_inbox(agent_id), env, agent_id, timeout, on_accept)
        except MeshError as exc:
            if exc.code in (ErrorCode.TRANSPORT_TIMEOUT, ErrorCode.TRANSPORT_NO_RESPONDERS) and not (exc.details or {}).get("accepted"):
                self._remember_sent(env["id"], agent_id)
                raise MeshError(
                    ErrorCode.AGENT_UNAVAILABLE,
                    f"No response from {agent_id}: the agent may just be offline. If it is a registered agent, "
                    "this request was captured by its mailbox and its reply, if any, will arrive at your own inbox later.",
                    details={"request_id": env["id"]},
                ) from exc
            if exc.code == ErrorCode.REQUEST_QUEUED:
                self._remember_sent(env["id"], agent_id)
            raise
        payload = resp.get("payload") if isinstance(resp.get("payload"), dict) else {}
        task_id = resp.get("task_id")
        if task_id:
            if self._tasks.has(task_id):
                raise MeshError(ErrorCode.IDENTITY_MISMATCH, f"{agent_id} answered with task_id {task_id}, which is already tracked here")
            status = payload.get("status")
            now = iso_now()
            self._tasks.create(Task(
                id=task_id, requester=self.agent_id, responder=agent_id, offering=offering,
                state=status if status and status != "accepted" else "working",
                created_at=now, updated_at=now, history=[env, resp],
                artifacts=list(resp.get("artifacts") or []), context_id=context_id or resp.get("context_id"), budget=budget,
            ))
            if status not in TERMINAL_STATES:
                await self._watch_task(task_id)
        if resp.get("error"):
            err = MeshError.from_error_object(resp["error"])
            if task_id:
                err.details = {**(err.details or {}), "task_id": task_id}
            raise err
        return RequestResult(task_id=task_id, payload=payload, envelope=resp, artifacts=resp.get("artifacts"))

    async def ask(self, to: str, text: str, *, timeout: float = 120.0, context_id: str | None = None) -> str:
        """Ask an agent in words and wait for its answer, as text (offering ``chat``)."""
        r = await self.request(to, "chat", {"text": text}, timeout=timeout, context_id=context_id)
        if r.task_id and r.status not in TERMINAL_STATES:
            payload = await self.await_task(r.task_id, timeout=timeout)
            return RequestResult(r.task_id, payload, r.envelope).text
        return r.text

    async def send(self, to: str, text: str | None = None, *, offering: str = "chat", input: Any = None, context_id: str | None = None) -> str:
        """Send without waiting. Returns the request id; the reply lands in the inbox.

        Uses the ``chat`` offering with ``{"text": ...}`` by default, the shape
        every AgentMesh agent answers.
        """
        await self._gate()
        agent_id = await self._target(to)
        body = input if input is not None else {"text": text or ""}
        self._preflight_text(agent_id, body)
        env = self._envelope("request", to=agent_id, context_id=context_id,
                             payload={"offering": offering, "input": body}, include_null_payload=True)
        self._remember_sent(env["id"], agent_id)
        await self._publish(self._resolved_inbox(agent_id), env)
        return env["id"]

    def _remember_sent(self, request_id: str, agent_id: str) -> None:
        self._sent[request_id] = agent_id
        while len(self._sent) > MAX_SEEN_IDS:
            self._sent.popitem(last=False)

    def _preflight_text(self, agent_id: str, input: Any) -> None:
        m = self._manifest_cache.get(agent_id) or {}
        limits = m.get("limits") if isinstance(m.get("limits"), dict) else {}
        cap = limits.get("max_inbound_chars") if isinstance(limits.get("max_inbound_chars"), int) else DEFAULT_MAX_INBOUND_CHARS
        size = inbound_text_length(input)
        if cap and size > cap:
            raise MeshError(ErrorCode.CONTEXT_TOO_LARGE, f"this message carries {size} characters of text; {agent_id[:12]}... accepts at most {cap}", retryable=False)

    async def _await_reply(self, subject: str, env: dict[str, Any], agent_id: str, timeout: float,
                           on_accept: Callable[[dict[str, Any]], None] | None) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()
        timer: list[asyncio.TimerHandle] = []
        pend = _Pending(request=env, agent_id=agent_id, future=fut, on_accept=on_accept)

        def fail(exc: MeshError) -> None:
            if not fut.done():
                fut.set_exception(exc)

        def on_timeout() -> None:
            if pend.accepted:
                fail(MeshError(ErrorCode.TRANSPORT_TIMEOUT,
                               f"{agent_id} accepted this request but no answer arrived within {timeout:g}s of the accept",
                               details={"accepted": True}))
            else:
                fail(MeshError(ErrorCode.TRANSPORT_TIMEOUT, f"Request timed out on subject '{subject}'"))

        def arm() -> None:
            for t in timer:
                t.cancel()
            timer[:] = [loop.call_later(timeout, on_timeout)]

        pend.reset = arm
        self._pending[env["id"]] = pend
        arm()

        async def on_transport_reply(m: Msg) -> None:
            hdrs = m.headers or {}
            status = hdrs.get("Status") or hdrs.get("status") or getattr(m, "_status", None)
            if str(status) == "503" or (not m.data and str(status).startswith("5")):
                fail(MeshError(ErrorCode.TRANSPORT_NO_RESPONDERS, f"nothing is listening on {subject}"))
                return
            try:
                r = decode(m.data)
                self._bind_response(r, env, agent=agent_id)
            except MeshError:
                return
            # Only the node's queued acknowledgement travels on the transport
            # reply subject (SPEC 6.4a); answers come to this agent's inbox.
            ack = _queued_ack(r)
            if ack is None or not self._fresh(r, False) or not self._seen_inbox.remember(f"{r.get('from')}|{r.get('id')}"):
                return
            fail(MeshError(ErrorCode.REQUEST_QUEUED,
                           f"The target's node queued this request (inbox {ack['inbox_id']}) for an attended session. "
                           "The real reply, if any, arrives later at this agent's own inbox.",
                           retryable=False, details={"queued": True, "inbox_id": ack["inbox_id"], "request_id": env["id"]}))

        reply_to = self._nc.new_inbox()
        sub = await self._nc.subscribe(reply_to, cb=on_transport_reply)
        try:
            data = encode(env)
            mp = getattr(self._nc, "max_payload", 0) or 0
            if mp and len(data) > mp:
                raise MeshError(ErrorCode.PAYLOAD_TOO_LARGE, f"the envelope is {len(data)} bytes; this mesh accepts at most {mp}", retryable=False)
            await self._nc.publish(subject, data, reply=reply_to)
            return await fut
        finally:
            for t in timer:
                t.cancel()
            self._pending.pop(env["id"], None)
            try:
                await sub.unsubscribe()
            except Exception:
                pass

    # ── tasks ────────────────────────────────────────────────────────────

    def get_task(self, task_id: str) -> Task | None:
        return self._tasks.get(task_id)

    def on_task_update(self, handler: Callable[[dict[str, Any], dict[str, Any]], Any]) -> None:
        """Called with ``(payload, envelope)`` for every update to a task this agent started."""
        self._task_update_handler = handler

    async def _watch_task(self, task_id: str) -> None:
        if task_id in self._task_subs or not is_subject_token(task_id):
            return

        async def cb(m: Msg) -> None:
            try:
                self._handle_task_update(task_id, decode(m.data))
            except MeshError:
                pass

        self._task_subs[task_id] = await self._nc.subscribe(Subjects.task_update(task_id), cb=cb)

    def _handle_task_update(self, task_id: str, env: dict[str, Any]) -> None:
        if env.get("type") != "respond" or env.get("task_id") != task_id:
            return
        payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
        if payload.get("status") == "accepted":
            return
        task = self._tasks.get(task_id)
        if task is None or env.get("from") not in (task.responder, task.requester):
            return
        if not self._seen_inbox.remember(f"{env.get('from')}|{env.get('id')}") or not self._fresh(env, False):
            return
        self._tasks.add_to_history(task_id, env)
        status = payload.get("status")
        if isinstance(status, str):
            try:
                self._tasks.transition(task_id, status)
            except MeshError:
                pass
        if self._task_update_handler is not None:
            try:
                r = self._task_update_handler(payload, env)
                if inspect.isawaitable(r):
                    self._spawn(r)
            except Exception:
                pass
        if status in TERMINAL_STATES:
            sub = self._task_subs.pop(task_id, None)
            if sub is not None:
                self._spawn(sub.unsubscribe())

    async def await_task(self, task_id: str, timeout: float = 300.0) -> dict[str, Any]:
        """Wait until a task reaches a terminal state; returns that respond payload."""
        task = self._tasks.get(task_id)
        if task is not None and task.done:
            for e in reversed(task.history):
                p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
                if p.get("status") == task.state:
                    return p
            return {"status": task.state}
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()

        async def cb(m: Msg) -> None:
            try:
                e = decode(m.data)
            except MeshError:
                return
            p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
            if e.get("task_id") == task_id and p.get("status") in TERMINAL_STATES and not fut.done():
                if task is not None and e.get("from") not in (task.responder, task.requester):
                    return
                if e.get("error"):
                    p = {**p, "error": e["error"]}
                fut.set_result(p)

        sub = await self._nc.subscribe(Subjects.task_update(task_id), cb=cb)
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as exc:
            raise MeshError(ErrorCode.TRANSPORT_TIMEOUT, f"task {task_id} reached no terminal state within {timeout:g}s") from exc
        finally:
            await sub.unsubscribe()

    # ── serving requests (primitive 4: respond) ──────────────────────────

    def on_request(self, offering: str, handler: Handler | None = None, *, defer_after: float | None = None) -> Any:
        """Serve an offering. Usable as a decorator.

        The handler gets ``(input, ctx)`` and returns the output (plain or
        async). Raise :class:`MeshError` to fail with a code, or
        :class:`RejectedError` to decline. With ``defer_after`` (seconds), a
        handler still running then answers ``working`` with a task id at once
        and publishes the final answer as a task update.
        """

        def bind(fn: Handler) -> Handler:
            self._handlers[offering] = fn
            self._handler_opts[offering] = {"defer_after": defer_after}
            return fn

        return bind(handler) if handler is not None else bind

    def on_default(self, handler: Handler) -> Handler:
        """Serve every offering no specific handler takes."""
        self._default_handler = handler
        return handler

    def remove_handler(self, offering: str) -> None:
        self._handlers.pop(offering, None)
        self._handler_opts.pop(offering, None)

    async def _listen_inbox(self) -> None:
        if self._inbox_sub is not None:
            return

        async def cb(m: Msg) -> None:
            self._spawn(self._on_inbound(m.data, m.subject, m.reply, None, False))

        self._inbox_sub = await self._nc.subscribe(Subjects.agent_inbox(self.agent_id), cb=cb)

    def _fresh(self, env: dict[str, Any], buffered: bool) -> bool:
        ts = parse_iso(env.get("ts", ""))
        if ts is None:
            return False
        drift = _now_ms() - ts.timestamp() * 1000
        if drift < -MAX_CLOCK_SKEW_AHEAD_MS:
            return False
        return drift <= (MAX_MAILBOX_AGE_MS if buffered else MAX_CLOCK_SKEW_BEHIND_MS)

    async def _reply_env(self, reply_subject: str | None, request: dict[str, Any], env: dict[str, Any], via_reply: bool) -> None:
        data = encode(env)
        if via_reply:
            if reply_subject and reply_subject.startswith("_INBOX."):
                await self._nc.publish(reply_subject, data)
        else:
            await self._nc.publish(Subjects.agent_inbox(request["from"]), data)
        await self._nc.publish(Subjects.agent_outbox(self.agent_id), data)

    async def _send_respond(self, request: dict[str, Any], payload: dict[str, Any], *, error: dict[str, Any] | None = None,
                            task_id: str | None = None, reply_subject: str | None = None, via_reply: bool = False) -> None:
        env = self._envelope("respond", to=request["from"], in_reply_to=request["id"],
                             task_id=task_id if task_id is not None else request.get("task_id"),
                             trace=child_span(request.get("trace")), payload=payload, error=error)
        await self._reply_env(reply_subject, request, env, via_reply)

    async def _on_inbound(self, data: bytes, subject: str | None, reply: str | None, js_msg: Any, buffered: bool) -> str:
        """Handle one inbound envelope. Returns ``"done"`` or ``"held"`` (the
        inbox keeps a mailbox message until the application acknowledges it)."""
        try:
            env = decode(data)
        except MeshError:
            return "done"
        if env["type"] == "respond":
            return await self._on_respond(env, buffered, js_msg)
        if env["type"] != "request":
            return "done"
        key = f"{env['from']}|{env['id']}"
        if not self._seen_inbox.remember(key):
            held = self._inbox_by_key.get(key)
            if held is not None and js_msg is not None and held._js_msg is None:
                held._js_msg = js_msg
                return "held"
            return "done"
        if "to" in env and env["to"] != self.agent_id:
            return "done"
        if not self._fresh(env, buffered):
            return "done"
        meta = env.get("meta") if isinstance(env.get("meta"), dict) else {}
        if isinstance(meta.get("hops"), int) and meta["hops"] > MAX_HOPS:
            return "done"
        irt = env.get("in_reply_to")
        if isinstance(irt, str) and irt in self._pending and env["from"] == self._pending[irt].agent_id:
            p = self._pending[irt]
            if not p.future.done():
                p.future.set_result(env)
            return "done"
        payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
        if payload.get("offering") is None and isinstance(payload.get("skill"), str):
            payload["offering"] = payload["skill"]
        offering = payload.get("offering") if isinstance(payload.get("offering"), str) else ""
        probe = offering == PROBE_OFFERING
        via_reply = probe
        if "task_id" in env and not is_subject_token(env["task_id"]):
            await self._send_respond(env, {"status": "failed"}, error={"code": "INVALID_ENVELOPE", "message": "task_id must be a single NATS subject token", "retryable": False}, reply_subject=reply, via_reply=via_reply)
            return "done"
        if probe:
            await self._send_respond(env, {"status": "completed", "output": None}, reply_subject=reply, via_reply=True)
            return "done"
        raw_input = payload.get("input")
        size = inbound_text_length(raw_input)
        if self.max_inbound_chars > 0 and size > self.max_inbound_chars:
            msg = f"Inbound message carries {size} characters of sender text, over this agent's {self.max_inbound_chars}-character cap"
            await self._send_respond(env, {"status": "failed"}, error={"code": "CONTEXT_TOO_LARGE", "message": msg, "retryable": False}, reply_subject=reply, via_reply=via_reply)
            self._warn({"code": "inbound_oversize", "message": msg, "from": env["from"], "subject": self.agent_id})
            return "done"
        framed = fence_inbound_input(raw_input, from_=env["from"], trace=env.get("trace")) if self.fence_inbound else raw_input
        handler = self._handlers.get(offering) or self._default_handler
        if handler is None:
            if self.inbox_enabled:
                return await self._hold(InboxMessage(
                    kind="request", id=env["id"], sender=env["from"], envelope=env, input=framed, offering=offering,
                    context_id=env.get("context_id"), received_at=iso_now(), _mesh=self, _js_msg=js_msg,
                ), key, env, reply)
            await self._send_respond(env, {"status": "failed"}, error={"code": "OFFERING_NOT_FOUND", "message": f"No handler registered for offering '{offering}'", "retryable": False}, reply_subject=reply, via_reply=via_reply)
            return "done"
        interactive = (self._manifest or {}).get("interaction") == "interactive"
        if not buffered and not interactive:
            await self._send_respond(env, {"status": "accepted"}, task_id=None, reply_subject=reply, via_reply=via_reply)
        await self._dispatch(handler, offering, framed, env, reply, via_reply, buffered)
        return "done"

    async def _hold(self, item: InboxMessage, key: str, env: dict[str, Any], reply: str | None) -> str:
        if len(self._inbox_items) >= self.inbox_capacity:
            if item.kind == "request":
                await self._send_respond(env, {"status": "failed"}, error={"code": "AGENT_OVERLOADED", "message": "this agent's inbox is full; try again later", "retryable": True})
            return "done"
        async with self._inbox_cond:
            self._inbox_items.append(item)
            self._inbox_by_key[key] = item
            self._inbox_cond.notify_all()
        return "held"

    def _forget_inbox_item(self, item: InboxMessage) -> None:
        key = f"{item.sender}|{item.id}"
        self._inbox_by_key.pop(key, None)
        try:
            self._inbox_items.remove(item)
        except ValueError:
            pass

    async def _on_respond(self, env: dict[str, Any], buffered: bool, js_msg: Any) -> str:
        if "to" in env and env["to"] != self.agent_id:
            return "done"
        if not self._fresh(env, buffered):
            return "done"
        irt = env.get("in_reply_to")
        pend = self._pending.get(irt) if isinstance(irt, str) else None
        key = f"{env['from']}|{env['id']}"
        if pend is not None:
            try:
                self._bind_response(env, pend.request, agent=pend.agent_id)
            except MeshError:
                return "done"
            if not self._seen_inbox.remember(key):
                return "done"
            payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
            if not env.get("error") and payload.get("status") == "accepted":
                pend.accepted = True
                if pend.reset:
                    pend.reset()
                if pend.on_accept:
                    try:
                        pend.on_accept(env)
                    except Exception:
                        pass
                return "done"
            ack = _queued_ack(env)
            if ack is not None:
                if not pend.future.done():
                    pend.future.set_exception(MeshError(ErrorCode.REQUEST_QUEUED, f"The target's node queued this request (inbox {ack['inbox_id']}).",
                                                        retryable=False, details={"queued": True, "inbox_id": ack["inbox_id"], "request_id": pend.request["id"]}))
                return "done"
            if not pend.future.done():
                pend.future.set_result(env)
            return "done"
        # No one is waiting: a late answer, or an answer to send(). Keep it for the inbox.
        if not isinstance(irt, str) or irt not in self._sent or self._sent[irt] != env["from"]:
            # An answer to something this process did not send (or sent before a
            # restart). Still worth keeping when it is addressed to us and signed.
            if "to" not in env:
                return "done"
        payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
        if payload.get("status") == "accepted" or _queued_ack(env) is not None:
            return "done"
        if not self._seen_inbox.remember(key):
            held = self._inbox_by_key.get(key)
            if held is not None and js_msg is not None and held._js_msg is None:
                held._js_msg = js_msg
                return "held"
            return "done"
        if not self.inbox_enabled:
            return "done"
        return await self._hold(InboxMessage(
            kind="reply", id=env["id"], sender=env["from"], envelope=env, in_reply_to=irt,
            context_id=env.get("context_id"), received_at=iso_now(), _mesh=self, _js_msg=js_msg,
        ), key, env, None)

    async def _dispatch(self, handler: Handler, offering: str, input: Any, env: dict[str, Any], reply: str | None, via_reply: bool, buffered: bool) -> None:
        task_id = env.get("task_id") or uuid7()
        ctx = RequestContext(envelope=env, task_id=task_id, offering=offering, sender=env["from"], trace=env.get("trace") or {},
                             budget=env.get("budget"), context_id=env.get("context_id"))
        defer_after = (self._handler_opts.get(offering) or {}).get("defer_after")

        async def run() -> Any:
            with use_trace(env.get("trace")):
                if inspect.iscoroutinefunction(handler) or inspect.iscoroutinefunction(getattr(handler, "__call__", None)):
                    return await handler(input, ctx)
                # A plain function may block (a model call, a LangChain chain):
                # run it on a worker thread so the connection stays responsive.
                # to_thread copies the context, so the trace follows it there.
                return await _maybe_await(await asyncio.to_thread(handler, input, ctx))

        deferred = False
        try:
            job = asyncio.ensure_future(run())
            if defer_after is not None and not buffered:
                done, _ = await asyncio.wait({job}, timeout=defer_after)
                if not done:
                    deferred = True
                    await self._send_respond(env, {"status": "working"}, task_id=task_id, reply_subject=reply, via_reply=via_reply)
            result = await job
            if deferred:
                await self._publish_task_terminal(task_id, env, {"status": "completed", "output": result})
                return
            await self._send_respond(env, {"status": "completed", "output": result}, reply_subject=reply, via_reply=via_reply)
        except RejectedError as exc:
            if deferred:
                await self._publish_task_terminal(task_id, env, {"status": "failed", "note": f"rejected after the work began: {exc.message}"})
                return
            await self._send_respond(env, {"status": "rejected", "message": exc.message}, reply_subject=reply, via_reply=via_reply)
        except Exception as exc:
            err = exc if isinstance(exc, MeshError) else MeshError(ErrorCode.INTERNAL_ERROR, str(exc) or "Handler error")
            if deferred:
                await self._publish_task_terminal(task_id, env, {"status": "failed"}, error=err.to_error_object())
                return
            await self._send_respond(env, {"status": "failed"}, error=err.to_error_object(), reply_subject=reply, via_reply=via_reply)

    async def _publish_task_terminal(self, task_id: str, request: dict[str, Any], payload: dict[str, Any], error: dict[str, Any] | None = None) -> None:
        env = self._envelope("respond", to=request["from"], in_reply_to=request["id"], task_id=task_id,
                             trace=child_span(request.get("trace")), payload=payload, error=error)
        data = encode(env)
        await self._nc.publish(Subjects.task_update(task_id), data)
        await self._nc.publish(Subjects.agent_outbox(self.agent_id), data)

    # ── the inbox ────────────────────────────────────────────────────────

    def inbox(self) -> list[InboxMessage]:
        """What is waiting, oldest first. Does not remove or acknowledge anything."""
        return list(self._inbox_items)

    async def receive(self, timeout: float | None = None) -> InboxMessage | None:
        """The oldest waiting message, waiting up to ``timeout`` seconds for one.

        The message leaves the waiting list but is not acknowledged: call
        ``msg.ack()`` or ``msg.reply(...)`` when it is handled. None on timeout.
        """
        async def take() -> InboxMessage:
            async with self._inbox_cond:
                await self._inbox_cond.wait_for(lambda: bool(self._inbox_items))
                return self._inbox_items.pop(0)

        try:
            return await asyncio.wait_for(take(), timeout) if timeout is not None else await take()
        except asyncio.TimeoutError:
            return None

    async def check_inbox(self, *, drain: bool = True, limit: int = 50) -> list[InboxMessage]:
        """Everything waiting now, taken and acknowledged in one step.

        With ``drain`` (the default), first pulls anything the mesh mailbox held
        while this agent was away. Requests taken this way can still be answered
        with ``msg.reply(...)``.
        """
        if drain and self._manifest is not None:
            await self.drain_mailbox()
        taken = self._inbox_items[:limit]
        for m in taken:
            await m.ack()
        return taken

    async def drain_mailbox(self) -> int:
        """Pull what the mesh mailbox (SPEC 16.4) held for this agent. Returns how
        many messages were read. Handled ones are acknowledged; ones held in the
        inbox are acknowledged when the application acks them."""
        if self._closed:
            return 0
        async with self._drain_lock:
            return await self._drain_once()

    async def _drain_once(self) -> int:
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
        from nats.js.errors import NotFoundError

        stream = Subjects.inbox_stream(self.agent_id)
        durable = Subjects.inbox_durable(self.agent_id)
        js = self._nc.jetstream()
        try:
            info = await js.stream_info(stream)
        except Exception:
            return 0  # no mailbox on this mesh
        bound = info.state.last_seq
        try:
            cinfo = await js.consumer_info(stream, durable)
        except NotFoundError:
            cinfo = await js.add_consumer(stream, ConsumerConfig(
                durable_name=durable, ack_policy=AckPolicy.EXPLICIT, deliver_policy=DeliverPolicy.ALL,
                ack_wait=30, max_deliver=5,
            ))
        except Exception:
            return 0
        budget = (cinfo.num_pending or 0) + (cinfo.num_ack_pending or 0)
        if bound == 0 or budget == 0:
            return 0
        psub = await js.pull_subscribe_bind(durable=durable, stream=stream)
        read = 0
        try:
            remaining = budget
            while remaining > 0 and not self._closed:
                try:
                    msgs = await psub.fetch(min(remaining, MAILBOX_DRAIN_BATCH), timeout=MAILBOX_DRAIN_EXPIRES_S)
                except (NatsTimeoutError, asyncio.TimeoutError):
                    break
                if not msgs:
                    break
                for m in msgs:
                    read += 1
                    seq = m.metadata.sequence.stream if m.metadata else 0
                    if seq > bound:
                        return read
                    try:
                        outcome = await self._on_inbound(m.data, None, None, m, True)
                    except Exception:
                        outcome = "done"
                    if outcome == "done":
                        try:
                            await m.ack()
                        except Exception:
                            pass
                    if seq >= bound:
                        return read
                remaining -= len(msgs)
        finally:
            try:
                await psub.unsubscribe()
            except Exception:
                pass
        return read

    async def _mailbox_loop(self) -> None:
        while not self._closed and self._manifest is not None:
            try:
                await self.drain_mailbox()
            except Exception:
                pass
            await asyncio.sleep(self.mailbox_drain_interval)

    # ── emit and subscribe (primitives 5 and 6) ─────────────────────────

    async def emit(self, topic: str, data: Any) -> None:
        """Fire-and-forget event on ``mesh.event.<topic>``."""
        if self.naming_gate is not None:
            self.naming_gate.require_cached()
        parts = topic.split(".")
        payload = {"domain": parts[0] or topic, "event_type": ".".join(parts[1:]) or topic, "data": data}
        env = self._envelope("emit", payload=payload)
        await self._publish(Subjects.event(topic), env, headers={"Nats-Msg-Id": env["id"]})

    async def subscribe(self, pattern: str, handler: EventHandler) -> Any:
        """Call ``handler(payload, envelope)`` for events matching ``pattern``
        (NATS wildcards ``*`` and ``>`` allowed). Returns the subscription."""

        async def cb(m: Msg) -> None:
            try:
                env = decode(m.data)
            except MeshError:
                return
            if not self._seen_events.remember(f"{env['from']}|{env['id']}|{pattern}") or not self._fresh(env, False):
                return
            payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
            size = inbound_text_length(payload.get("data"))
            if self.max_inbound_chars > 0 and size > self.max_inbound_chars:
                self._warn({"code": "inbound_oversize", "message": f"Event on {m.subject} carries {size} characters", "from": env["from"], "subject": m.subject})
                return
            if self.fence_inbound:
                payload = {**payload, "data": fence_inbound_input(payload.get("data"), from_=env["from"], trace=env.get("trace"))}
            try:
                with use_trace(env.get("trace")):
                    await _maybe_await(handler(payload, env))
            except Exception as exc:
                self._warn({"code": "event_handler_failed", "message": str(exc), "subject": m.subject})

        sub = await self._nc.subscribe(Subjects.event(pattern), cb=cb)
        self._event_subs.append(sub)
        return sub

    # ── lifecycle ────────────────────────────────────────────────────────

    def _start_loop(self, name: str, coro: Awaitable[Any]) -> None:
        for t in list(self._loops):
            if t.get_name() == name and not t.done():
                t.cancel()
                self._loops.remove(t)
        t = asyncio.ensure_future(coro)
        t.set_name(name)
        self._loops.append(t)

    def _stop_loops(self, names: set[str] | None = None) -> None:
        for t in list(self._loops):
            if names is None or t.get_name() in names:
                t.cancel()
                self._loops.remove(t)

    async def close(self) -> None:
        """Stop every loop and close the connection. Does not deregister."""
        if self._closed:
            return
        self._closed = True
        self._stop_loops()
        if self.credential_renewer is not None:
            self.credential_renewer.stop()
        for t in list(self._background):
            t.cancel()
        try:
            if self._owns:
                await self._nc.drain()
        except Exception:
            try:
                await self._nc.close()
            except Exception:
                pass

    async def __aenter__(self) -> "AgentMesh":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    def __repr__(self) -> str:
        return f"AgentMesh(agent_id={self.agent_id!r}, registered={self.registered})"


def _queued_ack(env: dict[str, Any]) -> dict[str, Any] | None:
    if env.get("error"):
        return None
    p = env.get("payload")
    for c in (p, p.get("output") if isinstance(p, dict) else None):
        if isinstance(c, dict) and c.get("queued") is True and isinstance(c.get("inbox_id"), str) and c["inbox_id"]:
            return {"queued": True, "inbox_id": c["inbox_id"]}
    return None


def _pick_servers(servers: list[str]) -> list[str]:
    """nats-py cannot mix TCP and WebSocket servers: prefer TCP (``nats://``,
    ``tls://``) and fall back to WebSocket only when that is all there is."""
    tcp = [s for s in servers if s.startswith(("nats://", "tls://")) or "://" not in s]
    return tcp or servers


async def connect(servers: str | Sequence[str] | None = None, **kwargs: Any) -> AgentMesh:
    """Connect one agent to the mesh. See :meth:`AgentMesh.connect`."""
    return await AgentMesh.connect(servers, **kwargs)
