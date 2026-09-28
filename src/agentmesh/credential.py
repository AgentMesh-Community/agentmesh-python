"""Getting and keeping a connection credential (SPEC.md 4.8).

How an agent gets onto a mesh, in order:

1. Its owner signs up at https://agentmesh.ai and mints an **agent key** in the
   console: a single-use ``am_...`` string, valid for seven days.
2. The agent makes its own identity key (:func:`agentmesh.keys.create_agent_identity`)
   and trades the agent key for a **credential** once, at ``POST /v1/bootstrap``
   (:func:`exchange_agent_key`). The credential is a NATS user JWT bound to a
   separate connection key whose seed comes back with it. The agent's own key
   never leaves the machine.
3. The credential is a **lease** (thirty days at the reference deployment). The
   SDK renews it at two thirds of its own lifetime through
   ``POST /v1/node-credential`` (:class:`CredentialRenewer`). Renewal is plain
   HTTPS authorized by possession of the keys, so it needs no live connection
   and works on a credential that has already lapsed.

There is no signup-free credential: ``POST /v1/guest`` answers 410 since
2026-09-27.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, Optional, Sequence, Union

import httpx

from .attestation import RENEWAL_FRACTION
from .keys import KeyPair, load_seed, save_seed

__all__ = [
    "CREDENTIAL_REQUEST_TIMEOUT_S",
    "MAX_CHECK_INTERVAL_MS",
    "CredentialClaims",
    "RenewalAgent",
    "RenewedCredential",
    "CredentialRefusedError",
    "BootstrapResult",
    "Credentials",
    "decode_credential_claims",
    "credential_renew_at",
    "credential_check_interval_ms",
    "build_credential_request",
    "renew_node_credential",
    "exchange_agent_key",
    "CredentialRenewer",
    "format_creds_file",
    "parse_creds_file",
]

#: One renewal request gets 15 seconds and no retry inside the call. The loop is
#: the retry: roughly hourly through the last third of the credential's life.
CREDENTIAL_REQUEST_TIMEOUT_S = 15.0
#: The renewal loop looks at the clock at least this often (one hour).
MAX_CHECK_INTERVAL_MS = 60 * 60_000
_THIRTY_DAYS_MS = 30 * 24 * 3600_000


@dataclass(frozen=True)
class CredentialClaims:
    sub: Optional[str]
    iat: Optional[float]
    exp: Optional[float]


def _b64url_segment(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * ((4 - len(seg) % 4) % 4))


def decode_credential_claims(jwt: str) -> CredentialClaims | None:
    """Read ``sub``, ``iat`` and ``exp`` from a NATS user JWT, for scheduling.

    Does not verify the JWT: the broker does that at connect time against the
    account chain, which is the only party that can.
    """
    try:
        parts = jwt.split(".")
        if len(parts) != 3:
            return None
        claim = json.loads(_b64url_segment(parts[1]).decode("utf-8"))

        def num(v: Any) -> float | None:
            return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) != float("inf") else None

        return CredentialClaims(
            sub=claim.get("sub") if isinstance(claim.get("sub"), str) else None,
            iat=num(claim.get("iat")),
            exp=num(claim.get("exp")),
        )
    except Exception:
        return None


def credential_renew_at(claims: CredentialClaims | None) -> float | None:
    """When to renew, in ms since the epoch: two thirds into the credential's
    own lifetime. None when there is no deadline (no ``exp``, or unreadable)."""
    if claims is None or claims.exp is None:
        return None
    expires = claims.exp * 1000
    issued = expires - _THIRTY_DAYS_MS if claims.iat is None else claims.iat * 1000
    if expires <= issued:
        return None
    return issued + (expires - issued) * RENEWAL_FRACTION


def credential_check_interval_ms(lifetime_ms: float) -> int:
    """Four checks inside the last third, never less often than hourly."""
    window = lifetime_ms * (1 - RENEWAL_FRACTION)
    return max(1, min(int(window // 4), MAX_CHECK_INTERVAL_MS))


@dataclass
class RenewalAgent:
    """One agent a credential covers, and the means of consenting to be hosted.

    Give ``seed`` or ``sign`` (a function returning a standard-base64 Ed25519
    signature of the message by the agent's key).
    """

    id: str
    seed: Optional[str] = None
    sign: Optional[Callable[[str], str]] = None


Roster = Union[Sequence[RenewalAgent], Callable[[], Sequence[RenewalAgent]]]


def _roster(r: Roster) -> Sequence[RenewalAgent]:
    return r() if callable(r) else r


def build_credential_request(node_seed: str, roster: Roster, now_sec: int | None = None) -> dict[str, Any]:
    """The signed body of ``POST /v1/node-credential``.

    The node proves it wants exactly this roster; each agent proves it consents
    to this node. Byte-identical to the TypeScript SDK's.
    """
    agents = list(_roster(roster))
    if not agents:
        raise ValueError("a node credential must cover at least one agent")
    now_sec = int(time.time()) if now_sec is None else int(now_sec)
    node_kp = KeyPair.from_seed(node_seed)
    node_id = node_kp.public_key
    line = ",".join(sorted(a.id for a in agents))

    def b64(sig: bytes) -> str:
        return base64.b64encode(sig).decode("ascii")

    node_sig = b64(node_kp.sign(f"mesh-node-cred-v1:{now_sec}:{node_id}:{line}".encode("utf-8")))
    signed = []
    for a in agents:
        message = f"mesh-node-agent-v1:{now_sec}:{node_id}:{a.id}"
        if a.sign is not None:
            signed.append({"id": a.id, "sig": a.sign(message)})
            continue
        if a.seed is None:
            raise ValueError(f"agent {a.id[:12]}... supplied neither seed nor sign")
        kp = KeyPair.from_seed(a.seed)
        if kp.public_key != a.id:
            raise ValueError(f"agent seed does not match id {a.id[:12]}...")
        signed.append({"id": a.id, "sig": b64(kp.sign(message.encode("utf-8")))})
    return {"node_id": node_id, "ts": now_sec, "node_sig": node_sig, "agents": signed}


@dataclass
class RenewedCredential:
    jwt: str
    node_id: str
    agents: list[str]
    expires_at: Optional[str]
    #: Agents the mesh left off this credential because they are stopped by the
    #: kill switch (``agent_paused`` or ``agent_terminated``), as
    #: ``{"id": ..., "code": ...}``. Empty when none is.
    stopped: list[dict[str, str]] = field(default_factory=list)


class CredentialRefusedError(RuntimeError):
    """The mesh refused a credential.

    ``code`` is the machine reason when the mesh gave one: ``agent_paused`` and
    ``agent_terminated`` (the kill switch, SPEC 4.12) mean every agent on the
    roster is stopped, and a host should say so and check back later rather
    than retry in a loop; ``agent_unnamed`` is the naming rule.
    """

    def __init__(self, message: str, status: int, code: Optional[str] = None,
                 stopped: Optional[list[dict[str, str]]] = None, retry_after_seconds: Optional[float] = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.stopped = list(stopped or [])
        self.retry_after_seconds = retry_after_seconds

    @property
    def is_stopped(self) -> bool:
        """True when the refusal is the kill switch's: every agent is stopped."""
        return self.code in ("agent_paused", "agent_terminated")


def _client(client: httpx.AsyncClient | None) -> tuple[httpx.AsyncClient, bool]:
    if client is not None:
        return client, False
    return httpx.AsyncClient(), True


async def renew_node_credential(
    api_base: str,
    node_seed: str,
    roster: Roster,
    *,
    client: httpx.AsyncClient | None = None,
    timeout_s: float = CREDENTIAL_REQUEST_TIMEOUT_S,
) -> RenewedCredential:
    """Renew (or first-mint) a node credential. Returns the fresh JWT.

    Persisting it is the caller's job. A refusal (as opposed to a failure) is
    revocation: the agent was retired or its account disabled.
    """
    body = build_credential_request(node_seed, roster)
    http, owned = _client(client)
    try:
        try:
            res = await http.post(f"{api_base.rstrip('/')}/v1/node-credential", json=body, timeout=timeout_s)
        except httpx.TimeoutException as exc:
            raise RuntimeError(f"credential renewal timed out after {timeout_s:g}s: the mesh did not answer") from exc
        try:
            data = res.json()
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        stopped = data.get("stopped") if isinstance(data.get("stopped"), list) else []
        if not res.is_success or not data.get("jwt"):
            code = data.get("code")
            retry = data.get("retry_after_seconds")
            raise CredentialRefusedError(
                data.get("error") or f"credential renewal failed: HTTP {res.status_code}",
                res.status_code,
                code if isinstance(code, str) else None,
                stopped,
                retry if isinstance(retry, (int, float)) and not isinstance(retry, bool) else None,
            )
        return RenewedCredential(
            jwt=data["jwt"],
            node_id=data.get("node_id") or body["node_id"],
            agents=data.get("agents") or [a["id"] for a in body["agents"]],
            expires_at=data.get("expires_at"),
            stopped=stopped,
        )
    finally:
        if owned:
            await http.aclose()


# ── bootstrap: trade an agent key for a credential, once ────────────────────


@dataclass
class BootstrapResult:
    """What ``POST /v1/bootstrap`` returns. Persist it: the agent key is burned."""

    jwt: str
    seed: str  # the CONNECTION key's seed, not the agent's
    endpoints: list[str]
    label: Optional[str] = None
    account_email: Optional[str] = None
    handle: Optional[str] = None
    expires_at: Optional[str] = None
    renew_url: Optional[str] = None
    naming: Optional[dict[str, Any]] = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:  # never print the seed or the JWT
        return (
            f"BootstrapResult(label={self.label!r}, account_email={self.account_email!r}, "
            f"handle={self.handle!r}, expires_at={self.expires_at!r}, endpoints={self.endpoints!r})"
        )


async def exchange_agent_key(
    api_base: str,
    agent_key: str,
    agent_public_key: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> BootstrapResult:
    """Trade a console-minted agent key (``am_...``) for a durable credential.

    Single use: the key is burned by this call, so save what comes back
    (:meth:`Credentials.save`).
    """
    http, owned = _client(client)
    try:
        res = await http.post(
            f"{api_base.rstrip('/')}/v1/bootstrap",
            json={"token": agent_key, "agent_id": agent_public_key},
            timeout=30.0,
        )
        try:
            data = res.json()
        except ValueError:
            data = {}
        if not res.is_success or not isinstance(data, dict):
            err = data.get("error") if isinstance(data, dict) else None
            raise RuntimeError(err or f"bootstrap failed: HTTP {res.status_code}")
        mesh = data.get("mesh") or {}
        return BootstrapResult(
            jwt=data["jwt"],
            seed=data["seed"],
            endpoints=list(mesh.get("endpoints") or []),
            label=data.get("label"),
            account_email=data.get("account_email"),
            handle=data.get("handle"),
            expires_at=data.get("expires_at"),
            renew_url=data.get("renew_url"),
            naming=data.get("naming"),
            raw=data,
        )
    finally:
        if owned:
            await http.aclose()


# ── the .creds file and a small credential bundle ───────────────────────────


def format_creds_file(jwt: str, seed: str) -> str:
    """The standard NATS ``.creds`` text for a JWT and its seed."""
    return (
        "-----BEGIN NATS USER JWT-----\n"
        f"{jwt}\n"
        "------END NATS USER JWT------\n\n"
        "************************* IMPORTANT *************************\n"
        "NKEY Seed printed below can be used to sign and prove identity.\n"
        "NKEYs are sensitive and should be treated as secrets.\n\n"
        "-----BEGIN USER NKEY SEED-----\n"
        f"{seed}\n"
        "------END USER NKEY SEED------\n\n"
        "*************************************************************\n"
    )


def parse_creds_file(text: str) -> tuple[str, str]:
    """``(jwt, seed)`` from a NATS ``.creds`` file."""
    jwt = seed = None
    lines = [ln.strip() for ln in text.splitlines()]
    for i, ln in enumerate(lines):
        if "BEGIN NATS USER JWT" in ln and i + 1 < len(lines):
            jwt = lines[i + 1]
        if "BEGIN USER NKEY SEED" in ln and i + 1 < len(lines):
            seed = lines[i + 1]
    if not jwt or not seed:
        raise ValueError("not a NATS .creds file: it needs a JWT block and a seed block")
    return jwt, seed


@dataclass
class Credentials:
    """Everything an agent needs to connect, and a place to keep it.

    - ``agent_seed``: the agent's identity key. It signs every envelope.
    - ``jwt`` and ``connection_seed``: the credential and the key it is bound
      to. It authenticates the connection. After bootstrap the two keys differ.
    - ``servers``: the mesh's NATS endpoints.
    - ``api_base``: the control plane, where renewal happens.

    :meth:`save` writes a folder readable by the owner only: ``agent.seed`` and
    ``mesh.creds`` with mode 0600, and a ``mesh.json`` holding nothing secret.
    """

    agent_seed: str
    jwt: Optional[str] = None
    connection_seed: Optional[str] = None
    servers: list[str] = field(default_factory=list)
    api_base: Optional[str] = None
    handle: Optional[str] = None
    expires_at: Optional[str] = None

    def __repr__(self) -> str:
        return (
            f"Credentials(agent={KeyPair.from_seed(self.agent_seed).public_key!r}, "
            f"servers={self.servers!r}, api_base={self.api_base!r}, handle={self.handle!r}, "
            f"expires_at={self.expires_at!r})"
        )

    @property
    def agent_id(self) -> str:
        return KeyPair.from_seed(self.agent_seed).public_key

    @classmethod
    def from_bootstrap(cls, agent_seed: str, result: BootstrapResult, api_base: str) -> "Credentials":
        return cls(
            agent_seed=agent_seed,
            jwt=result.jwt,
            connection_seed=result.seed,
            servers=list(result.endpoints),
            api_base=api_base,
            handle=result.handle,
            expires_at=result.expires_at,
        )

    def save(self, folder: str | Path) -> Path:
        d = Path(folder).expanduser()
        d.mkdir(parents=True, exist_ok=True)
        save_seed(d / "agent.seed", self.agent_seed)
        if self.jwt and self.connection_seed:
            _write_private(d / "mesh.creds", format_creds_file(self.jwt, self.connection_seed))
        meta = {
            "servers": self.servers,
            "api_base": self.api_base,
            "handle": self.handle,
            "expires_at": self.expires_at,
        }
        (d / "mesh.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        return d

    @classmethod
    def load(cls, folder: str | Path) -> "Credentials":
        d = Path(folder).expanduser()
        agent_seed = load_seed(d / "agent.seed")
        jwt = conn_seed = None
        if (d / "mesh.creds").exists():
            jwt, conn_seed = parse_creds_file((d / "mesh.creds").read_text(encoding="utf-8"))
        meta: dict[str, Any] = {}
        if (d / "mesh.json").exists():
            meta = json.loads((d / "mesh.json").read_text(encoding="utf-8"))
        return cls(
            agent_seed=agent_seed,
            jwt=jwt,
            connection_seed=conn_seed,
            servers=list(meta.get("servers") or []),
            api_base=meta.get("api_base"),
            handle=meta.get("handle"),
            expires_at=meta.get("expires_at"),
        )

    def update_jwt(self, folder: str | Path, jwt: str, expires_at: str | None) -> None:
        """Persist a renewed credential (the key it is bound to does not change)."""
        self.jwt = jwt
        self.expires_at = expires_at
        self.save(folder)


def _write_private(path: Path, text: str) -> None:
    import os
    import sys

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    if sys.platform != "win32":
        os.chmod(path, 0o600)


# ── the renewal loop ────────────────────────────────────────────────────────

Warning = dict[str, Any]


class CredentialRenewer:
    """Keeps one node credential alive: renew at two thirds of its lifetime.

    The loop compares the wall clock against a stored deadline on a periodic
    tick instead of sleeping until the deadline, so a laptop that slept through
    the deadline renews on its first tick after waking. A failed attempt leaves
    the deadline in place and the next tick retries. Call
    :meth:`renew_if_expiring` before connecting to heal a credential that lapsed
    while the host was off.
    """

    def __init__(
        self,
        *,
        api_base: str,
        jwt: str,
        node_seed: str,
        agents: Roster,
        on_renewed: Callable[[RenewedCredential], Union[None, Awaitable[None]]] | None = None,
        on_warning: Callable[[Warning], None] | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] | None = None,
    ):
        self._api_base = api_base
        self._node_seed = node_seed
        self._agents = agents
        self._on_renewed = on_renewed
        self._on_warning = on_warning
        self._client = client
        self._clock = clock or (lambda: time.time() * 1000)
        self._jwt = jwt
        self._claims = decode_credential_claims(jwt)
        self._renew_at = credential_renew_at(self._claims)
        self._last_error: str | None = None
        self._in_flight = False
        self._task: asyncio.Task[None] | None = None

    @property
    def credential(self) -> str:
        return self._jwt

    @property
    def renew_at_ms(self) -> float | None:
        return self._renew_at

    def status(self, now_ms: float | None = None) -> dict[str, Any]:
        now_ms = self._clock() if now_ms is None else now_ms
        exp_ms = None if self._claims is None or self._claims.exp is None else self._claims.exp * 1000

        def iso(ms: float | None) -> str | None:
            if ms is None:
                return None
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(ms % 1000):03d}Z"

        return {
            "expires_at": iso(exp_ms),
            "renew_at": iso(self._renew_at),
            "expired": exp_ms is not None and exp_ms <= now_ms,
            "last_error": self._last_error,
        }

    async def renew(self) -> RenewedCredential:
        """Renew now. Raises on failure. Persists (via ``on_renewed``) before adopting."""
        fresh = await renew_node_credential(self._api_base, self._node_seed, self._agents, client=self._client)
        if self._on_renewed is not None:
            result = self._on_renewed(fresh)
            if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
                await result  # type: ignore[misc]
        self._jwt = fresh.jwt
        self._claims = decode_credential_claims(fresh.jwt)
        self._renew_at = credential_renew_at(self._claims)
        self._last_error = None
        return fresh

    async def renew_if_due(self, now_ms: float | None = None) -> bool:
        """Renew if the deadline has passed. Never raises; True if it renewed."""
        now_ms = self._clock() if now_ms is None else now_ms
        if self._renew_at is None or now_ms < self._renew_at or self._in_flight:
            return False
        self._in_flight = True
        try:
            await self.renew()
            return True
        except Exception as exc:  # the loop has no caller to raise to
            self._last_error = str(exc)
            s = self.status(now_ms)
            sub = self._claims.sub if self._claims else None
            if self._on_warning is not None:
                self._on_warning(
                    {
                        "code": "credential_renewal_failed",
                        "message": (
                            f"could not renew the node credential for {(sub or 'this node')[:12]}...: {exc}. "
                            f"It expires {s['expires_at'] or 'at an unknown time'}; after that this node cannot "
                            "open a connection to the mesh until it renews. Renewal does not need a working "
                            "connection, so it keeps retrying."
                        ),
                        "subject": sub,
                    }
                )
            return False
        finally:
            self._in_flight = False

    async def renew_if_expiring(self) -> bool:
        """The startup call: renew a credential past its deadline or already expired."""
        return await self.renew_if_due()

    def start(self) -> None:
        """Start the periodic check on the running event loop. Idempotent."""
        self.stop()
        c = self._claims
        lifetime = (c.exp - c.iat) * 1000 if c and c.exp is not None and c.iat is not None else _THIRTY_DAYS_MS
        interval = credential_check_interval_ms(lifetime) / 1000

        async def loop() -> None:
            while True:
                await asyncio.sleep(interval)
                await self.renew_if_due()

        self._task = asyncio.get_running_loop().create_task(loop())

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None


def roster_for(agent_seeds: Iterable[str]) -> list[RenewalAgent]:
    """A renewal roster from agent seeds."""
    return [RenewalAgent(id=KeyPair.from_seed(s).public_key, seed=s) for s in agent_seeds]
