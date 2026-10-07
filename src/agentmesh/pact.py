"""PACT 1.0 for agent builders.

PACT (https://openpactprotocol.org) lets a person's own agent act for them at a
business: the personal agent proves which platform it is, and acts only with
the permissions the person gave by signing in at the business itself. This
module is the same set of helpers as the TypeScript SDK's ``pact`` namespace
and the Rust SDK's ``pact`` module.

For an agent that serves a business on AgentMesh. The A2A gateway hands each
PACT turn to the agent on the envelope's ``meta["pact"]`` (and, for a packaged
agent, in its job's context bag). Under a person's permission the turn carries
a delegation token. Check it with :func:`check_delegation` (or
:func:`check_delegation_fetching_keys`) before acting on anybody's account, then
answer with :func:`pact_report` (what was used and done, which the gateway signs
into the receipt) or :func:`pact_needs_permission` (what is missing, which the
gateway turns into the step-up)::

    turn = pact_turn_from_meta(ctx.envelope.get("meta")) or {}
    who = await check_delegation_fetching_keys(
        (turn.get("delegation") or {}).get("token"), pa_issuer=turn.get("pa", ""))
    if missing_scopes(who, ["orders:read"]):
        return pact_needs_permission("I need your permission to see your orders.", ["orders:read"])
    return pact_report("Your orders: ...", ["orders:read"], [("lookup_orders", None)])

For anyone who is their own personal-agent platform: :func:`sign_pa_jwt` makes
the per-request JWT, :func:`send_pact_message` talks to a business and reads its
answer, and :func:`verify_receipt` checks the business's signed receipt.

ES256 only: AgentMesh's gateway signs with ES256, and a token in any other
algorithm is refused here rather than half-checked. The signing and checking
need the ``cryptography`` package: ``pip install "agentmesh[pact]"``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence, Union
from urllib.parse import urlsplit

from .canonical import canonical_json

__all__ = [
    "PACT_TURN_SCHEMA",
    "AGENTMESH_GATEWAYS",
    "MAX_SKEW_S",
    "PA_JWT_LIFE_S",
    "MAX_PA_JWT_LIFE_S",
    "DELEGATION_HEADER",
    "CheckedDelegation",
    "PactReply",
    "PactSendError",
    "decode_jwt",
    "verify_es256",
    "check_delegation",
    "check_delegation_fetching_keys",
    "fetch_gateway_keys",
    "missing_scopes",
    "pact_report",
    "pact_needs_permission",
    "report_text",
    "args_hash",
    "sign_pa_jwt",
    "generate_es256_key",
    "pact_turn_from_meta",
    "pact_turn_from_bag",
    "send_pact_message",
    "read_pact_answer",
    "verify_receipt",
]

#: The context bag schema of a PACT turn.
PACT_TURN_SCHEMA = "https://schemas.agentmesh.ai/pact-delegation/v1"
#: AgentMesh's A2A gateways, production and dev: where a token is trusted from by default.
AGENTMESH_GATEWAYS: tuple[str, ...] = ("https://a2a.agentmesh.ai", "https://a2a.dev.agentmesh.ai")
#: Clock skew allowed on ``exp`` (PACT 3.2).
MAX_SKEW_S = 30
#: A personal-agent JWT's life by default, and the most PACT allows (3.2).
PA_JWT_LIFE_S = 120
MAX_PA_JWT_LIFE_S = 300
#: The header a delegation token rides in (PACT 5.5).
DELEGATION_HEADER = "X-A2A-User-Delegation"

_MISSING_SCOPES = "pact.missingScopes"
_VERIFICATION_URI = "pact.verificationUriComplete"
_RECEIPT = "pact.receipt"

Jwk = Mapping[str, Any]
Keys = Union[Sequence[Jwk], Mapping[str, Any]]


# ── encoding and keys ────────────────────────────────────────────────────────


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes | None:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*=*", text):
        return None
    try:
        return base64.urlsafe_b64decode(text.rstrip("=") + "=" * (-len(text.rstrip("=")) % 4))
    except (ValueError, TypeError):
        return None


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    except ImportError as err:  # pragma: no cover - the message is the point
        raise ImportError('PACT signing and checking need the "cryptography" package: pip install "agentmesh[pact]"') from err
    return InvalidSignature, hashes, ec, decode_dss_signature, encode_dss_signature


def _key_list(keys: Keys | None) -> list[Jwk]:
    if keys is None:
        return []
    if isinstance(keys, Mapping):
        found = keys.get("keys")
        return [k for k in found if isinstance(k, Mapping)] if isinstance(found, list) else []
    return [k for k in keys if isinstance(k, Mapping)]


def _public_key(jwk: Jwk):
    _, _, ec, _, _ = _crypto()
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return None
    x, y = _unb64(jwk.get("x", "")), _unb64(jwk.get("y", ""))
    if not x or not y or len(x) != 32 or len(y) != 32:
        return None
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError:
        return None


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    """A compact JWS's header and claims, decoded and unchecked, or None."""
    if not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return None
    raw_h, raw_c = _unb64(parts[0]), _unb64(parts[1])
    if raw_h is None or raw_c is None:
        return None
    try:
        header, claims = json.loads(raw_h), json.loads(raw_c)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims


def verify_es256(token: str, keys: Keys) -> bool:
    """Whether an ES256 compact JWS verifies against one of ``keys`` (by ``kid`` when it names one)."""
    decoded = decode_jwt(token)
    if not decoded or decoded[0].get("alg") != "ES256":
        return False
    InvalidSignature, hashes, ec, _, encode_dss_signature = _crypto()
    signing_input, _, sig_text = token.rpartition(".")
    sig = _unb64(sig_text)
    if not sig or len(sig) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    kid = decoded[0].get("kid")
    for jwk in _key_list(keys):
        if kid is not None and jwk.get("kid") != kid:
            continue
        key = _public_key(jwk)
        if key is None:
            continue
        try:
            key.verify(der, signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            continue
    return False


# ── the business's side: checking a delegation ───────────────────────────────


@dataclass(frozen=True)
class CheckedDelegation:
    """A delegation the agent checked: who the person is at the business, and what they allowed."""

    person: str
    scopes: tuple[str, ...]
    grant_id: str | None
    interface_url: str
    expires_at: int


def _parse_scope(scope: str) -> tuple[str, ...]:
    out: list[str] = []
    for s in scope.split():
        if s not in out:
            out.append(s)
    return tuple(out)


def _interface_of(claims: Mapping[str, Any], interface_url: str | None, gateways: Iterable[str]) -> str | None:
    """The Brand interface the token is addressed to, when it is one this agent accepts."""
    aud = claims.get("aud")
    if not isinstance(aud, str):
        return None
    try:
        u = urlsplit(aud)
    except ValueError:
        return None
    if u.scheme not in ("https", "http") or not u.netloc:
        return None
    origin = f"{u.scheme}://{u.netloc}"
    iface = f"{origin}{u.path}".rstrip("/")
    if interface_url is not None:
        return iface if iface == interface_url.rstrip("/") else None
    if origin not in tuple(gateways) or not re.fullmatch(r"/a2a/[^/]+", u.path):
        return None
    return iface


def check_delegation(
    token: str | None,
    *,
    pa_issuer: str,
    keys: Keys,
    interface_url: str | None = None,
    gateways: Iterable[str] = AGENTMESH_GATEWAYS,
    now: int | None = None,
) -> CheckedDelegation | None:
    """Check a delegation token before acting on anybody's account (PACT 5.4, 5.5).

    It must be an access token (``typ: at+jwt``) in ES256, addressed to this
    Brand's interface (exactly ``interface_url`` when given, else an interface
    on one of ``gateways``), issued by that interface's authorization server,
    for the personal agent that sent the turn (``client_id`` equal to
    ``pa_issuer``, from ``meta["pact"]["pa"]``), not expired, and signed by one
    of ``keys`` (the Brand's JWKS from ``{interface}/oauth/jwks.json``).
    None when anything fails; nothing is raised.
    """
    decoded = decode_jwt(token) if token else None
    if not decoded:
        return None
    header, c = decoded
    if header.get("alg") != "ES256" or header.get("typ") != "at+jwt":
        return None
    iface = _interface_of(c, interface_url, gateways)
    if iface is None:
        return None
    if c.get("iss") != f"{iface}/oauth" or c.get("client_id") != pa_issuer:
        return None
    t = int(time.time()) if now is None else now
    exp = c.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool) or exp < t - MAX_SKEW_S:
        return None
    sub, scope = c.get("sub"), c.get("scope")
    if not isinstance(sub, str) or not sub or not isinstance(scope, str):
        return None
    if not verify_es256(token, keys):
        return None
    grant = c.get("grant_id")
    return CheckedDelegation(person=sub, scopes=_parse_scope(scope), grant_id=grant if isinstance(grant, str) else None, interface_url=iface, expires_at=exp)


async def fetch_gateway_keys(interface_url: str, *, client: Any = None) -> list[dict] | None:
    """A Brand's keys from ``{interface}/oauth/jwks.json``, or None. ``client`` is an ``httpx.AsyncClient``."""
    import httpx

    url = f"{interface_url.rstrip('/')}/oauth/jwks.json"
    own = client is None
    http = client or httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    try:
        res = await http.get(url, headers={"Accept": "application/json"})
        if res.status_code != 200:
            return None
        body = res.json()
    except (httpx.HTTPError, ValueError):
        return None
    finally:
        if own:
            await http.aclose()
    keys = body.get("keys") if isinstance(body, dict) else None
    return [k for k in keys if isinstance(k, dict)] if isinstance(keys, list) else None


async def check_delegation_fetching_keys(
    token: str | None,
    *,
    pa_issuer: str,
    interface_url: str | None = None,
    gateways: Iterable[str] = AGENTMESH_GATEWAYS,
    now: int | None = None,
    client: Any = None,
) -> CheckedDelegation | None:
    """:func:`check_delegation`, reading the Brand's keys first.

    The keys are fetched only from an interface the token may be addressed to
    (``interface_url``, or one on ``gateways``), never from wherever the token
    points.
    """
    decoded = decode_jwt(token) if token else None
    if not decoded:
        return None
    iface = _interface_of(decoded[1], interface_url, gateways)
    if iface is None:
        return None
    keys = await fetch_gateway_keys(iface, client=client)
    if not keys:
        return None
    return check_delegation(token, pa_issuer=pa_issuer, keys=keys, interface_url=interface_url, gateways=gateways, now=now)


def missing_scopes(held: CheckedDelegation | None, needed: Iterable[str]) -> list[str]:
    """The scopes a turn needs and the person has not allowed."""
    have = set(held.scopes) if held else set()
    out: list[str] = []
    for s in needed:
        if s not in have and s not in out:
            out.append(s)
    return out


# ── the business's side: answering ───────────────────────────────────────────


def _unique(items: Iterable[str]) -> list[str]:
    out: list[str] = []
    for s in items:
        if s not in out:
            out.append(s)
    return out


def pact_report(text: str, scopes_used: Iterable[str], actions: Iterable[Any] = ()) -> dict:
    """The output of a turn done on the person's account: the words, and what the receipt needs.

    Each action is ``(tool, args_hash_or_None)``, a tool name, or a mapping
    with ``tool`` and optionally ``argsHash``.
    """
    out_actions: list[dict] = []
    for a in actions:
        if isinstance(a, str):
            tool, h = a, None
        elif isinstance(a, Mapping):
            tool, h = a.get("tool"), a.get("argsHash")
        else:
            tool, h = a[0], (a[1] if len(a) > 1 else None)
        out_actions.append({"tool": str(tool), **({"argsHash": h} if h else {})})
    return {"text": text, "pact": {"scopes_used": _unique(scopes_used), "actions": out_actions}}


def pact_needs_permission(text: str, missing: Iterable[str]) -> dict:
    """The output of a turn that needs more permission: the gateway answers it with the step-up task."""
    return {"text": text, "pact": {"missing_scopes": _unique(missing)}}


def report_text(report: Mapping[str, Any]) -> str:
    """The same object as JSON text, for an agent whose reply is text (a packaged agent)."""
    return json.dumps(report, separators=(",", ":"), ensure_ascii=False)


def args_hash(args: Any) -> str:
    """A receipt's ``argsHash``: base64url SHA-256 of the arguments as canonical JSON, or of a string as itself."""
    text = args if isinstance(args, str) else canonical_json(args)
    return _b64(hashlib.sha256(text.encode("utf-8")).digest())


# ── turns ────────────────────────────────────────────────────────────────────


def _as_turn(v: Any) -> dict | None:
    return v if isinstance(v, dict) and isinstance(v.get("pa"), str) and isinstance(v.get("user"), str) else None


def pact_turn_from_meta(meta: Mapping[str, Any] | None) -> dict | None:
    """The PACT turn on an envelope's meta (``meta["pact"]``), or None for a message that did not come through the gateway.

    The turn has ``pa`` (the personal-agent platform), ``user`` (the person's
    id there, naming nobody), ``context`` and, only under the person's
    permission, ``delegation`` (``grant_id``, ``user``, ``scopes``, ``token``).
    Nothing in ``delegation`` is to be trusted before :func:`check_delegation`.
    """
    return _as_turn((meta or {}).get("pact")) if isinstance(meta, Mapping) else None


def pact_turn_from_bag(bag: Mapping[str, Any] | None, read: Callable[[str], str]) -> dict | None:
    """The PACT turn in a job's context bag: ``bag`` is bag.json as the adapter wrote it, ``read`` reads one of its files."""
    entries = (bag or {}).get("entries") if isinstance(bag, Mapping) else None
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or e.get("schema") != PACT_TURN_SCHEMA or not isinstance(e.get("file"), str) or e.get("why"):
            continue
        if ".." in e["file"]:
            return None
        try:
            return _as_turn(json.loads(read(e["file"])))
        except (OSError, ValueError):
            return None
    return None


# ── the personal agent's side ────────────────────────────────────────────────


def _private_key(private_jwk: Jwk):
    _, _, ec, _, _ = _crypto()
    d = _unb64(private_jwk.get("d", ""))
    if not d or len(d) != 32 or private_jwk.get("crv") != "P-256":
        raise ValueError("a private P-256 JWK (kty EC, crv P-256, d, x, y) is needed")
    return ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())


def _sign_es256(payload: Mapping[str, Any], private_jwk: Jwk, typ: str) -> str:
    _, hashes, ec, decode_dss_signature, _ = _crypto()
    header: dict[str, Any] = {"alg": "ES256", "typ": typ}
    if private_jwk.get("kid"):
        header["kid"] = private_jwk["kid"]
    signing_input = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}.{_b64(json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))}"
    r, s = decode_dss_signature(_private_key(private_jwk).sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def sign_pa_jwt(
    private_jwk: Jwk,
    *,
    iss: str,
    sub: str,
    aud: str,
    now: int | None = None,
    life_seconds: int = PA_JWT_LIFE_S,
    jti: str | None = None,
) -> str:
    """A personal-agent JWT (PACT 3.2), ES256: ``iss``, ``sub``, ``aud``, ``iat`` and ``exp`` (120 s by default, never more than 300).

    ``iss`` is your platform's registered issuer, ``sub`` the person's stable
    opaque id (no personal data), ``aud`` the audience the Provider assigned.
    Make a fresh one for every request.
    """
    iat = int(time.time()) if now is None else int(now)
    claims: dict[str, Any] = {"iss": iss, "sub": sub, "aud": aud, "iat": iat, "exp": iat + min(life_seconds, MAX_PA_JWT_LIFE_S)}
    if jti:
        claims["jti"] = jti
    return _sign_es256(claims, private_jwk, "JWT")


def generate_es256_key() -> tuple[dict, dict]:
    """A new P-256 key as ``(private_jwk, public_jwk)``, its ``kid`` the RFC 7638 thumbprint. Publish the public one in your JWKS."""
    _, _, ec, _, _ = _crypto()
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.private_numbers()
    x = _b64(nums.public_numbers.x.to_bytes(32, "big"))
    y = _b64(nums.public_numbers.y.to_bytes(32, "big"))
    kid = _b64(hashlib.sha256(json.dumps({"crv": "P-256", "kty": "EC", "x": x, "y": y}, separators=(",", ":")).encode()).digest())
    public = {"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "alg": "ES256", "use": "sig"}
    return {**public, "d": _b64(nums.private_value.to_bytes(32, "big"))}, public


class PactSendError(Exception):
    """A business's provider refused or failed a message.

    ``reason`` is the A2A error's reason when the answer was an error envelope
    (PACT 6), read by its reason, never by status. ``delegation_rejected`` is
    true on a 401 that refused the delegation token: ask the person again.
    """

    def __init__(self, status: int, message: str, *, reason: str | None = None, retry_after: str | None = None, delegation_rejected: bool = False):
        super().__init__(message)
        self.status = status
        self.reason = reason
        self.retry_after = retry_after
        self.delegation_rejected = delegation_rejected


@dataclass
class PactReply:
    """A business's answer to one message.

    ``kind`` is ``"message"`` (its agent answered; ``receipt`` is set when it
    acted on the person's account) or ``"auth_required"`` (it needs the
    person's permission first: show them ``link`` to open themselves, never
    open, fetch or frame it for them, then send again).
    """

    kind: str
    text: str
    context_id: str | None
    receipt: dict | None = None
    missing_scopes: list[str] = field(default_factory=list)
    link: str | None = None
    task_id: str | None = None
    raw: dict = field(default_factory=dict)


def _text_of(parts: Any) -> str:
    return "\n".join(p["text"] for p in parts or [] if isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"])


def read_pact_answer(body: Mapping[str, Any]) -> PactReply:
    """A ``message:send`` answer's JSON as a :class:`PactReply`. Raises PactSendError for anything else."""
    task = body.get("task") if isinstance(body, Mapping) else None
    if isinstance(task, dict):
        status = task.get("status") or {}
        if status.get("state") != "TASK_STATE_AUTH_REQUIRED":
            raise PactSendError(200, f"unexpected task state {status.get('state')}")
        meta = task.get("metadata") or {}
        missing = [s for s in meta.get(_MISSING_SCOPES, []) if isinstance(s, str)] if isinstance(meta.get(_MISSING_SCOPES), list) else []
        link = meta.get(_VERIFICATION_URI)
        return PactReply(
            kind="auth_required",
            text=_text_of((status.get("message") or {}).get("parts")),
            context_id=task.get("contextId") if isinstance(task.get("contextId"), str) else None,
            missing_scopes=missing,
            link=link if isinstance(link, str) else None,
            task_id=str(task.get("id") or ""),
            raw=dict(body),
        )
    message = body.get("message") if isinstance(body, Mapping) else None
    if not isinstance(message, dict) or message.get("role") != "ROLE_AGENT":
        raise PactSendError(200, "the reply was not a message from the business's agent")
    receipt = (message.get("metadata") or {}).get(_RECEIPT)
    return PactReply(
        kind="message",
        text=_text_of(message.get("parts")),
        context_id=message.get("contextId") if isinstance(message.get("contextId"), str) else None,
        receipt=receipt if isinstance(receipt, dict) else None,
        raw=dict(body),
    )


async def send_pact_message(
    interface_url: str,
    text: str,
    *,
    pa_jwt: str | Callable[[], str],
    delegation_token: str | None = None,
    context_id: str | None = None,
    message_id: str | None = None,
    client: Any = None,
) -> PactReply:
    """Send one message to a business (PACT 4, 5.5) and read its answer.

    ``interface_url`` is the card's interface (``supportedInterfaces[].url``).
    ``pa_jwt`` is a fresh personal-agent JWT, or a function that signs one.
    ``delegation_token``, when the person gave permission, rides in
    X-A2A-User-Delegation. Keep ``reply.context_id`` and pass it back to carry
    on the same conversation. ``client`` is an ``httpx.AsyncClient``.
    """
    import httpx

    token = pa_jwt() if callable(pa_jwt) else pa_jwt
    message: dict[str, Any] = {"messageId": message_id or str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}
    if context_id:
        message["contextId"] = context_id
    headers = {"Authorization": f"Bearer {token}", "A2A-Version": "1.0", "Content-Type": "application/json", "Accept": "application/json"}
    if delegation_token:
        headers[DELEGATION_HEADER] = f"Bearer {delegation_token}"
    own = client is None
    http = client or httpx.AsyncClient(timeout=60.0, follow_redirects=False)
    try:
        res = await http.post(f"{interface_url.rstrip('/')}/message:send", headers=headers, content=json.dumps({"message": message}))
    except httpx.HTTPError as err:
        raise PactSendError(0, f"the business's provider could not be reached: {type(err).__name__}") from err
    finally:
        if own:
            await http.aclose()
    try:
        body = res.json() if res.content else None
    except ValueError:
        body = None
    if res.status_code != 200:
        details = ((body or {}).get("error") or {}).get("details") if isinstance(body, dict) else None
        reason = details[0].get("reason") if isinstance(details, list) and details and isinstance(details[0], dict) else None
        if isinstance(reason, str):
            raise PactSendError(res.status_code, str(((body or {}).get("error") or {}).get("message") or reason), reason=reason)
        challenge = res.headers.get("www-authenticate", "")
        raise PactSendError(
            res.status_code,
            f"the business's provider answered {res.status_code}",
            retry_after=res.headers.get("retry-after"),
            delegation_rejected=res.status_code == 401 and bool(delegation_token) and "invalid_token" in challenge,
        )
    if not isinstance(body, dict):
        raise PactSendError(200, "the answer was not a JSON object")
    return read_pact_answer(body)


def verify_receipt(receipt: Mapping[str, Any] | None, keys: Keys, expected: Mapping[str, str] | None = None) -> tuple[bool, str | None]:
    """A personal agent's check of a receipt (PACT 5.6, SHOULD): ``(True, None)`` or ``(False, why)``.

    The JWS must verify against the business's keys, its payload must equal
    ``claims``, and any ``expected`` values (``grantId``, ``user``, ``pa``,
    ``brand``) must match. ``why`` is ``malformed``, ``signature``,
    ``claims_differ`` or ``expected``.
    """
    if not isinstance(receipt, Mapping) or not isinstance(receipt.get("jws"), str) or not isinstance(receipt.get("claims"), Mapping):
        return False, "malformed"
    jws = receipt["jws"]
    parts = jws.split(".")
    if len(parts) != 3:
        return False, "malformed"
    if not verify_es256(jws, keys):
        return False, "signature"
    raw = _unb64(parts[1])
    try:
        payload = json.loads(raw) if raw is not None else None
    except (ValueError, UnicodeDecodeError):
        payload = None
    if payload is None:
        return False, "malformed"
    if canonical_json(payload) != canonical_json(dict(receipt["claims"])):
        return False, "claims_differ"
    for k, v in (expected or {}).items():
        if v is not None and receipt["claims"].get(k) != v:
            return False, "expected"
    return True, None
