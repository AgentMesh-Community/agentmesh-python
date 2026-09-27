"""The envelope: build, sign, verify, encode, decode (SPEC.md 5).

Every message on the mesh is one JSON envelope, and every envelope is signed by
the agent named in ``from``. The signature covers the tagged bytes

    agentmesh-envelope-v1 + LF + canonical JSON of the envelope without "sig"

and is written as unpadded base64url in ``sig`` (SPEC 5.3). Receivers verify it
against ``from``, which is what makes ``from`` trustworthy when one connection
carries many agents.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Literal

from .canonical import canonical_bytes, canonical_json, parse_json
from .errors import ErrorCode, MeshError
from .keys import KeyPair, b64url_decode, b64url_encode, verify_signature
from .trace import child_span, current_trace, new_trace_context

__all__ = [
    "PROTOCOL_VERSION",
    "ENVELOPE_SIG_PREFIX",
    "PrimitiveType",
    "uuid7",
    "iso_now",
    "create_envelope",
    "sign_envelope",
    "verify_envelope",
    "signed_envelope_bytes",
    "canonical_envelope_bytes",
    "validate_envelope",
    "encode",
    "decode",
    "decode_unverified",
    "sign_tagged",
    "verify_tagged",
]

PROTOCOL_VERSION = "0.3.0"
ENVELOPE_SIG_PREFIX = "agentmesh-envelope-v1\n"

PrimitiveType = Literal["register", "discover", "request", "respond", "emit", "subscribe"]
_VALID_TYPES = ("register", "discover", "request", "respond", "emit", "subscribe")

# ── ids and times ───────────────────────────────────────────────────────────

_uuid_lock = threading.Lock()
_last_ms = 0
_seq = 0


def uuid7() -> str:
    """A UUIDv7: 48-bit millisecond time, then a 12-bit counter, then random.

    Monotonic within one process, the same scheme as the TypeScript SDK, so ids
    sort by creation time.
    """
    global _last_ms, _seq
    with _uuid_lock:
        now = int(time.time() * 1000)
        if now > _last_ms:
            _last_ms = now
            _seq = 0
        else:
            _seq += 1
            if _seq > 0x0FFF:
                _seq = 0
                _last_ms += 1
            now = _last_ms
        seq = _seq
    b = bytearray(os.urandom(16))
    b[0:6] = now.to_bytes(6, "big")
    b[6] = 0x70 | ((seq >> 8) & 0x0F)
    b[7] = seq & 0xFF
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def iso_now(now: datetime | None = None) -> str:
    """An instant as JavaScript's ``Date.toISOString()`` writes it (ms, ``Z``)."""
    dt = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_iso(ts: str) -> datetime | None:
    """Parse an RFC 3339 instant. None if it is not one."""
    if not isinstance(ts, str) or not ts:
        return None
    text = ts.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ── building ────────────────────────────────────────────────────────────────


def create_envelope(
    type: PrimitiveType,
    from_: str,
    *,
    to: str | None = None,
    trace: dict[str, Any] | None = None,
    task_id: str | None = None,
    in_reply_to: str | None = None,
    context_id: str | None = None,
    budget: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    payload: Any = None,
    artifacts: list[dict[str, Any]] | None = None,
    meta: dict[str, Any] | None = None,
    include_null_payload: bool = False,
) -> dict[str, Any]:
    """Build an unsigned envelope. Fills ``v``, ``id``, ``ts`` and ``trace``.

    Optional fields left as None are absent, not null. An explicit trace wins;
    otherwise, inside a request handler, the envelope is a child of the inbound
    trace; otherwise it starts a new trace.
    """
    if not type:
        raise MeshError(ErrorCode.INVALID_ENVELOPE, "Envelope 'type' is required")
    if not from_:
        raise MeshError(ErrorCode.INVALID_ENVELOPE, "Envelope 'from' is required")
    if type not in _VALID_TYPES:
        raise MeshError(
            ErrorCode.INVALID_ENVELOPE,
            f"Invalid envelope type '{type}'. Must be one of: {', '.join(_VALID_TYPES)}",
        )
    if trace is None:
        ambient = current_trace()
        trace = child_span(ambient) if ambient else new_trace_context()
    env: dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "id": uuid7(),
        "type": type,
        "ts": iso_now(),
        "from": from_,
        "trace": trace,
    }
    if to is not None:
        env["to"] = to
    if task_id is not None:
        env["task_id"] = task_id
    if in_reply_to is not None:
        env["in_reply_to"] = in_reply_to
    if context_id is not None:
        env["context_id"] = context_id
    if budget is not None:
        env["budget"] = budget
    if error is not None:
        env["error"] = error
    if payload is not None or include_null_payload:
        env["payload"] = payload
    if artifacts is not None:
        env["artifacts"] = artifacts
    if meta is not None:
        env["meta"] = meta
    return env


def validate_envelope(env: Any) -> None:
    """Structural check of a decoded envelope. Raises MeshError when invalid."""
    if not isinstance(env, dict):
        raise MeshError(ErrorCode.INVALID_ENVELOPE, "Envelope must be a non-null object")
    for field in ("v", "id", "type", "ts", "from"):
        if not isinstance(env.get(field), str):
            raise MeshError(ErrorCode.INVALID_ENVELOPE, f"Missing or invalid '{field}' field")
    if not isinstance(env.get("trace"), dict):
        raise MeshError(ErrorCode.INVALID_ENVELOPE, "Missing or invalid 'trace' field")
    major = env["v"].split(".")[0]
    if major != PROTOCOL_VERSION.split(".")[0]:
        raise MeshError(
            ErrorCode.INVALID_VERSION,
            f"Unsupported protocol version '{env['v']}'. Expected major version {PROTOCOL_VERSION.split('.')[0]}.",
        )


# ── signing ─────────────────────────────────────────────────────────────────


def _without_sig(env: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in env.items() if k != "sig"}


def canonical_envelope_bytes(env: dict[str, Any]) -> bytes:
    """Canonical JSON of the envelope without ``sig``. Not what is signed on its
    own: the signature covers the tag plus these bytes."""
    return canonical_bytes(_without_sig(env))


def signed_envelope_bytes(env: dict[str, Any]) -> bytes:
    """The exact bytes an envelope's ``sig`` covers (SPEC 5.3)."""
    return (ENVELOPE_SIG_PREFIX + canonical_json(_without_sig(env))).encode("utf-8")


def sign_tagged(kp: KeyPair, prefix: str, canonical: str) -> bytes:
    """Sign ``prefix + canonical``. Every tagged signature goes through here."""
    return kp.sign((prefix + canonical).encode("utf-8"))


def verify_tagged(public_key: str, prefix: str, canonical: str, sig: bytes) -> bool:
    """Tagged form only. The untagged form was refused from protocol 0.3."""
    return verify_signature(public_key, (prefix + canonical).encode("utf-8"), sig)


def sign_envelope(env: dict[str, Any], kp: KeyPair) -> dict[str, Any]:
    """Sign in place with ``kp`` (sets ``sig``) and return the envelope."""
    env["sig"] = b64url_encode(kp.sign(signed_envelope_bytes(env)))
    return env


def verify_envelope(env: Any) -> bool:
    """True when ``sig`` is a valid signature by the key in ``from``."""
    if not isinstance(env, dict):
        return False
    sig, sender = env.get("sig"), env.get("from")
    if not isinstance(sig, str) or not sig or not isinstance(sender, str) or not sender:
        return False
    try:
        raw = b64url_decode(sig)
    except Exception:
        return False
    try:
        canonical = canonical_json(_without_sig(env))
    except TypeError:
        return False
    return verify_tagged(sender, ENVELOPE_SIG_PREFIX, canonical, raw)


# ── wire ────────────────────────────────────────────────────────────────────


def encode(env: dict[str, Any]) -> bytes:
    """Wire bytes of an envelope.

    Written in canonical form. Any valid JSON would do on the wire, since the
    receiver re-canonicalizes before verifying, but the canonical form is
    deterministic and writes numbers exactly as the signature saw them.
    """
    return canonical_bytes(env)


def decode_unverified(data: bytes | str) -> dict[str, Any]:
    """Parse and structurally check, without checking the signature."""
    try:
        parsed = parse_json(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MeshError(ErrorCode.INVALID_ENVELOPE, f"Envelope is not valid JSON: {exc}") from exc
    validate_envelope(parsed)
    return parsed


def decode(data: bytes | str) -> dict[str, Any]:
    """Parse, check structure, and verify the signature against ``from``."""
    env = decode_unverified(data)
    if not isinstance(env.get("sig"), str) or not env["sig"]:
        raise MeshError(ErrorCode.IDENTITY_MISMATCH, "Envelope is missing a signature (`sig`)")
    if not verify_envelope(env):
        raise MeshError(
            ErrorCode.IDENTITY_MISMATCH,
            f"Envelope signature does not verify against 'from' ({env['from']})",
        )
    return env
