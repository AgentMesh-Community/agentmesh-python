"""Node vouches (SPEC.md 4.4) and the manifest key claim (SPEC.md 8.3).

A **vouch** is a node saying "I host this agent", signed by the node's key over
``agentmesh-vouch-v1`` + LF + the canonical JSON of the attestation without
``sig``. It carries an expiry and is a lease: the registry refuses an expired
one and drops a registration whose vouch has lapsed, so the SDK renews it at
two thirds of its life. A standalone agent is its own node and vouches for
itself.

The **manifest key claim** binds an agent id to its encryption key, the one
manifest fact whose forgery would let a stranger read sealed traffic. It is a
newline-joined string, not JSON, so there is nothing for two SDKs to
canonicalize differently:

    agentmesh-manifest-key-v1 LF issued_at LF id LF encryption_key
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .canonical import canonical_json
from .envelope import iso_now, parse_iso, sign_tagged, verify_tagged
from .keys import KeyPair, b64url_decode, b64url_encode, verify_signature

__all__ = [
    "VOUCH_SIG_PREFIX",
    "DEFAULT_VOUCH_TTL_MS",
    "EPHEMERAL_VOUCH_TTL_MS",
    "RENEWAL_FRACTION",
    "create_attestation",
    "verify_attestation",
    "attestation_expired",
    "sign_manifest",
    "verify_manifest_signature",
    "manifest_key_claim_bytes",
]

VOUCH_SIG_PREFIX = "agentmesh-vouch-v1\n"
MANIFEST_KEY_CLAIM_TYPE = "agentmesh-manifest-key-v1"

#: A declared, durable registration's vouch lifetime (30 days).
DEFAULT_VOUCH_TTL_MS = 30 * 24 * 60 * 60_000
#: An undeclared registration's vouch lifetime (72 hours): ephemerality is the
#: default, durability is declared with a node profile ``availability_class``.
EPHEMERAL_VOUCH_TTL_MS = 72 * 60 * 60_000
#: How far into a lease the SDK renews it: vouches and credentials alike.
RENEWAL_FRACTION = 2 / 3


def create_attestation(
    node_kp: KeyPair,
    agent_public: str,
    ttl_ms: int = DEFAULT_VOUCH_TTL_MS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The node's signed statement that it hosts ``agent_public`` (SPEC 4.4)."""
    now = now or datetime.now(timezone.utc)
    att: dict[str, Any] = {
        "node": node_kp.public_key,
        "agent": agent_public,
        "issued_at": iso_now(now),
        "expires_at": iso_now(now + timedelta(milliseconds=ttl_ms)),
    }
    att["sig"] = b64url_encode(sign_tagged(node_kp, VOUCH_SIG_PREFIX, canonical_json(att)))
    return att


def verify_attestation(att: Any, expected_agent: str | None = None) -> bool:
    """Check a vouch's signature (and, optionally, whom it vouches for).

    Does not check expiry; see :func:`attestation_expired`.
    """
    if not isinstance(att, dict) or not att.get("node") or not att.get("agent") or not att.get("sig"):
        return False
    if expected_agent and att.get("agent") != expected_agent:
        return False
    rest = {k: v for k, v in att.items() if k != "sig"}
    try:
        sig = b64url_decode(str(att["sig"]))
        return verify_tagged(str(att["node"]), VOUCH_SIG_PREFIX, canonical_json(rest), sig)
    except Exception:
        return False


def attestation_expired(att: dict[str, Any], now: datetime | None = None) -> bool:
    exp = parse_iso(att.get("expires_at", "")) if isinstance(att, dict) else None
    if exp is None:
        return False
    return exp < (now or datetime.now(timezone.utc))


def manifest_key_claim_bytes(agent_id: str, encryption_key: str, issued_at: str) -> bytes:
    for part in (issued_at, agent_id, encryption_key):
        if "\n" in part:
            raise ValueError("manifest key claim components must not contain a newline (SPEC 8.3)")
    return "\n".join([MANIFEST_KEY_CLAIM_TYPE, issued_at, agent_id, encryption_key]).encode("utf-8")


def sign_manifest(manifest: dict[str, Any], kp: KeyPair, now: datetime | None = None) -> dict[str, Any]:
    """Sign a manifest's key claim with the agent's own key, in place.

    Sets ``trust.issued_at`` and ``trust.signature``; keeps any other ``trust``
    fields. An absent ``encryption_key`` signs as the empty string: the claim
    then says "this agent declares no encryption key".
    """
    issued_at = iso_now(now)
    trust = {k: v for k, v in (manifest.get("trust") or {}).items() if k not in ("signature", "issued_at")}
    claim = manifest_key_claim_bytes(manifest["id"], manifest.get("encryption_key") or "", issued_at)
    manifest["trust"] = {**trust, "issued_at": issued_at, "signature": b64url_encode(kp.sign(claim))}
    return manifest


def verify_manifest_signature(manifest: Any) -> bool:
    """True when the agent named by ``id`` signed this ``encryption_key`` claim."""
    if not isinstance(manifest, dict):
        return False
    trust = manifest.get("trust")
    if not isinstance(trust, dict):
        return False
    sig, issued_at, agent_id = trust.get("signature"), trust.get("issued_at"), manifest.get("id")
    if not isinstance(sig, str) or not sig or not isinstance(issued_at, str) or not issued_at:
        return False
    if not isinstance(agent_id, str) or not agent_id:
        return False
    enc = manifest.get("encryption_key")
    if enc is not None and not isinstance(enc, str):
        return False
    try:
        return verify_signature(agent_id, manifest_key_claim_bytes(agent_id, enc or "", issued_at), b64url_decode(sig))
    except Exception:
        return False
