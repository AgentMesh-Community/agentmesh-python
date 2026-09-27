"""Signing must be byte-identical to the TypeScript SDK.

Every vector here was produced by tools/gen-vectors.mjs from the TypeScript SDK
source. Ed25519 is deterministic, so a signature that differs by one byte means
the signed bytes differ, which means a Python agent and a TypeScript agent would
refuse each other's messages.
"""

import base64
import copy
from datetime import datetime, timezone

import pytest

from agentmesh.attestation import (
    VOUCH_SIG_PREFIX,
    create_attestation,
    sign_manifest,
    verify_attestation,
    verify_manifest_signature,
)
from agentmesh.canonical import canonical_json
from agentmesh.credential import (
    RenewalAgent,
    build_credential_request,
    credential_check_interval_ms,
    credential_renew_at,
    decode_credential_claims,
)
from agentmesh.envelope import ENVELOPE_SIG_PREFIX, sign_envelope, signed_envelope_bytes, verify_envelope
from agentmesh.keys import KeyPair, verify_signature
from agentmesh.naming import pair_line

from .conftest import load

TS = load("ts-sdk-vectors.json")
SIG_TAGS = load("conformance/signature-tags.json")
MANIFEST_SIGNING = load("conformance/manifest-signing.json")
T0 = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)


def test_prefixes_match():
    assert ENVELOPE_SIG_PREFIX == TS["envelope_sig_prefix"]
    assert VOUCH_SIG_PREFIX == TS["vouch_sig_prefix"]


@pytest.mark.parametrize("v", TS["nkeys"], ids=lambda v: v["public"][:10])
def test_public_key_from_seed(v):
    kp = KeyPair.from_seed(v["seed"])
    assert kp.public_key == v["public"]
    assert kp.seed == v["seed"]  # the seed re-encodes to the same string


@pytest.mark.parametrize("v", TS["raw_sign"], ids=lambda v: v["seed"][:10])
def test_raw_signatures(v):
    kp = KeyPair.from_seed(v["seed"])
    assert base64.b64encode(kp.sign(v["message"].encode())).decode() == v["sig_b64"]


@pytest.mark.parametrize("v", TS["envelopes"], ids=lambda v: v["name"])
def test_envelope_canonical_and_signed_bytes(v):
    env = v["envelope"]
    assert canonical_json(env) == v["canonical"]
    assert base64.b64encode(signed_envelope_bytes(env)).decode() == v["signed_bytes_b64"]


@pytest.mark.parametrize("v", [e for e in TS["envelopes"] if "sig" in e], ids=lambda v: v["name"])
def test_envelope_signature_matches_typescript(v):
    kp = KeyPair.from_seed(TS["identities"]["seed"])
    signed = sign_envelope(copy.deepcopy(v["envelope"]), kp)
    assert signed["sig"] == v["sig"]
    assert verify_envelope(signed)


@pytest.mark.parametrize("v", [e for e in TS["envelopes"] if "sig" in e], ids=lambda v: v["name"])
def test_typescript_signed_envelope_verifies(v):
    env = {**v["envelope"], "sig": v["sig"]}
    assert verify_envelope(env)


def test_vouch_matches_typescript():
    node = KeyPair.from_seed(TS["identities"]["node_seed"])
    att = create_attestation(node, TS["identities"]["public"], TS["vouch"]["ttl_ms"], T0)
    assert att == TS["vouch"]["attestation"]
    me = KeyPair.from_seed(TS["identities"]["seed"])
    assert create_attestation(me, me.public_key, TS["vouch"]["short_ttl_ms"], T0) == TS["vouch"]["self"]
    assert verify_attestation(TS["vouch"]["attestation"], TS["identities"]["public"])


def test_vouch_conformance_fixture():
    v = SIG_TAGS["vouch"]
    rest = {k: x for k, x in v["signed"].items() if k != "sig"}
    assert canonical_json(rest) == v["canonical"]
    assert verify_attestation(v["signed"])
    node = KeyPair.from_seed(SIG_TAGS["identities"]["sender_seed"])
    issued = datetime.fromisoformat(rest["issued_at"].replace("Z", "+00:00"))
    again = create_attestation(node, rest["agent"], 24 * 3600_000, issued)
    assert again["sig"] == v["signed"]["sig"]


def test_room_descriptor_and_roster_tags_verify():
    """The same tagged-signature machinery, for the two other tagged objects."""
    for block, decode in (("room_descriptor", "url"), ("admission_roster", "std")):
        b = SIG_TAGS[block]
        signed = b["signed"]
        rest = {k: x for k, x in signed.items() if k != "sig"}
        assert canonical_json(rest) == b["canonical"]
        raw = base64.urlsafe_b64decode(signed["sig"] + "==") if decode == "url" else base64.b64decode(signed["sig"])
        signer = rest.get("creator") or rest.get("owner") or SIG_TAGS["identities"]["sender"]
        assert verify_signature(SIG_TAGS["identities"]["sender"], (b["signed_bytes_prefix"] + b["canonical"]).encode(), raw), signer


def test_manifest_claims_match_typescript():
    kp = KeyPair.from_seed(TS["identities"]["seed"])
    me = TS["identities"]["public"]
    m1 = sign_manifest({"id": me, "name": "m", "trust": {"tenant": "t1"}}, kp, T0)
    assert m1 == TS["manifest_claims"]["without_key"]
    m2 = sign_manifest({"id": me, "name": "m", "encryption_key": "c2VhbGVkLWtleS1mb3ItdGVzdHM"}, kp, T0)
    assert m2 == TS["manifest_claims"]["with_key"]
    assert verify_manifest_signature(m1) and verify_manifest_signature(m2)
    tampered = {**m2, "encryption_key": "attacker"}
    assert not verify_manifest_signature(tampered)


@pytest.mark.parametrize("block", ["key_claim_v1", "key_claim_v1_no_encryption_key"])
def test_manifest_signing_conformance_fixture(block):
    from agentmesh.attestation import manifest_key_claim_bytes
    from agentmesh.keys import b64url_encode

    v = MANIFEST_SIGNING[block]
    claim = manifest_key_claim_bytes(v["id"], v["encryption_key"], v["issued_at"])
    assert claim.decode() == v["canonical"]
    kp = KeyPair.from_seed(v["agent_seed"])
    assert kp.public_key == v["id"]
    assert b64url_encode(kp.sign(claim)) == v["signature"]
    manifest = {"id": v["id"], "trust": {"issued_at": v["issued_at"], "signature": v["signature"]}}
    if v["encryption_key"]:
        manifest["encryption_key"] = v["encryption_key"]
    assert verify_manifest_signature(manifest)


def test_credential_request_matches_typescript():
    c = TS["credential_request"]
    me = KeyPair.from_seed(c["agent_seed"])
    body = build_credential_request(c["node_seed"], [RenewalAgent(id=me.public_key, seed=c["agent_seed"])], c["now_sec"])
    assert body == c["body"]
    self_hosted = build_credential_request(c["agent_seed"], [RenewalAgent(id=me.public_key, seed=c["agent_seed"])], c["now_sec"])
    assert self_hosted == c["self_hosted"]


def test_credential_request_with_sign_callback():
    c = TS["credential_request"]
    me = KeyPair.from_seed(c["agent_seed"])

    def sign(message: str) -> str:
        return base64.b64encode(me.sign(message.encode())).decode()

    body = build_credential_request(c["node_seed"], [RenewalAgent(id=me.public_key, sign=sign)], c["now_sec"])
    assert body == c["body"]


@pytest.mark.parametrize("v", TS["credential_jwts"], ids=lambda v: v["name"])
def test_credential_schedule_matches_typescript(v):
    claims = decode_credential_claims(v["jwt"])
    d = v["decoded"]
    assert (claims.sub, claims.iat, claims.exp) == (d["sub"], d.get("iat"), d.get("exp"))
    assert credential_renew_at(claims) == v["renew_at_ms"]
    lifetime = (claims.exp - claims.iat) * 1000 if claims.exp is not None and claims.iat is not None else 30 * 24 * 3600_000
    assert credential_check_interval_ms(lifetime) == v["check_interval_ms"]


def test_pairing_signature_matches_typescript():
    n = TS["naming"]
    kp = KeyPair.from_seed(TS["identities"]["seed"])
    assert pair_line("abcd1234", kp.public_key) == n["pair_line"]
    assert base64.b64encode(kp.sign(n["pair_line"].encode())).decode() == n["pair_sig_b64"]


def test_registrar_card_signature_verifies():
    n = TS["naming"]
    from agentmesh.canonical import canonical_bytes

    assert verify_signature(n["card_registrar_key"], canonical_bytes(n["card"]), base64.b64decode(n["card_sig_b64"]))
