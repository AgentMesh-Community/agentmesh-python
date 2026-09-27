"""Envelope build, verify and decode: what a receiver must refuse."""

import copy
import re

import pytest

from agentmesh.envelope import (
    PROTOCOL_VERSION,
    create_envelope,
    decode,
    encode,
    sign_envelope,
    uuid7,
    verify_envelope,
)
from agentmesh.errors import ErrorCode, MeshError
from agentmesh.keys import KeyPair, b64url_encode
from agentmesh.trace import child_span, use_trace

from .conftest import load

TS = load("ts-sdk-vectors.json")
KP = KeyPair.from_seed(TS["identities"]["seed"])
OTHER = KeyPair.create()


def signed(**kw):
    return sign_envelope(create_envelope("request", KP.public_key, to=OTHER.public_key, payload={"offering": "chat", "input": {"text": "hi"}}, **kw), KP)


def test_builder_fills_the_same_fields_as_typescript():
    env = create_envelope("request", KP.public_key, to=OTHER.public_key, payload={"offering": "chat", "input": "x"})
    assert sorted(env) == TS["built_envelope_keys"]
    assert env["v"] == TS["built_envelope_v"] == PROTOCOL_VERSION
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$", env["ts"])
    assert env["trace"]["parent_span_id"] is None


def test_optional_fields_are_absent_not_null():
    env = create_envelope("emit", KP.public_key)
    for k in ("to", "task_id", "in_reply_to", "context_id", "budget", "error", "payload", "artifacts", "meta"):
        assert k not in env


def test_uuid7_shape_and_order():
    ids = [uuid7() for _ in range(2000)]
    assert all(re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", i) for i in ids)
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)


def test_round_trip():
    env = signed()
    back = decode(encode(env))
    assert back == env
    assert verify_envelope(back)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e["payload"]["input"].__setitem__("text", "hj"),
        lambda e: e.__setitem__("to", KeyPair.create().public_key),
        lambda e: e.__setitem__("ts", "2026-01-01T00:00:00.000Z"),
        lambda e: e["trace"].__setitem__("span_id", "1" * 16),
        lambda e: e.__setitem__("meta", {"hops": 1}),
        lambda e: e.__setitem__("from", OTHER.public_key),
    ],
    ids=["payload", "to", "ts", "trace", "added-field", "from"],
)
def test_any_change_breaks_the_signature(mutate):
    env = signed()
    mutate(env)
    assert not verify_envelope(env)
    with pytest.raises(MeshError) as e:
        decode(encode(env))
    assert e.value.code == ErrorCode.IDENTITY_MISMATCH


def test_missing_signature_is_refused():
    env = signed()
    del env["sig"]
    with pytest.raises(MeshError) as e:
        decode(encode(env))
    assert e.value.code == ErrorCode.IDENTITY_MISMATCH


def test_untagged_signature_is_refused():
    """A signature over bare canonical JSON (the pre-0.3 form) must not verify."""
    from agentmesh.canonical import canonical_bytes

    env = signed()
    rest = {k: v for k, v in env.items() if k != "sig"}
    env["sig"] = b64url_encode(KP.sign(canonical_bytes(rest)))
    assert not verify_envelope(env)


def test_signature_by_another_key_is_refused():
    env = signed()
    sign_envelope(env, OTHER)  # from still names KP
    assert not verify_envelope(env)


def test_garbage_is_refused():
    for data in (b"not json", b"[]", b'{"v":"0.3.0"}', b"[NaN]"):
        with pytest.raises(MeshError):
            decode(data)


def test_wrong_major_version_is_refused():
    env = create_envelope("emit", KP.public_key)
    env["v"] = "1.0.0"
    sign_envelope(env, KP)
    with pytest.raises(MeshError) as e:
        decode(encode(env))
    assert e.value.code == ErrorCode.INVALID_VERSION


def test_typescript_signed_envelope_decodes_from_its_wire_bytes():
    import json

    for v in TS["envelopes"]:
        if "sig" not in v:
            continue
        wire = json.dumps({**v["envelope"], "sig": v["sig"]}, ensure_ascii=False).encode()
        assert decode(wire)["id"] == v["envelope"]["id"]


def test_trace_is_inherited_inside_a_handler():
    parent = {"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7", "parent_span_id": None}
    with use_trace(parent):
        env = create_envelope("emit", KP.public_key)
    assert env["trace"]["trace_id"] == parent["trace_id"]
    assert env["trace"]["parent_span_id"] == parent["span_id"]
    outside = create_envelope("emit", KP.public_key)
    assert outside["trace"]["trace_id"] != parent["trace_id"]


def test_traceparent_round_trip():
    from agentmesh.trace import from_traceparent, to_traceparent

    t = TS["traceparent"]
    assert to_traceparent(t["context"]) == t["header"]
    joined = from_traceparent(t["header"], "k=v")
    assert joined["trace_id"] == t["context"]["trace_id"]
    assert joined["parent_span_id"] == t["context"]["span_id"]
    assert joined["tracestate"] == "k=v"
    assert from_traceparent("garbage") is None


def test_child_span_of_invalid_parent_starts_a_new_trace():
    c = child_span({"trace_id": "0" * 32, "span_id": "1" * 16})
    assert c["parent_span_id"] is None
