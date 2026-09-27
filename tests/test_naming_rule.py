"""The naming rule, held to conformance/naming-gate.json (the same file the
TypeScript SDK, the Rust SDK and the reference adapter are held to)."""

import base64
import json

import httpx
import pytest

from agentmesh.canonical import canonical_bytes
from agentmesh.errors import ErrorCode, MeshError
from agentmesh.keys import KeyPair
from agentmesh.naming import (
    NAMED_TTL_MS,
    NAMING_STANDARD_WORDS,
    UNNAMED_TTL_MS,
    NameCheck,
    NamingGate,
    is_standard_handle,
    not_named_error,
    propose_handle,
    registrar_name_lookup,
)

from .conftest import load

F = load("conformance/naming-gate.json")
TS = load("ts-sdk-vectors.json")


def test_words_are_the_owners_exactly_and_have_no_em_dash():
    assert NAMING_STANDARD_WORDS == F["words"]
    assert NAMING_STANDARD_WORDS.startswith(F["naming_standard"])
    assert "—" not in NAMING_STANDARD_WORDS
    assert F["code"] == ErrorCode.NOT_NAMED.value


def test_cache_times_match_the_fixture():
    assert NAMED_TTL_MS == F["cache"]["named_ttl_ms"]
    assert UNNAMED_TTL_MS == F["cache"]["unnamed_ttl_ms"]


@pytest.mark.parametrize("h", F["standard"])
def test_standard_handles(h):
    assert is_standard_handle(h)


@pytest.mark.parametrize("h", F["not_standard"])
def test_not_standard_handles(h):
    assert not is_standard_handle(h)


@pytest.mark.parametrize("p", F["proposals"], ids=lambda p: repr(p["name"]))
def test_proposals_from_fixture(p):
    got = propose_handle(p["name"], p["email"])
    assert got.name == p["proposed_name"]
    assert got.handle == p["handle"]


@pytest.mark.parametrize("p", TS["naming"]["proposals"], ids=lambda p: repr(p["input_name"])[:20])
def test_proposals_match_typescript(p):
    got = propose_handle(p["input_name"], p["input_email"])
    assert (got.name, got.email, got.handle) == (p["name"], p["email"], p["handle"])


@pytest.mark.parametrize("h", TS["naming"]["handles"], ids=lambda h: h["handle"])
def test_handle_checks_match_typescript(h):
    assert is_standard_handle(h["handle"]) is h["standard"]


@pytest.mark.parametrize("r", TS["naming"]["refusals"], ids=lambda r: repr(r["name"]))
def test_refusal_opens_with_words_then_the_same_proposal(r):
    err = not_named_error(r["name"], r["email"])
    assert err.code == ErrorCode.NOT_NAMED
    assert err.retryable is False
    assert err.details["proposed_handle"] == r["details"]["proposed_handle"]
    # The words and the proposal sentence are shared by every door; only the
    # "how to name it" sentence names this SDK's own functions.
    ts_first_two = r["message"].split(" To name it, ")[0]
    assert err.message.split(" To name it, ")[0] == ts_first_two
    assert err.message.startswith(F["words"])
    assert "start_naming" in err.message and "complete_naming" in err.message


# ── the gate's behaviour ────────────────────────────────────────────────────


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def lookup_returning(*answers):
    calls = []

    async def lookup(agent_id):
        calls.append(agent_id)
        a = answers[min(len(calls) - 1, len(answers) - 1)]
        if isinstance(a, Exception):
            raise a
        return a

    return lookup, calls


async def test_named_agent_passes_and_answer_is_kept_for_named_ttl():
    clock = Clock()
    lookup, calls = lookup_returning(NameCheck("named", "genesis.stephen@example.com"))
    g = NamingGate("UX", lookup, now=clock)
    await g.require()
    clock.t += NAMED_TTL_MS - 1
    await g.require()
    assert len(calls) == 1
    clock.t += 2
    await g.require()
    assert len(calls) == 2
    assert g.current().handle == "genesis.stephen@example.com"


async def test_unnamed_agent_is_refused_and_answer_kept_briefly():
    clock = Clock()
    lookup, calls = lookup_returning(NameCheck("unnamed", None))
    g = NamingGate("UX", lookup, name="Genesis", owner_email="stephen@example.com", now=clock)
    with pytest.raises(MeshError) as e:
        await g.require()
    assert e.value.code == ErrorCode.NOT_NAMED
    assert "genesis.stephen@example.com" in e.value.message
    clock.t += UNNAMED_TTL_MS + 1
    with pytest.raises(MeshError):
        await g.require()
    assert len(calls) == 2


async def test_handle_not_in_standard_shape_is_not_a_name():
    lookup, _ = lookup_returning(NameCheck("named", "genesis"))
    g = NamingGate("UX", lookup)
    with pytest.raises(MeshError):
        await g.require()


async def test_unreachable_service_lets_send_through_and_asks_again_soon():
    clock = Clock()
    lookup, calls = lookup_returning(NameCheck("unreachable"), NameCheck("unnamed"))
    g = NamingGate("UX", lookup, last_verified="kit.a@b.co", now=clock)
    await g.require()
    s = g.current()
    assert s.named and s.unchecked and s.handle == "kit.a@b.co"
    clock.t += UNNAMED_TTL_MS + 1
    with pytest.raises(MeshError):
        await g.require()
    assert len(calls) == 2


async def test_a_lookup_that_raises_counts_as_unreachable():
    lookup, _ = lookup_returning(RuntimeError("dns"))
    g = NamingGate("UX", lookup)
    await g.require()
    assert g.current().unchecked


async def test_require_cached_uses_last_answer_and_does_not_refuse_before_one():
    lookup, _ = lookup_returning(NameCheck("unnamed"))
    g = NamingGate("UX", lookup)
    g.require_cached()  # no answer yet: goes through
    await g.check()
    with pytest.raises(MeshError):
        g.require_cached()


async def test_forget_makes_the_next_send_ask_again():
    lookup, calls = lookup_returning(NameCheck("unnamed"), NameCheck("named", "kit.a@b.co"))
    g = NamingGate("UX", lookup)
    with pytest.raises(MeshError):
        await g.require()
    g.forget()
    await g.require()
    assert len(calls) == 2


# ── the registrar lookup, against a fake registrar ──────────────────────────


def registrar(card, *, sign_with, publish, status=200):
    body = {
        "card": card,
        "registrar_key": sign_with.public_key,
        "registrar_sig": base64.b64encode(sign_with.sign(canonical_bytes(card))).decode(),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/registrar-key":
            return httpx.Response(200, json={"keys": [k.public_key for k in publish]})
        if request.url.path == "/api/resolve":
            if status != 200:
                return httpx.Response(status, json={"error": "nope"})
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


AGENT = KeyPair.create()
REG = KeyPair.create()


def card_for(agent_id, handle="kit.owner@example.com"):
    return {"handle": handle, "endpoints": [{"protocol": "agentmesh", "agent_id": agent_id}], "registrar": "https://reg.test"}


async def test_lookup_named():
    c = registrar(card_for(AGENT.public_key), sign_with=REG, publish=[REG])
    r = await registrar_name_lookup("https://reg.test", client=c)(AGENT.public_key)
    assert r == NameCheck("named", "kit.owner@example.com")


async def test_lookup_404_is_unnamed():
    c = registrar(card_for(AGENT.public_key), sign_with=REG, publish=[REG], status=404)
    assert (await registrar_name_lookup("https://reg.test", client=c)(AGENT.public_key)).status == "unnamed"


async def test_lookup_unpublished_key_is_unreachable_not_named():
    rogue = KeyPair.create()
    c = registrar(card_for(AGENT.public_key), sign_with=rogue, publish=[REG])
    assert (await registrar_name_lookup("https://reg.test", client=c)(AGENT.public_key)).status == "unreachable"


async def test_lookup_card_bound_to_another_key_is_unreachable():
    c = registrar(card_for(KeyPair.create().public_key), sign_with=REG, publish=[REG])
    assert (await registrar_name_lookup("https://reg.test", client=c)(AGENT.public_key)).status == "unreachable"


async def test_lookup_nonstandard_handle_is_unnamed():
    c = registrar(card_for(AGENT.public_key, handle="kit"), sign_with=REG, publish=[REG])
    r = await registrar_name_lookup("https://reg.test", client=c)(AGENT.public_key)
    assert r.status == "unnamed" and r.handle == "kit"
