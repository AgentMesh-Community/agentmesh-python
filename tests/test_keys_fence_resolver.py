"""Keys and seed files, the inbound fence, and the verifying, pinning resolver."""

import base64
import sys
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from agentmesh.canonical import canonical_bytes
from agentmesh.fence import fence_inbound_input, frame_message, inbound_text_length
from agentmesh.keys import KeyPair, is_agent_id, load_seed, save_seed
from agentmesh.naming import PinStore, Resolver

from .conftest import load

TS = load("ts-sdk-vectors.json")

# ── keys ────────────────────────────────────────────────────────────────────


def test_fresh_identity_round_trips():
    kp = KeyPair.create()
    assert is_agent_id(kp.public_key)
    assert KeyPair.from_seed(kp.seed).public_key == kp.public_key
    assert kp.seed.startswith("SU") and kp.seed not in repr(kp)


def test_bad_checksum_and_non_seeds_are_refused():
    seed = KeyPair.create().seed
    broken = seed[:-2] + ("A" if seed[-2] != "A" else "B") + seed[-1]
    for bad in (broken, "hello", KeyPair.create().public_key):
        with pytest.raises(ValueError):
            KeyPair.from_seed(bad)
    assert not is_agent_id(KeyPair.create().public_key[:-1] + "A")


def test_seed_file_round_trip(tmp_path):
    kp = KeyPair.create()
    p = save_seed(tmp_path / "keys" / "agent.seed", kp.seed)
    assert load_seed(p) == kp.seed
    if sys.platform != "win32":
        assert (p.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_seed_file_readable_by_others_is_refused(tmp_path):
    import os

    p = save_seed(tmp_path / "agent.seed", KeyPair.create().seed)
    os.chmod(p, 0o644)
    with pytest.raises(PermissionError):
        load_seed(p)


# ── fence ───────────────────────────────────────────────────────────────────

F = TS["fence"]
RECEIVED = datetime.fromisoformat(F["received_at"].replace("Z", "+00:00"))


@pytest.mark.parametrize("case", F["cases"], ids=lambda c: repr(c["input"])[:24])
def test_fence_matches_typescript(case):
    got = fence_inbound_input(case["input"], from_=F["from"], trace={"trace_id": F["trace_id"]}, received_at=RECEIVED)
    assert got == case["fenced"]
    assert inbound_text_length(case["input"]) == case["text_length"]


@pytest.mark.parametrize("fr", F["frames"], ids=lambda f: str(f["prov"].get("handle")))
def test_frame_matches_typescript(fr):
    p = fr["prov"]
    got = frame_message(fr["text"], from_=p["from"], handle=p.get("handle"), operator=p.get("operator"), trace=p.get("trace"), received_at=RECEIVED)
    assert got == fr["framed"]


# ── resolver ────────────────────────────────────────────────────────────────

AGENT = KeyPair.create()
REG = KeyPair.create()
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


def card(agent_id=None, handle="kit.owner@example.com", expires=NOW + timedelta(hours=1)):
    return {
        "handle": handle,
        "operator": {"name": "Owner"},
        "endpoints": [{"protocol": "agentmesh", "agent_id": agent_id or AGENT.public_key}],
        "registrar": "https://reg.test",
        "issued_at": (expires - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
    }


class FakeRegistrar:
    def __init__(self):
        self.card = card()
        self.signer = REG
        self.published = [REG]
        self.signed = True

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/registrar-key":
            return httpx.Response(200, json={"keys": [k.public_key for k in self.published]})
        if request.url.path == "/api/resolve":
            body = {"card": self.card}
            if self.signed:
                body["registrar_key"] = self.signer.public_key
                body["registrar_sig"] = base64.b64encode(self.signer.sign(canonical_bytes(self.card))).decode()
            return httpx.Response(200, json=body)
        return httpx.Response(404)


def resolver(reg, pins=None, warnings=None):
    client = httpx.AsyncClient(transport=httpx.MockTransport(reg.handler))
    return Resolver("https://reg.test", pins=pins or PinStore(), client=client,
                    on_warning=(warnings.append if warnings is not None else None), now=lambda: NOW)


async def test_resolves_verifies_and_pins():
    reg = FakeRegistrar()
    r = resolver(reg)
    got = await r.resolve("kit.owner@example.com")
    assert got.agent_id == AGENT.public_key and got.operator == "Owner"
    assert r.pins.handles["kit.owner@example.com"] == AGENT.public_key
    assert r.pins.authorities["https://reg.test"] == REG.public_key
    assert (await r.reverse(AGENT.public_key)).handle == "kit.owner@example.com"
    assert await r.agent_id_for("kit.owner@example.com") == AGENT.public_key
    assert await r.agent_id_for(AGENT.public_key) == AGENT.public_key


async def test_unsigned_card_is_discarded():
    reg = FakeRegistrar()
    reg.signed = False
    w = []
    assert await resolver(reg, warnings=w).resolve("kit.owner@example.com") is None
    assert w[0]["code"] == "card_unsigned"


async def test_card_signed_by_unpublished_key_is_discarded():
    reg = FakeRegistrar()
    reg.signer = KeyPair.create()
    w = []
    assert await resolver(reg, warnings=w).resolve("kit.owner@example.com") is None
    assert w[0]["code"] == "card_key_unpublished"


async def test_tampered_card_is_discarded():
    reg = FakeRegistrar()
    r = resolver(reg)
    good = reg.card
    orig = reg.handler

    def tamper(request):
        resp = orig(request)
        if request.url.path == "/api/resolve":
            body = resp.json()
            body["card"] = {**good, "handle": "evil.owner@example.com"}
            return httpx.Response(200, json=body)
        return resp

    reg.handler = tamper
    r = resolver(reg)
    assert await r.resolve("kit.owner@example.com") is None


async def test_expired_card_is_discarded():
    reg = FakeRegistrar()
    reg.card = card(expires=NOW - timedelta(minutes=5))
    w = []
    assert await resolver(reg, warnings=w).resolve("kit.owner@example.com") is None
    assert w[0]["code"] == "card_expired"


async def test_handle_moving_to_another_key_is_refused_and_pin_kept():
    reg = FakeRegistrar()
    pins = PinStore()
    w = []
    r = resolver(reg, pins, w)
    await r.resolve("kit.owner@example.com")
    other = KeyPair.create()
    reg.card = card(agent_id=other.public_key)
    assert await r.resolve("kit.owner@example.com") is None
    assert pins.handles["kit.owner@example.com"] == AGENT.public_key
    assert w[-1]["code"] == "handle_key_changed"
    pins.confirm("kit.owner@example.com")
    assert (await r.resolve("kit.owner@example.com")).agent_id == other.public_key


async def test_registrar_key_change_is_refused_unless_additive_rotation():
    reg = FakeRegistrar()
    pins = PinStore()
    w = []
    r = resolver(reg, pins, w)
    await r.resolve("kit.owner@example.com")
    new = KeyPair.create()
    # Replaced outright: the pinned key is gone from the published set.
    reg.signer, reg.published = new, [new]
    r._key_cache.clear()
    assert await r.resolve("kit.owner@example.com") is None
    assert w[-1]["code"] == "registrar_key_changed"
    assert pins.authorities["https://reg.test"] == REG.public_key
    # Additive rotation: both keys published, the new one signing.
    reg.published = [new, REG]
    r._key_cache.clear()
    assert (await r.resolve("kit.owner@example.com")) is not None
    assert pins.authorities["https://reg.test"] == new.public_key


async def test_pins_persist_to_a_file(tmp_path):
    reg = FakeRegistrar()
    path = tmp_path / "pins.json"
    await resolver(reg, PinStore(path)).resolve("kit.owner@example.com")
    assert PinStore(path).handles["kit.owner@example.com"] == AGENT.public_key
