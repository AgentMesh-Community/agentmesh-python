"""PACT helpers (agentmesh.pact), held to the TypeScript SDK by tests/vectors/pact-ts-vectors.json.

The vectors are tokens, a personal-agent JWT and receipts the TypeScript SDK signed, with the verdict it
gave on each; tools/gen-pact-vectors.mjs makes them. Python must give the same verdicts, the same
argument hashes and the same turn outputs.
"""

import json

import httpx
import pytest

from agentmesh import pact

from .conftest import load

V = load("pact-ts-vectors.json")


@pytest.mark.parametrize("case", V["delegations"], ids=[c["name"] for c in V["delegations"]])
def test_check_delegation_agrees_with_typescript(case):
    got = pact.check_delegation(case["token"], pa_issuer=V["pa_issuer"], keys=V["brand_keys"], interface_url=case.get("interface_url"), now=V["now"])
    if case["expect"] is None:
        assert got is None
    else:
        assert got is not None
        assert {"person": got.person, "scopes": list(got.scopes), "grant_id": got.grant_id, "interface_url": got.interface_url, "expires_at": got.expires_at} == case["expect"]


def test_check_delegation_refuses_what_is_not_a_token():
    for bad in [None, "", "a.b", "a.b.c", "x" * 50]:
        assert pact.check_delegation(bad, pa_issuer=V["pa_issuer"], keys=V["brand_keys"], now=V["now"]) is None
    ok = next(c for c in V["delegations"] if c["name"] == "ok")
    # Keys given as a bare list work as well as a JWKS; no keys, no delegation.
    assert pact.check_delegation(ok["token"], pa_issuer=V["pa_issuer"], keys=V["brand_keys"]["keys"], now=V["now"]) is not None
    assert pact.check_delegation(ok["token"], pa_issuer=V["pa_issuer"], keys=[], now=V["now"]) is None


def test_personal_agent_jwt_from_typescript_verifies_and_python_signs_one_that_does():
    assert pact.verify_es256(V["pa_jwt"]["token"], [V["pa_public_jwk"]])
    private, public = pact.generate_es256_key()
    assert "d" not in public
    token = pact.sign_pa_jwt(private, iss=V["pa_issuer"], sub="person-1", aud="https://provider.example/a2a", now=V["now"])
    assert pact.verify_es256(token, {"keys": [public]})
    header, claims = pact.decode_jwt(token)
    assert header == {"alg": "ES256", "typ": "JWT", "kid": public["kid"]}
    assert claims == {k: V["pa_jwt"]["claims"][k] for k in ("iss", "sub", "aud", "iat", "exp")}
    # Never longer than PACT allows.
    long = pact.decode_jwt(pact.sign_pa_jwt(private, iss="i", sub="s", aud="a", now=0, life_seconds=3600))[1]
    assert long["exp"] == pact.MAX_PA_JWT_LIFE_S
    other, _ = pact.generate_es256_key()
    assert not pact.verify_es256(token, [{k: v for k, v in other.items() if k != "d"}])


@pytest.mark.parametrize("case", V["receipts"], ids=[c["name"] for c in V["receipts"]])
def test_verify_receipt_agrees_with_typescript(case):
    ok, why = pact.verify_receipt(case["receipt"], V["brand_keys"], case["expected"])
    assert (None if ok else why) == case["expect"]


def test_args_hash_and_turn_outputs_match_typescript():
    for h in V["args_hashes"]:
        assert pact.args_hash(h["input"]) == h["hash"], h["input"]
    by = {r["call"]: r for r in V["reports"]}
    assert pact.pact_report(*by["pact_report"]["args"]) == by["pact_report"]["out"]
    assert pact.pact_report("Done.", ["orders:read"], [("lookup_orders", None), ("cancel_order", "h1")]) == {
        "text": "Done.",
        "pact": {"scopes_used": ["orders:read"], "actions": [{"tool": "lookup_orders"}, {"tool": "cancel_order", "argsHash": "h1"}]},
    }
    assert pact.pact_needs_permission(*by["pact_needs_permission"]["args"]) == by["pact_needs_permission"]["out"]
    assert pact.report_text(by["report_text"]["args"][0]) == by["report_text"]["out"]
    assert pact.PACT_TURN_SCHEMA == V["turn_schema"]
    assert list(pact.AGENTMESH_GATEWAYS) == V["gateways"]


def test_missing_scopes_and_turns(tmp_path):
    ok = next(c for c in V["delegations"] if c["name"] == "ok")
    who = pact.check_delegation(ok["token"], pa_issuer=V["pa_issuer"], keys=V["brand_keys"], now=V["now"])
    assert pact.missing_scopes(who, ["orders:read", "orders:cancel", "orders:cancel"]) == ["orders:cancel"]
    assert pact.missing_scopes(None, ["orders:read"]) == ["orders:read"]
    turn = {"pa": V["pa_issuer"], "user": "u1", "context": "c1"}
    assert pact.pact_turn_from_meta({"pact": turn}) == turn
    assert pact.pact_turn_from_meta({}) is None
    assert pact.pact_turn_from_meta({"pact": {"pa": 1}}) is None
    (tmp_path / "pact.json").write_text(json.dumps(turn), encoding="utf-8")
    bag = {"entries": [{"schema": "other", "file": "x"}, {"schema": pact.PACT_TURN_SCHEMA, "file": "pact.json"}]}
    assert pact.pact_turn_from_bag(bag, lambda f: (tmp_path / f).read_text(encoding="utf-8")) == turn
    assert pact.pact_turn_from_bag({"entries": [{"schema": pact.PACT_TURN_SCHEMA, "file": "../x"}]}, lambda f: "{}") is None
    assert pact.pact_turn_from_bag(None, lambda f: "{}") is None


def _mock(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_send_pact_message_reads_a_reply_and_a_step_up():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        if "X-A2A-User-Delegation" in request.headers:
            receipt = V["receipts"][0]["receipt"]
            return httpx.Response(200, json={"message": {"messageId": "m2", "contextId": body["message"].get("contextId"), "role": "ROLE_AGENT", "parts": [{"text": "Your orders: LG-1042."}], "metadata": {"pact.receipt": receipt}}})
        return httpx.Response(200, json={"task": {"id": "t1", "contextId": "ctx-1", "status": {"state": "TASK_STATE_AUTH_REQUIRED", "message": {"role": "ROLE_AGENT", "parts": [{"text": "I need your permission."}]}}, "metadata": {"pact.missingScopes": ["orders:read"], "pact.verificationUriComplete": "https://b.example/oauth/start?user_code=ABCD-EFGH"}}})

    async with _mock(handler) as client:
        first = await pact.send_pact_message(V["interface_url"] + "/", "What are my orders?", pa_jwt=lambda: "pa.jwt.x", client=client)
        assert (first.kind, first.text, first.context_id, first.missing_scopes) == ("auth_required", "I need your permission.", "ctx-1", ["orders:read"])
        assert first.link == "https://b.example/oauth/start?user_code=ABCD-EFGH"
        second = await pact.send_pact_message(V["interface_url"], "What are my orders?", pa_jwt="pa.jwt.y", delegation_token="dt", context_id=first.context_id, client=client)
        assert (second.kind, second.text, second.context_id) == ("message", "Your orders: LG-1042.", "ctx-1")
        assert pact.verify_receipt(second.receipt, V["brand_keys"]) == (True, None)
    assert str(seen[0].url) == V["interface_url"] + "/message:send"
    assert seen[0].headers["Authorization"] == "Bearer pa.jwt.x"
    assert seen[0].headers["A2A-Version"] == "1.0"
    assert "X-A2A-User-Delegation" not in seen[0].headers
    assert seen[1].headers["X-A2A-User-Delegation"] == "Bearer dt"
    sent = json.loads(seen[1].content)["message"]
    assert sent["role"] == "ROLE_USER" and sent["parts"] == [{"text": "What are my orders?"}] and sent["contextId"] == "ctx-1"


async def test_send_pact_message_raises_on_refusals():
    def envelope(request):
        return httpx.Response(403, json={"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "This platform is not allowed.", "details": [{"reason": "PA_NOT_REGISTERED"}]}})

    def bad_delegation(request):
        return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="a2a", error="invalid_token"'})

    async with _mock(envelope) as client:
        with pytest.raises(pact.PactSendError) as e:
            await pact.send_pact_message(V["interface_url"], "hi", pa_jwt="t", client=client)
        assert (e.value.status, e.value.reason) == (403, "PA_NOT_REGISTERED")
    async with _mock(bad_delegation) as client:
        with pytest.raises(pact.PactSendError) as e:
            await pact.send_pact_message(V["interface_url"], "hi", pa_jwt="t", delegation_token="old", client=client)
        assert e.value.status == 401 and e.value.delegation_rejected


async def test_check_delegation_fetching_keys_reads_only_from_the_interface():
    asked = []

    def handler(request):
        asked.append(str(request.url))
        return httpx.Response(200, json=V["brand_keys"])

    ok = next(c for c in V["delegations"] if c["name"] == "ok")
    elsewhere = next(c for c in V["delegations"] if c["name"] == "another_gateway")
    async with _mock(handler) as client:
        who = await pact.check_delegation_fetching_keys(ok["token"], pa_issuer=V["pa_issuer"], now=V["now"], client=client)
        assert who is not None and who.person == "person-1"
        assert await pact.check_delegation_fetching_keys(elsewhere["token"], pa_issuer=V["pa_issuer"], now=V["now"], client=client) is None
    assert asked == [V["interface_url"] + "/oauth/jwks.json"]
