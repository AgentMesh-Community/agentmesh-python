# Python SDK plan and status

Status as of 2026-09-27. The source is public at
https://github.com/AgentMesh-Community/agentmesh-python. The package is not on
PyPI yet, and nothing here has connected to the production mesh.

## Build items

| # | Item | Status |
|---|---|---|
| 1 | Package `agentmesh`: Python 3.10+, hatchling, typed (`py.typed`), async first, blocking wrapper (`agentmesh.sync`). Dependencies: nats-py, pynacl, httpx. | Done. The wheel builds. |
| 2a | Keys: nkey seeds encoded and decoded here over PyNaCl Ed25519; seed files written 0600 and refused on POSIX when others can read them. | Done. |
| 2b | Credentials: `join` trades a console agent key at `/v1/bootstrap`; `Credentials` saves and loads the folder; `CredentialRenewer` renews at two thirds of the credential's own lifetime (SPEC 4.8), heals a lapsed credential before connecting, and writes the renewal back. A refused credential fails `connect()` fast with `TRANSPORT_PERMISSION_DENIED`. | Done. Renewal is unit tested against a mock control plane; the JWT connection path is tested against a local operator-mode nats-server. |
| 2c | Envelopes: canonical JSON (RFC 8785 with the SPEC 5.3 rules), the `agentmesh-envelope-v1` tag, sign and verify, decode refusing bad or untagged signatures and wrong major versions. | Done. Byte-identical to the TypeScript SDK, proven by vectors it generated. |
| 2d | Primitives: register (manifest key claim, node vouch and its renewal), discover, get manifest, request (accept signal, queued acknowledgement, no-responders, response binding per SPEC 6.2), respond, emit, subscribe. | Done. |
| 2e | Tasks: deferred answers (`defer_after`), task updates, `await_task`, `on_task_update`, local task tracking. | Done. Cancel and budget revisions are not built. |
| 2f | Inbox: unhandled requests and late answers held; `receive`, `inbox`, `check_inbox`, `reply`, `ack`; the SPEC 16.4 mailbox drained on register, on reconnect and every 60 s, with a held message acknowledged to the mailbox only when the application acks it. | Done. |
| 2g | Naming: resolve and reverse-resolve verified against the registrar's published key set, expiry checked, handle and registrar-key pins (refuse on change, additive rotation accepted, optional pin file); `start_naming`, `verify_naming`, `complete_naming`. | Done. Tested against a mock registrar, not the real one. |
| 2h | The naming rule on by default (`require_named=False` for tests only), same words, cache times and outage rule as `conformance/naming-gate.json`. | Done. |
| 2i | Presence heartbeat every 30 s after register; `presence(agent)` reads availability through discover. | Done. |
| 2j | W3C trace context: child spans inside handlers (a context variable), `traceparent` in and out. | Done. |
| 2k | Inbound fence (the provenance frame around another agent's text), on by default. | Done. Byte-identical to the TypeScript frame. |
| 2l | Refusing revoked and paused senders (SPEC 5.3, 4.12): before a request is handled, a registry `get` for the sender's key; a revoked key is refused with `UNAUTHORIZED` / `agent_key_revoked` and remembered for the life of the process, a paused agent with `UNAUTHORIZED` / `agent_paused` and remembered a minute; a lookup that cannot answer lets the message through. `connect(refuse_revoked_senders=False)` turns it off. A refused credential renewal is a `CredentialRefusedError` carrying the kill switch's code. | Done. Same memo times as the TypeScript SDK; unit tested with a fake registry and end to end against the local one. |
| 3 | Framework helpers: `send_to_agent`, `ask_agent`, `check_inbox`, `find_agent` as plain functions (ADK, AutoGen, LlamaIndex), LangChain tools (`[langchain]`), CrewAI tools (`[crewai]`), with runnable examples. | Done. LangChain tested with langchain-core 1.6; CrewAI tested with crewai 1.15 in its own virtualenv. The model-driven parts of the examples need an API key and were not run. |
| 4 | Tests: 304 in all (275 unit, 29 integration). On this Windows machine 302 pass and 2 skip (a POSIX file-mode test, and the CrewAI test outside its own virtualenv, where it passes). | Done. See below. |
| 5 | README, CHANGELOG, LICENSE (Apache-2.0). | Done. |
| 6 | This plan. | Done. |

## Tests

- Canonical JSON: the full `conformance/canonical-json.json` fixture (vectors
  and IEEE-754 bit rows) plus 14 harder cases the TypeScript SDK produced
  (UTF-16 key order, lone surrogates, control characters, number formats).
- Cross-language signing (42 tests): nkey encoding, raw signatures, the
  canonical and signed bytes and `sig` of six envelope kinds, TypeScript-signed
  envelopes verifying here, the node vouch, the manifest key claim, the
  node-credential request, credential renewal schedules, the pairing line and a
  registrar card signature. Plus `conformance/signature-tags.json` and
  `conformance/manifest-signing.json`.
- Naming rule: all of `conformance/naming-gate.json` plus the gate's cache,
  outage and forget behaviour and the registrar lookup.
- Integration (local nats-server, started by the tests when found): two Python
  agents end to end; a TypeScript SDK agent and a Python agent asking and
  answering each other and sharing an event; the operator-mode JWT path; the
  tools in all three shapes.

Vectors are regenerated with `node tools/gen-vectors.mjs` (needs a checkout of
agentmesh-typescript beside this one, with `npm ci` run in it).

## Differences from the TypeScript SDK, on purpose

- A Python agent listens on its inbox from `connect()`, not from `register()`,
  so an agent that only sends still receives late answers.
- Requests with no handler are held in the inbox (`inbox=True`, the default)
  instead of answered `OFFERING_NOT_FOUND`; `inbox=False` gives the TypeScript
  behaviour.
- A refused-credential error names Python's own naming functions
  (`start_naming`, `complete_naming`); the words before that sentence are the
  same as every other door.
- Plain (non-async) handlers run on a worker thread.

## Not built yet

Streaming (`requestStream`), sealing (EXT-7), rooms (EXT-5), feeds,
artifacts, task cancel, budget revisions, admission guarding (EXT-6),
payments/agreements/allowances, `MeshNode` (many agents on one connection),
storefront adoption, span publishing, the adapter's stricter naming outage rule
(`adapter_outage` in naming-gate.json, still the owner's decision for SDKs),
anchor-domain WebFinger and referrals in resolution (SPEC-NAMING 5.5, 5.6).

## Not verified

- Nothing has run against the production mesh. A live smoke test needs a real
  agent key (`am_...`) minted in the console for a test account, used once with
  `examples/join.py`, then `examples/quickstart.py` against a known agent. That
  also checks the real registry, mailbox stream permissions and naming service,
  which the tests stand in for.
- The WebSocket transport (`[websocket]` extra) is untested; the SDK prefers
  the TCP endpoint the control plane returns.

## To publish

- **PyPI name.** `agentmesh` is taken: a placeholder uploaded 2024-11-29 by
  "Aboyai Inc" (summary "Placeholder for reserving the agentmesh package
  name", homepage agentmesh.org). Options: a PEP 541 request for the name, or
  publish under a free name. Checked free on 2026-09-27: `agentmeshai`,
  `agentmesh-io`, `agentmesh-net`, `agentmesh-official`. Taken by unrelated
  projects: `agentmesh-sdk`, `agentmesh-ai`, `agentmesh-python`, `pyagentmesh`,
  `agentmesh-client`, `agentmesh-py`. The import name can stay `agentmesh`
  whatever the distribution is called.
- **Repository.** Done: `AgentMesh-Community/agentmesh-python` on GitHub.
- **CI.** Done: `.github/workflows/ci.yml` runs `pytest` on Python 3.10 to
  3.13 with a nats-server release for the integration tests, and checks out
  agentmesh-typescript for the TypeScript peer test.
- **Release.** Still to do: PyPI trusted publishing from a tagged release,
  once the distribution name is settled.
