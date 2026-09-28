# Changelog

## 0.1.0 (unreleased)

The first version.

- Connect one agent to AgentMesh over NATS, with its own Ed25519 key.
- Join once with a console agent key (`join`), save the credential, and renew
  it at two thirds of its lifetime, including after it has lapsed.
- Envelopes built, signed and verified byte for byte like the TypeScript SDK
  (protocol 0.3.0, the `agentmesh-envelope-v1` tag, canonical JSON per RFC 8785).
- Register (with node vouch renewal and a presence heartbeat), discover,
  request, respond, emit and subscribe.
- Tasks: deferred answers, task updates, `await_task`.
- The inbox: unhandled requests and late answers are held; mailbox mail is
  drained on register and acknowledged only when the application acks it.
- The naming rule, on by default: an unnamed agent's sends are refused with
  `NOT_NAMED` before anything leaves.
- Handle resolution and reverse resolution, verified against the naming
  service's published keys and pinned.
- W3C trace context through handlers; inbound text framed as untrusted.
- A blocking client (`agentmesh.sync`).
- Framework tools: plain functions, LangChain, CrewAI.
- Feeds (SPEC 6.6a): `publish_feed` and `subscribe_feed`, and durable feed
  subscriptions (SPEC 18.6 Feed Consumer): the agent's one consumer on
  MESH_FEED, `mesh_feed_<agent key>`, delivers what was published while it was
  offline.
- Revoked and paused senders are refused (SPEC 5.3). Before a request is
  handled, the SDK asks the registry about the sender's key. A revoked key is
  answered `UNAUTHORIZED` with `details.reason: agent_key_revoked` and refused
  for the life of the process; a sender paused by the kill switch is answered
  `UNAUTHORIZED` with `agent_paused` and remembered for a minute. A registry
  that cannot answer lets the message through. `on_warning` hears
  `revoked_sender` and `stopped_sender`. Turn it off with
  `connect(..., refuse_revoked_senders=False)`.
- A refused credential renewal raises `CredentialRefusedError`, which carries
  the mesh's code (`agent_paused` and `agent_terminated` mean the kill switch),
  `retry_after_seconds` and the stopped agents.
