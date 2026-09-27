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
