// A TypeScript SDK agent for the cross-language integration test.
//
//     node tools/ts-peer.mjs <ws-url> [path-to-AgentMesh-repo]
//
// Bundles the TypeScript SDK source (as gen-vectors.mjs does), connects to a
// LOCAL nats-server over WebSocket with the naming rule off (a throwaway test
// identity), serves "chat", and then takes one JSON command per stdin line:
//
//     {"ask": "<agent id>", "text": "..."}      -> {"answer": ..., "task_id": ...}
//     {"emit": "<topic>", "data": {...}}        -> {"emitted": true}
//
// Prints {"ready": true, "id": "<its agent id>"} first. Never point this at a
// real mesh: it has no credential and wants none.

import { createRequire } from "node:module";
import { mkdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

const HERE = dirname(fileURLToPath(import.meta.url));
const url = process.argv[2];
const AM = resolve(process.argv[3] ?? process.env.AGENTMESH_REPO ?? join(HERE, "..", "..", "AgentMesh"));
const SDK = join(AM, "sdk-typescript");
if (!url || !existsSync(join(SDK, "src", "index.ts"))) {
  console.log(JSON.stringify({ ready: false, error: "usage: ts-peer.mjs <ws-url> [AgentMesh repo]" }));
  process.exit(2);
}

const require = createRequire(join(SDK, "package.json"));
const esbuild = require("esbuild");
const out = join(HERE, ".build", "ts-full.cjs");
mkdirSync(dirname(out), { recursive: true });
await esbuild.build({
  entryPoints: [join(SDK, "src", "index.ts")],
  bundle: true,
  format: "cjs",
  platform: "node",
  outfile: out,
  logLevel: "error",
});
const { AgentMesh } = createRequire(import.meta.url)(out);

const mesh = await AgentMesh.connect(url, { requireNamed: false, fenceInbound: false });
mesh.onRequest("chat", (input, ctx) => ({ text: `ts heard: ${input?.text}`, trace_id: ctx.traceContext.trace_id }));
// The TypeScript SDK starts listening on its inbox at register(). With no
// registry on a bare local server the register is published and not answered,
// which the SDK accepts.
await mesh.register({ name: "ts-peer", offerings: [{ id: "chat", name: "Chat", description: "Echo." }] });
const say = (o) => process.stdout.write(JSON.stringify(o) + "\n");
say({ ready: true, id: mesh.id });

const rl = createInterface({ input: process.stdin });
for await (const line of rl) {
  if (!line.trim()) continue;
  const cmd = JSON.parse(line);
  try {
    if (cmd.ask) {
      const r = await mesh.request(cmd.ask, "chat", { text: cmd.text }, { timeout_ms: 5000 });
      say({ answer: r.payload.output, status: r.payload.status, task_id: r.task_id });
    } else if (cmd.emit) {
      mesh.emit(cmd.emit, cmd.data);
      say({ emitted: true });
    } else if (cmd.quit) {
      break;
    }
  } catch (err) {
    say({ error: String(err?.code ?? ""), message: String(err?.message ?? err) });
  }
}
await mesh.close();
process.exit(0);
