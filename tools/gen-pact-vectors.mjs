// Cross-language PACT vectors for the Python SDK, made by the TypeScript SDK's own pact source.
//
// Run from the agentmesh-python repository:
//
//     node tools/gen-pact-vectors.mjs <path to an AgentMesh checkout, or its sdk-typescript folder>
//
// The TypeScript SDK there needs `npm ci` (for esbuild). The script bundles src/pact/index.ts and asks it
// to sign and check a fixed set of tokens, a personal-agent JWT and a receipt, hash receipt arguments and
// build turn outputs. ES256 signatures are not deterministic, so each run makes a fresh test key and
// writes its PUBLIC half with the tokens it signed; the Python tests check those tokens and expect the
// same verdict the TypeScript SDK gave. The private key is never written. Nothing here controls anything.
//
// It writes tests/vectors/pact-ts-vectors.json and nothing else.
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const AM = resolve(process.argv[2] ?? process.env.AGENTMESH_REPO ?? join(ROOT, "..", "AgentMesh"));
const SDK = existsSync(join(AM, "sdk-typescript")) ? join(AM, "sdk-typescript") : AM;
if (!existsSync(join(SDK, "src", "pact", "index.ts"))) {
  console.error(`cannot find the TypeScript SDK's pact source at ${join(SDK, "src", "pact")}`);
  process.exit(1);
}
const esbuild = createRequire(join(SDK, "package.json"))("esbuild");
const BUILD = join(HERE, ".build");
mkdirSync(BUILD, { recursive: true });
const outfile = join(BUILD, "ts-pact.cjs");
await esbuild.build({ entryPoints: [join(SDK, "src", "pact", "index.ts")], bundle: true, format: "cjs", platform: "node", outfile, logLevel: "error" });
const ts = createRequire(import.meta.url)(outfile);

const NOW = 1_791_000_000;
const PA = "https://pa.example/pact";
const IFACE = "https://a2a.agentmesh.ai/a2a/UBRANDEXAMPLE";
const brand = await ts.generateEs256();
const other = await ts.generateEs256();
const pa = await ts.generateEs256();
const keys = { keys: [brand.publicJwk] };

const base = { iss: `${IFACE}/oauth`, aud: IFACE, sub: "person-1", client_id: PA, scope: "orders:read orders:read", grant_id: "pactgrant_1", iat: NOW, exp: NOW + 3600 };
const at = (claims, jwk = brand.privateJwk, typ = "at+jwt") => ts.signJwt(claims, jwk, { typ });
const cases = [
  ["ok", await at(base), {}],
  ["pinned_to_this_interface", await at(base), { interfaceUrl: IFACE }],
  ["pinned_to_another_interface", await at(base), { interfaceUrl: "https://a2a.agentmesh.ai/a2a/UOTHER" }],
  ["another_gateway", await at({ ...base, aud: "https://evil.example/a2a/X", iss: "https://evil.example/a2a/X/oauth" }), {}],
  ["another_personal_agent", await at({ ...base, client_id: "https://other.example" }), {}],
  ["expired", await at({ ...base, exp: NOW - 120 }), {}],
  ["inside_the_skew", await at({ ...base, exp: NOW - 10 }), {}],
  ["not_an_access_token", await at(base, brand.privateJwk, "JWT"), {}],
  ["another_key", await at(base, other.privateJwk), {}],
  ["issuer_not_the_interface", await at({ ...base, iss: IFACE }), {}],
  ["no_scope", await at({ ...base, scope: undefined }), {}],
];
const delegations = [];
for (const [name, token, extra] of cases) {
  const r = await ts.checkDelegation(token, { paIssuer: PA, keys, now: NOW, ...extra });
  delegations.push({
    name,
    token,
    ...(extra.interfaceUrl ? { interface_url: extra.interfaceUrl } : {}),
    expect: r ? { person: r.person, scopes: r.scopes, grant_id: r.grantId, interface_url: r.interfaceUrl, expires_at: r.expiresAt } : null,
  });
}

const paJwt = await ts.signPaJwt(pa.privateJwk, { iss: PA, sub: "person-1", aud: "https://provider.example/a2a", now: NOW });

const claims = { grantId: "pactgrant_1", user: "person-1", pa: PA, brand: IFACE, scopesUsed: ["orders:read"], actions: [{ tool: "lookup_orders" }, { tool: "cancel_order", argsHash: await ts.argsHash("LG-1043") }], ts: "2026-10-07T03:44:00.000Z" };
const receipt = await ts.signReceipt(claims, brand.privateJwk);
const tampered = { jws: receipt.jws, claims: { ...receipt.claims, scopesUsed: ["orders:cancel"] } };
const receipts = [
  ["ok", receipt, {}],
  ["expected_matches", receipt, { grantId: "pactgrant_1", pa: PA }],
  ["expected_differs", receipt, { user: "person-2" }],
  ["claims_differ", tampered, {}],
  ["another_key", await ts.signReceipt(claims, other.privateJwk), {}],
];
const receiptVectors = [];
for (const [name, r, expected] of receipts) {
  const check = await ts.verifyReceipt(r, keys, expected);
  receiptVectors.push({ name, receipt: r, expected, expect: "ok" in check ? null : check.refused });
}

const hashInputs = ["LG-1043", "", "Grüße 🚀", { b: 1, a: 2 }, { order: "LG-1043", reason: "changed my mind", items: [3, 1.5, null, true] }, [1, "two", { three: 3 }]];
const hashes = [];
for (const input of hashInputs) hashes.push({ input, hash: await ts.argsHash(input) });

const reports = [
  { call: "pact_report", args: ["Done.", ["orders:read", "orders:read"], [{ tool: "lookup_orders" }, { tool: "cancel_order", argsHash: "h1" }]], out: ts.pactReport("Done.", ["orders:read", "orders:read"], [{ tool: "lookup_orders" }, { tool: "cancel_order", argsHash: "h1" }]) },
  { call: "pact_needs_permission", args: ["Need your OK.", ["orders:cancel", "orders:cancel"]], out: ts.pactNeedsPermission("Need your OK.", ["orders:cancel", "orders:cancel"]) },
];
reports.push({ call: "report_text", args: [reports[0].out], out: ts.reportText(reports[0].out) });

const out = {
  made_by: "tools/gen-pact-vectors.mjs from the TypeScript SDK's src/pact",
  now: NOW,
  pa_issuer: PA,
  interface_url: IFACE,
  brand_keys: keys,
  pa_public_jwk: pa.publicJwk,
  delegations,
  pa_jwt: { token: paJwt, claims: ts.decodeJwt(paJwt).claims },
  receipts: receiptVectors,
  args_hashes: hashes,
  reports,
  turn_schema: ts.PACT_TURN_SCHEMA,
  gateways: ts.AGENTMESH_GATEWAYS,
};
const dest = join(ROOT, "tests", "vectors", "pact-ts-vectors.json");
writeFileSync(dest, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${dest}: ${delegations.length} delegation tokens, ${receiptVectors.length} receipts, ${hashes.length} hashes`);
