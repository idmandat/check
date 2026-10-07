// idmandat – check who stands behind an AI agent, in one line (Node 18+, no dependencies). License: MIT
//   import { check } from "./idmandat.mjs";
//   const r = await check("example.com", { agent: "Support-Agent" });
//   if (r.ok("registered")) { ... }
import { createPublicKey, verify } from "node:crypto";

const RANK = { unknown: 0, listed_unverified: 1, registered: 2, verified: 3 };
const SPKI = Buffer.from("302a300506032b6570032100", "hex"); // Ed25519 public key header
const keys = new Map();

async function getJson(url, timeout) {
  const r = await fetch(url, { headers: { "User-Agent": "js-idmandat/0.1.0" }, signal: AbortSignal.timeout(timeout) });
  if (!r.ok) throw new Error("http " + r.status);
  return r.json();
}

async function verifySig(base, resp, timeout) {
  try {
    let c = keys.get(base);
    if (!c || Date.now() - c.t > 3600_000) { c = { t: Date.now(), k: await getJson(base + "/.well-known/idmandat-key.json", timeout) }; keys.set(base, c); }
    const k = c.k.keys.find((x) => x.keyId === resp.keyId);
    if (!k) return false;
    const pub = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(k.publicKey, "base64")]), format: "der", type: "spki" });
    return verify(null, Buffer.from(resp.payload, "utf8"), pub, Buffer.from(resp.signature, "base64"));
  } catch { return false; }
}

export async function check(domain, { agent, base = "https://idmandat.com", timeout = 8000 } = {}) {
  const q = new URLSearchParams({ domain, ...(agent ? { agent } : {}) });
  try {
    const resp = await getJson(`${base}/check?${q}`, timeout);
    const data = JSON.parse(resp.payload);
    let verified = await verifySig(base, resp, timeout);
    if (verified && Date.now() > Date.parse(data.validUntil)) verified = false;
    return wrap(data, verified);
  } catch { return wrap({ found: false, status: "unknown" }, false); }
}

function wrap(data, verified) {
  return {
    data, verified, found: !!data.found, status: data.status ?? "unknown",
    organization: data.organization, agent: data.agent, howToRegister: data.howToRegister,
    ok(minimum = "registered", requireSignature = true) {
      if (requireSignature && !verified) return false;
      if (data.agentListed === false) return false;
      return (RANK[this.status] ?? 0) >= RANK[minimum];
    },
  };
}
