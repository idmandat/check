// idmandat – check who stands behind an AI agent, in one line (Node 18+, no dependencies). License: MIT
//   import { check } from "./idmandat.js";
//   const r = await check("example.com", { agent: "Support-Agent" });
//   if (r.ok("registered")) { ... }
//   const s = await checkSignatureAgent("https://bot.example.com"); // from the Signature-Agent header
// Reads /api/v1/verify (Ed25519-signed, keys at /api/v1/keys). may/mayNot are declarations by the operator.
// ID MANDAT confirms identity and authority, not trustworthiness or quality.
import { createPublicKey, verify } from "node:crypto";

const RANK = { unknown: 0, listed_unverified: 1, registered: 2, verified: 3 };
const SPKI = Buffer.from("302a300506032b6570032100", "hex"); // Ed25519 public key header
const keys = new Map();

async function getJson(url, timeout) {
  const r = await fetch(url, { headers: { "User-Agent": "js-idmandat/0.3.0" }, signal: AbortSignal.timeout(timeout) });
  if (!r.ok) throw new Error("http " + r.status);
  return r.json();
}

// Same rule as the server: keys sorted recursively, compact, no escaping of unicode or "/".
const sorted = (v) =>
  Array.isArray(v) ? v.map(sorted)
  : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])]))
  : v;
const canonical = (o) => Buffer.from(JSON.stringify(sorted(o)), "utf8");
const b64u = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

async function verifySig(base, resp, timeout) {
  try {
    if (!resp.signed || !resp.signature || resp.signature.alg !== "Ed25519") return false;
    let c = keys.get(base);
    if (!c || Date.now() - c.t > 3600_000) { c = { t: Date.now(), k: await getJson(base + "/api/v1/keys", timeout) }; keys.set(base, c); }
    const k = c.k.keys.find((x) => x.key_id === resp.key_id);
    if (!k) return false;
    const { signature, ...body } = resp;
    const pub = createPublicKey({ key: Buffer.concat([SPKI, b64u(k.public_key)]), format: "der", type: "spki" });
    return verify(null, canonical(body), pub, b64u(signature.value));
  } catch { return false; }
}

const norm = (d) => d.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];

export async function check(domain, { agent, base = "https://idmandat.com", timeout = 8000 } = {}) {
  const dom = norm(domain);
  const q = new URLSearchParams({ domain: dom, ...(agent ? { agent } : {}) });
  try {
    const resp = await getJson(`${base}/api/v1/verify?${q}`, timeout);
    let verified = await verifySig(base, resp, timeout);
    // The signature must belong to THIS question and still be valid.
    if (verified && (resp.domain !== dom || Date.now() > Date.parse(resp.expires_at))) verified = false;
    return wrap(resp, verified);
  } catch { return wrap({ registered: false, level: "none" }, false); }
}

function wrap(data, verified) {
  const status = data.level in RANK ? data.level : "unknown";
  return {
    data, verified, found: !!data.registered, status,
    organization: data.organization, agents: data.agents ?? [], agentListed: data.agent_found ?? null,
    howToRegister: data.register,
    entryState: data.entry_state ?? null,   // "revoked" | "suspended" | "expired" if the entry WAS valid but no longer is
    revoked: data.revoked === true,
    // Only for lookups by key directory (checkSignatureAgent):
    signatureAgent: data.signature_agent ?? null,
    ambiguous: data.ambiguous === true,
    claimedBy: data.claimed_by ?? [],
    keyDirectoryLink: data.key_directory_link ?? null, // "same_domain" (hint, not proof) | "declared_only"
    ok(minimum = "registered", requireSignature = true) {
      if (requireSignature && !verified) return false;
      if (data.agent_found === false) return false;
      return (RANK[status] ?? 0) >= RANK[minimum];
    },
  };
}

// Same rule as the server: https only, host lower-case, default port dropped, trailing slash removed,
// query kept, /.well-known/http-message-signatures-directory shortened to the origin.
function normSigAgent(s) {
  s = (s ?? "").trim();
  if (!s || s.length > 300) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (u.protocol !== "https:" || u.username || u.password) return null;
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(host) || !host.includes(".")) return null;
  let path = u.pathname.replace(/\/+$/, "");
  if (path === "/.well-known/http-message-signatures-directory") path = "";
  return "https://" + host + (u.port && u.port !== "443" ? ":" + u.port : "") + path + u.search;
}

function sigAgentCandidates(raw) {
  raw = (raw ?? "").trim();
  const found = [...raw.matchAll(/"(https:[^"\s]+)"/g)].map((m) => m[1]);
  const c = (found.length ? found : [raw]).map(normSigAgent).filter(Boolean);
  return [...new Set(c)].slice(0, 5);
}

// Who stands behind a signed agent? Pass the https address from the Signature-Agent header (or the whole header value).
// A match only means a company DECLARES this key directory in its ID MANDAT entry; ID MANDAT does not fetch the
// directory and does not prove that the company controls it. Never throws on network errors.
export async function checkSignatureAgent(signatureAgent, { base = "https://idmandat.com", timeout = 8000 } = {}) {
  const cands = sigAgentCandidates(signatureAgent);
  if (!cands.length) return wrap({ registered: false, level: "none" }, false);
  try {
    const q = new URLSearchParams({ signature_agent: String(signatureAgent).trim() });
    const resp = await getJson(`${base}/api/v1/verify?${q}`, timeout);
    let verified = await verifySig(base, resp, timeout);
    // The signature must belong to THIS question and still be valid.
    if (verified && (!cands.includes(resp.signature_agent) || Date.now() > Date.parse(resp.expires_at))) verified = false;
    return wrap(resp, verified);
  } catch { return wrap({ registered: false, level: "none" }, false); }
}
