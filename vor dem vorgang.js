// ID MANDAT: Vor dem Vorgang nachfragen (Beispiel, Node 18+, keine Pakete nötig).
// may/mayNot sind Angaben des Unternehmens. Im Zweifel: NICHT ausführen.
import { createPublicKey, verify } from "node:crypto";

const API = "https://idmandat.com/api/v1";
const get = async (u) => { const r = await fetch(u); if (!r.ok) throw new Error(r.status); return r.json(); };
const canon = (o) => Array.isArray(o) ? o.map(canon)
  : (o && typeof o === "object") ? Object.fromEntries(Object.keys(o).sort().map(k => [k, canon(o[k])])) : o;
const b64u = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

async function signaturOk(a) {
  const { signature, ...body } = a;
  if (!a.signed || !signature || signature.alg !== "Ed25519") return false;
  const key = (await get(API + "/keys")).keys.find(k => k.key_id === a.key_id && k.status === "active");
  if (!key) return false;
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.public_key }, format: "jwk" });
  return verify(null, Buffer.from(JSON.stringify(canon(body))), pub, b64u(signature.value));
}

export async function darfIch(domain, agent, handlung) {
  let a;
  try { a = await get(`${API}/verify?domain=${encodeURIComponent(domain)}&agent=${encodeURIComponent(agent)}`); }
  catch (e) { return [false, "Abfrage fehlgeschlagen: " + e.message]; }
  if (!(await signaturOk(a))) return [false, "Antwort nicht (gültig) signiert"];
  if (new Date(a.expires_at) < new Date()) return [false, "Antwort abgelaufen, neu abfragen"];
  if (!a.registered) return [false, "nicht registriert (" + (a.entry_state ?? "unbekannt") + ")"];
  if (a.entry_state || a.revoked) return [false, "Eintrag gilt nicht: " + (a.entry_state ?? "widerrufen")];
  const ag = (a.agents ?? []).find(x => x.name === agent);
  if (!ag) return [false, "Agent steht nicht in der Liste dieser Domain"];
  if ((ag.mayNot ?? []).includes(handlung)) return [false, "Handlung ausdrücklich ausgeschlossen (mayNot)"];
  if (!(ag.may ?? []).includes(handlung)) return [false, "Handlung nicht ausdrücklich erlaubt (may)"];
  return [true, "erlaubt laut Erklärung des Unternehmens (declared_by_operator)"];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(await darfIch("idmandat.com", "Grok (xAI)", "draft_social_posts"));
  console.log(await darfIch("idmandat.com", "Grok (xAI)", "place_order"));
}
