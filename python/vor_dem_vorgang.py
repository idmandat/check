"""ID MANDAT: Vor dem Vorgang nachfragen (Beispiel, Python 3.9+).

Braucht:  pip install cryptography
Prüft:    ist der Agent bei der Domain eingetragen, ist die Antwort echt signiert
          und frisch, ist der Eintrag nicht widerrufen/ausgesetzt/abgelaufen,
          und steht die geplante Handlung in "may" bzw. "mayNot".

Wichtig: "may"/"mayNot" sind Angaben des Unternehmens (declared_by_operator).
ID MANDAT bestätigt Identität und Befugnis, nicht Bonität, Vertrauenswürdigkeit
oder Qualität. Im Zweifel gilt: NICHT ausführen (fail closed).
"""
import base64, json, urllib.parse, urllib.request
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

API = "https://idmandat.com/api/v1"


def _b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _canon(o):
    if isinstance(o, dict):
        return {k: _canon(o[k]) for k in sorted(o)}
    if isinstance(o, list):
        return [_canon(x) for x in o]
    return o


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


def signature_ok(answer):
    """Echtheit prüfen: Ed25519 über die kanonische JSON-Antwort ohne 'signature'."""
    body = dict(answer)
    sig = body.pop("signature", None)
    if not answer.get("signed") or not sig or sig.get("alg") != "Ed25519":
        return False
    keys = {k["key_id"]: k for k in _get(API + "/keys")["keys"]}
    key = keys.get(answer.get("key_id"))
    if not key or key.get("status") != "active":
        return False
    msg = json.dumps(_canon(body), separators=(",", ":"), ensure_ascii=False).encode()
    try:
        Ed25519PublicKey.from_public_bytes(_b64u(key["public_key"])).verify(_b64u(sig["value"]), msg)
        return True
    except Exception:
        return False


def darf_ich(domain, agent_name, handlung):
    """Gibt (erlaubt, grund) zurück. erlaubt ist nur True, wenn alles klar ist."""
    q = urllib.parse.urlencode({"domain": domain, "agent": agent_name})
    try:
        a = _get(API + "/verify?" + q)
    except Exception as e:
        return False, "Abfrage fehlgeschlagen: %s" % e
    if not signature_ok(a):
        return False, "Antwort nicht (gültig) signiert"
    if datetime.fromisoformat(a["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc):
        return False, "Antwort abgelaufen, neu abfragen"
    if not a.get("registered"):
        return False, "nicht registriert (%s)" % a.get("entry_state", "unbekannt")
    if a.get("entry_state") or a.get("revoked"):
        return False, "Eintrag gilt nicht: %s" % a.get("entry_state", "widerrufen")
    treffer = [x for x in a.get("agents", []) if x.get("name") == agent_name]
    if not treffer:
        return False, "Agent steht nicht in der Liste dieser Domain"
    ag = treffer[0]
    if handlung in ag.get("mayNot", []):
        return False, "Handlung ist ausdrücklich ausgeschlossen (mayNot)"
    if handlung not in ag.get("may", []):
        return False, "Handlung ist nicht ausdrücklich erlaubt (may)"
    return True, "erlaubt laut Erklärung des Unternehmens (declared_by_operator)"


if __name__ == "__main__":
    print(darf_ich("idmandat.com", "Grok (xAI)", "draft_social_posts"))
    print(darf_ich("idmandat.com", "Grok (xAI)", "place_order"))
