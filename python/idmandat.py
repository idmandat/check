"""idmandat – check who stands behind an AI agent, in one line.

    import idmandat
    r = idmandat.check("example.com", agent="Support-Agent")
    if r.ok("registered"):   # registered or verified
        ...

Needs only the standard library. For signature checking install `cryptography`
(pip install cryptography); without it r.verified is False and r.ok() is False.

Reads https://idmandat.com/api/v1/verify (signed with Ed25519, public keys at /api/v1/keys).
`may` / `mayNot` of an agent are declarations by the operator, not checked by ID MANDAT.
ID MANDAT confirms identity and authority, not trustworthiness or quality.
License: MIT
"""
import base64, json, time, urllib.parse, urllib.request
from datetime import datetime

__version__ = "0.2.0"
BASE = "https://idmandat.com"
_RANK = {"unknown": 0, "listed_unverified": 1, "registered": 2, "verified": 3}
_keys = {}


class Result:
    def __init__(self, data, verified):
        self.data, self.verified = data, verified
        self.found = bool(data.get("registered"))
        level = data.get("level", "none")
        self.status = level if level in _RANK else "unknown"
        self.organization = data.get("organization")
        self.agents = data.get("agents") or []
        self.agent_listed = data.get("agent_found")  # None if no agent name was asked for
        self.how_to_register = data.get("register")

    def ok(self, minimum="registered", require_signature=True):
        """True if the status is at least `minimum` (listed_unverified < registered < verified)
        and, by default, the signature was checked successfully and is still valid."""
        if require_signature and not self.verified:
            return False
        if self.agent_listed is False:
            return False
        return _RANK.get(self.status, 0) >= _RANK[minimum]

    def summary(self):
        """Short plain-text summary, e.g. as the answer of an LLM tool."""
        if not self.found:
            return "No entry at ID MANDAT for this domain. This is not by itself a sign of wrongdoing."
        sig = "signature valid" if self.verified else "NO valid signature - do not treat as proof"
        lines = [f"{self.organization}: level={self.status}, {sig}."]
        if self.agent_listed is False:
            lines.append("The requested agent name is NOT declared for this company.")
        for a in self.agents:
            lines.append(f"Agent '{a.get('name')}': may={a.get('may')}, may not={a.get('mayNot')} (declared by the operator).")
        if not self.agents:
            lines.append("No agents declared.")
        lines.append("ID MANDAT confirms identity and authority, not trustworthiness or quality.")
        return "\n".join(lines)

    def __repr__(self):
        return f"<idmandat {self.status} verified_signature={self.verified}>"


def _get(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": f"python-idmandat/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _sorted(v):
    if isinstance(v, dict):
        return {k: _sorted(v[k]) for k in sorted(v)}
    if isinstance(v, list):
        return [_sorted(x) for x in v]
    return v


def _canonical(d):
    # Same rule as the server: keys sorted recursively, compact, no escaping of unicode or "/".
    return json.dumps(_sorted(d), ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify(base, resp, timeout):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False
    try:
        sig = resp.get("signature")
        if not resp.get("signed") or not isinstance(sig, dict) or sig.get("alg") != "Ed25519":
            return False
        if base not in _keys or time.time() - _keys[base][1] > 3600:
            _keys[base] = (_get(base + "/api/v1/keys", timeout), time.time())
        keys = {k["key_id"]: k for k in _keys[base][0]["keys"]}
        k = keys.get(resp.get("key_id"))
        if not k:
            return False
        body = {x: y for x, y in resp.items() if x != "signature"}
        Ed25519PublicKey.from_public_bytes(_b64u(k["public_key"])).verify(_b64u(sig["value"]), _canonical(body))
        return True
    except Exception:
        return False


def _parse(iso):
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0


def _norm(domain):
    d = domain.strip().lower()
    for p in ("https://", "http://"):
        if d.startswith(p):
            d = d[len(p):]
    return d.split("/")[0]


def check(domain, agent=None, base=BASE, timeout=8):
    """Look up a domain (and optionally an agent name). Never raises on network errors:
    in that case the result is status 'unknown' with verified=False."""
    q = {"domain": _norm(domain)}
    if agent:
        q["agent"] = agent
    try:
        resp = _get(f"{base}/api/v1/verify?{urllib.parse.urlencode(q)}", timeout)
        verified = _verify(base, resp, timeout)
        # The signature must belong to THIS question and still be valid.
        if verified and (resp.get("domain") != q["domain"] or time.time() > _parse(resp.get("expires_at"))):
            verified = False
        return Result(resp, verified)
    except Exception:
        return Result({"registered": False, "level": "none"}, False)
