"""idmandat – check who stands behind an AI agent, in one line.

    import idmandat
    r = idmandat.check("example.com", agent="Support-Agent")
    if r.ok("registered"):   # registered or verified
        ...

    r = idmandat.check_signature_agent("https://bot.example.com")   # from the Signature-Agent header

Needs only the standard library. For signature checking install `cryptography`
(pip install cryptography); without it r.verified is False and r.ok() is False.

Reads https://idmandat.com/api/v1/verify (signed with Ed25519, public keys at /api/v1/keys).
`may` / `mayNot` of an agent are declarations by the operator, not checked by ID MANDAT.
ID MANDAT confirms identity and authority, not trustworthiness or quality.
License: MIT
"""
import base64, json, re, time, urllib.parse, urllib.request
from datetime import datetime

__version__ = "0.3.0"
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
        # "revoked", "suspended" or "expired" when the entry WAS valid but no longer is; otherwise None.
        self.entry_state = data.get("entry_state")
        self.revoked = data.get("revoked") is True
        # Only for lookups by key directory (check_signature_agent):
        self.signature_agent = data.get("signature_agent")
        self.ambiguous = data.get("ambiguous") is True
        self.claimed_by = data.get("claimed_by") or []
        # "same_domain" (hint, not proof) or "declared_only"; None if not a key-directory lookup.
        self.key_directory_link = data.get("key_directory_link")

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
        if self.entry_state:
            since = self.data.get("state_since")
            return (f"The ID MANDAT entry for this domain is {self.entry_state}"
                    + (f" (since {since})" if since else "")
                    + ". Do not rely on earlier answers or on any ID MANDAT seal shown by this domain.")
        if self.ambiguous:
            return ("Several entries at ID MANDAT declare this key directory ("
                    + ", ".join(map(str, self.claimed_by)) + "). It does not tell you who is responsible for the agent.")
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


def _norm_sigagent(s):
    """Same rule as the server: https only, host lower-case, default port dropped, trailing slash
    removed, query kept, /.well-known/http-message-signatures-directory shortened to the origin."""
    s = (s or "").strip()
    if not s or len(s) > 300:
        return None
    try:
        p = urllib.parse.urlsplit(s)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port or 443
    except ValueError:
        return None
    if p.scheme != "https" or not host or p.username or p.password:
        return None
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", host) or "." not in host:
        return None
    path = p.path.rstrip("/")
    if path == "/.well-known/http-message-signatures-directory":
        path = ""
    return "https://" + host + (f":{port}" if port != 443 else "") + path + ("?" + p.query if p.query else "")


def _candidates(raw):
    raw = (raw or "").strip()
    found = re.findall(r'"(https:[^"\s]+)"', raw)
    cands = [_norm_sigagent(u) for u in found] if found else [_norm_sigagent(raw)]
    out = []
    for c in cands:
        if c and c not in out:
            out.append(c)
    return out[:5]


def check_signature_agent(signature_agent, base=BASE, timeout=8):
    """Who stands behind a signed agent? Pass the https address from the Signature-Agent header
    (or the whole header value). Returns a Result like check(); also see r.signature_agent,
    r.ambiguous, r.claimed_by, r.key_directory_link.

    Caution: a match only means a company DECLARES this key directory in its ID MANDAT entry.
    ID MANDAT does not fetch the directory and does not prove that the company controls it.
    Never raises on network errors: the result is then status 'unknown' with verified=False."""
    cands = _candidates(signature_agent)
    if not cands:
        return Result({"registered": False, "level": "none"}, False)
    try:
        resp = _get(f"{base}/api/v1/verify?{urllib.parse.urlencode({'signature_agent': signature_agent.strip()})}", timeout)
        verified = _verify(base, resp, timeout)
        # The signature must belong to THIS question and still be valid.
        if verified and (resp.get("signature_agent") not in cands or time.time() > _parse(resp.get("expires_at"))):
            verified = False
        return Result(resp, verified)
    except Exception:
        return Result({"registered": False, "level": "none"}, False)
