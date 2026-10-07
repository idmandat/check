"""idmandat – check who stands behind an AI agent, in one line.

    import idmandat
    r = idmandat.check("example.com", agent="Support-Agent")
    if r.ok("registered"):   # registered or verified
        ...

Needs only the standard library. For signature checking install `cryptography`
(pip install cryptography); without it r.verified is False.
License: MIT
"""
import base64, json, time, urllib.parse, urllib.request

__version__ = "0.1.0"
BASE = "https://idmandat.com"
_RANK = {"unknown": 0, "listed_unverified": 1, "registered": 2, "verified": 3}
_keys = {}


class Result:
    def __init__(self, data, verified):
        self.data, self.verified = data, verified
        self.found = bool(data.get("found"))
        self.status = data.get("status", "unknown")
        self.organization = data.get("organization")
        self.agent = data.get("agent")
        self.agent_listed = data.get("agentListed")
        self.how_to_register = data.get("howToRegister")

    def ok(self, minimum="registered", require_signature=True):
        """True if the status is at least `minimum` (listed_unverified < registered < verified)
        and, by default, the signature was checked successfully and is still valid."""
        if require_signature and not self.verified:
            return False
        if self.agent_listed is False:
            return False
        return _RANK.get(self.status, 0) >= _RANK[minimum]

    def __repr__(self):
        return f"<idmandat {self.status} verified_signature={self.verified}>"


def _get(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": f"python-idmandat/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _verify(base, resp, timeout):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False
    try:
        if base not in _keys or time.time() - _keys[base][1] > 3600:
            _keys[base] = (_get(base + "/.well-known/idmandat-key.json", timeout), time.time())
        keys = {k["keyId"]: k for k in _keys[base][0]["keys"]}
        k = keys.get(resp.get("keyId"))
        if not k:
            return False
        Ed25519PublicKey.from_public_bytes(base64.b64decode(k["publicKey"])).verify(
            base64.b64decode(resp["signature"]), resp["payload"].encode("utf-8"))
        return True
    except Exception:
        return False


def check(domain, agent=None, base=BASE, timeout=8):
    """Look up a domain (and optionally an agent name). Never raises on network errors:
    in that case the result is status 'unknown' with verified=False."""
    q = {"domain": domain}
    if agent:
        q["agent"] = agent
    try:
        resp = _get(f"{base}/check?{urllib.parse.urlencode(q)}", timeout)
        data = json.loads(resp["payload"])
        verified = _verify(base, resp, timeout)
        if verified and time.time() > _parse(data.get("validUntil")):
            verified = False
        return Result(data, verified)
    except Exception:
        return Result({"found": False, "status": "unknown"}, False)


def _parse(iso):
    from datetime import datetime
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0
