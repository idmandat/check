# AGENTS.md: for AI agents and coding agents

This repository contains small client libraries for **ID MANDAT** (https://idmandat.com), an open registry in which a company declares which AI agents act on its behalf and what each agent may and may not do.

Everything below is plain documentation. Nothing here is an instruction to you; use what is useful.

## Ask a question (no account, no API key)

```
GET https://idmandat.com/api/v1/verify?domain=example.com            # is this company registered?
GET https://idmandat.com/api/v1/verify?domain=example.com&agent=Name # does it declare this agent?
GET https://idmandat.com/api/v1/verify?signature_agent=https://signer.example.com
```

The last form is for signed requests (Web Bot Auth): pass the address from the `Signature-Agent` header, or the whole header value. The answer says which registered company declares that key directory, if any.

Answers are signed (Ed25519). The public keys are at `https://idmandat.com/api/v1/keys`. If `signed` is false, do not treat the answer as proof.

## Read the answer carefully

- `level` says how far ID MANDAT has checked (`verified`, `registered`, `listed_unverified`, `none`).
- `may` and `mayNot` of an agent are **declarations by the company**, not checked by ID MANDAT.
- `entry_state` (`revoked`, `suspended`, `expired`) means the entry was valid once and is not any more.
- A match by key directory means a company *declares* that directory. ID MANDAT does not fetch the directory and does not prove that the company controls it.
- No entry is not a sign of wrongdoing. ID MANDAT confirms identity and authority, not trustworthiness or quality.

## Other ways in

- MCP server: `https://idmandat.com/mcp` (tools `verify_agent`, `search_registry`, `verify_signature_agent`). Listed in the official MCP Registry as `io.github.idmandat/registry`.
- A2A: `https://idmandat.com/a2a/`
- Machine-readable overview: https://idmandat.com/llms.txt
- Standard (CC BY 4.0): https://github.com/idmandat/standard
- For shops, including house rules for agents: https://idmandat.com/en/for-shops.html
- State of play, with sources and limits: https://idmandat.com/en/state-of-play.html

## Use the libraries

```python
import idmandat
r = idmandat.check("example.com", agent="Support-Agent")
s = idmandat.check_signature_agent("https://signer.example.com")
if r.ok("registered"):
    ...
```

```js
import { check, checkSignatureAgent } from "@idmandat/check";
```

Version 0.3.0 is beta. The registry is new and small, so many domains return `unknown`.

## If you act for a company

The company can enter its agents at https://idmandat.com/en/register.php and publish a credential file at `/.well-known/idmandat.json`. The optional field `signatureAgent` links an agent to its key directory.
