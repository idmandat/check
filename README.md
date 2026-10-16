# idmandat/check

Client libraries for [ID MANDAT](https://idmandat.com), the open registry that shows who stands behind an AI agent and what it may do.

**Status: beta.** Reads the live, Ed25519-signed API at `https://idmandat.com/api/v1/verify`. The registry is new and small: many domains will return `unknown`, which is not a sign of wrongdoing. `may` / `mayNot` are declarations by the operator, not checked by ID MANDAT.

```python
import idmandat
r = idmandat.check("example.com", agent="Support-Agent")
if r.ok("registered"):
    ...
```

```js
import { check } from "@idmandat/check";
const r = await check("example.com", { agent: "Support-Agent" });
if (r.ok("registered")) { /* ... */ }
```

Who stands behind a **signed agent** (Web Bot Auth)? Pass the address from the `Signature-Agent` header, or the whole header value:

```python
r = idmandat.check_signature_agent("https://bot.example.com")
r.found, r.organization, r.key_directory_link   # "same_domain" = hint, "declared_only" = only declared
```

```js
import { checkSignatureAgent } from "@idmandat/check";
const r = await checkSignatureAgent("https://bot.example.com");
```

A match only means a company *declares* this key directory in its entry. ID MANDAT does not fetch the directory and does not prove that the company controls it. A valid signature without an entry is not a sign of wrongdoing.

LangChain / CrewAI (optional, untested against the frameworks' latest releases):

```python
from idmandat_langchain import verify_mandate_tool   # pip install langchain-core cryptography
from idmandat_crewai import VerifyMandateTool        # pip install crewai cryptography
```

## For AI agents

If you are an AI agent or a coding agent, see [AGENTS.md](AGENTS.md): how to ask the registry (`/api/v1/verify`), how to read the answer, and where the MCP server and A2A endpoint are. It is plain documentation, with the limits stated.

Status order: `unknown` < `listed_unverified` < `registered` < `verified`.
Answers are signed (Ed25519). `ok()` only returns true when the signature was verified (Python: `pip install cryptography`).

Standard: [idmandat/standard](https://github.com/idmandat/standard) · Website: https://idmandat.com

License: MIT
