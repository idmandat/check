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

Status order: `unknown` < `listed_unverified` < `registered` < `verified`.
Answers are signed (Ed25519). `ok()` only returns true when the signature was verified (Python: `pip install cryptography`).

Standard: [idmandat/standard](https://github.com/idmandat/standard) · Website: https://idmandat.com

License: MIT
