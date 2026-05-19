# Authproof Templates

Quick-start examples showing Authproof receipt creation and scope checking in two common agent frameworks.

## Prerequisites

**JavaScript template** — Node.js 18 or later (uses native `crypto.subtle`).

**Python template** — Python 3.10 or later. No packages required; uses stdlib only.

## Running the templates

From the repo root:

```bash
# JavaScript (Cursor / Claude Code style)
node authproof-cloud/templates/cursor-claude-template.js

# Python (CrewAI / LangGraph style)
python authproof-cloud/templates/crewai-langraph-template.py
```

Each template prints a PERMIT decision and a DENY decision with the reason.

## What the templates show

| File | Framework | Auth method |
|------|-----------|-------------|
| `cursor-claude-template.js` | Cursor / Claude Code agent | Real ECDSA-signed receipt via JS SDK |
| `crewai-langraph-template.py` | CrewAI / LangGraph agent | Simulated receipt (stdlib only) |

## Moving to production

**JavaScript** — the template already uses the real `AuthProof.create()` and `AuthProof.verify()` from `src/authproof.js`. Add an API key and log receipts to Authproof Cloud:

```js
import AuthProofClient from 'authproof/client';
const client = new AuthProofClient({ apiKey: process.env.AUTHPROOF_KEY });
```

**Python** — replace the simulated `create_receipt()` with `AuthProofClient.delegate()` from `authproof-py`:

```python
pip install authproof-py
from authproof import AuthProofClient, ScopeSchema
```

## Full SDK docs

[https://github.com/Commonguy25/authproof-sdk](https://github.com/Commonguy25/authproof-sdk)
