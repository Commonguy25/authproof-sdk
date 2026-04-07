# Delegation Receipt Protocol — Infrastructure

A cryptographic trust layer for AI agent authorization. This repo contains everything needed to run DRP as real persistent infrastructure.

---

## What's included

```
drp-infrastructure/
├── schema.sql                          — Supabase database schema + RLS
├── supabase/
│   └── functions/
│       ├── _shared/cors.ts             — CORS headers (shared)
│       ├── verify/index.ts             — POST /verify edge function
│       └── revoke/index.ts             — POST /revoke edge function
├── mcp-server.js                       — MCP stdio server for Claude Code
├── package.json                        — Node.js dependencies
├── delegation-receipt-protocol.html    — Frontend app (wired to Supabase)
└── README.md                           — This file
```

---

## 1. Set up Supabase

### Create a project

1. Go to [supabase.com](https://supabase.com) and create a free project.
2. Note your **Project URL** and **anon/public key** from Settings → API.
3. Also copy your **service_role key** — keep this secret, it's only used in edge functions.

### Run the schema

1. Open the Supabase Dashboard → **SQL Editor** → **New query**.
2. Paste the contents of `schema.sql` and click **Run**.

This creates the `receipts` table, indexes, and Row Level Security policies.

---

## 2. Deploy Edge Functions

You'll need the [Supabase CLI](https://supabase.com/docs/guides/cli).

```bash
npm install -g supabase
supabase login
supabase link --project-ref YOUR_PROJECT_REF
```

Deploy both functions:

```bash
supabase functions deploy verify
supabase functions deploy revoke
```

The functions automatically pick up `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` from the Supabase runtime environment — no manual env vars needed for deployment.

To test locally before deploying:

```bash
supabase start
supabase functions serve verify --env-file .env.local
```

Where `.env.local` contains:
```
SUPABASE_URL=http://localhost:54321
SUPABASE_SERVICE_ROLE_KEY=your-local-service-role-key
```

### Verify endpoint

```
POST https://YOUR_PROJECT.supabase.co/functions/v1/verify
Authorization: Bearer YOUR_ANON_KEY
Content-Type: application/json

{
  "hash": "abc123...",
  "proposed_action": "Search the web for competitor pricing"
}
```

Response:
```json
{
  "authorized": true,
  "result": "Action is authorized under this delegation receipt",
  "checks": [
    { "name": "Receipt exists",   "passed": true,  "detail": "..." },
    { "name": "Not revoked",      "passed": true,  "detail": "..." },
    { "name": "Time window",      "passed": true,  "detail": "..." },
    { "name": "Signature valid",  "passed": true,  "detail": "..." },
    { "name": "Hash integrity",   "passed": true,  "detail": "..." },
    { "name": "Scope alignment",  "passed": true,  "detail": "..." },
    { "name": "Boundary check",   "passed": true,  "detail": "..." }
  ],
  "receipt_context": { ... }
}
```

### Revoke endpoint

```
POST https://YOUR_PROJECT.supabase.co/functions/v1/revoke
Authorization: Bearer YOUR_ANON_KEY
Content-Type: application/json

{ "hash": "abc123..." }
```

---

## 3. Configure the HTML app

Open `delegation-receipt-protocol.html` in a text editor and fill in the two config constants near the top of the `<script>` block:

```js
const SUPABASE_URL      = 'https://YOUR_PROJECT.supabase.co';
const SUPABASE_ANON_KEY = 'YOUR_ANON_PUBLIC_KEY';
```

Once set:
- The mode badge in the topbar changes to **live mode** (green).
- Receipts are persisted to Supabase and verifiable by anyone with the hash.
- The **Revoke** button calls the revoke edge function.
- **Copy Link** generates a `?receipt=<hash>` URL — anyone who opens it lands on the Verify tab with the hash pre-filled.
- Your **device key** is persisted in IndexedDB — the same key is used across browser sessions on the same device. The key ID is shown in the topbar.

To host the app, you can drop the single HTML file anywhere: GitHub Pages, Vercel, Netlify, S3, etc.

---

## 4. Set up the MCP Server (for Claude Code)

The MCP server lets Claude Code agents issue and verify receipts without leaving their workflow.

### Install dependencies

```bash
cd drp-infrastructure
npm install
```

### Configure Claude Code

Add the following to your Claude Code MCP config file.

**macOS/Linux:** `~/.claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "drp": {
      "command": "node",
      "args": ["/absolute/path/to/drp-infrastructure/mcp-server.js"],
      "env": {
        "SUPABASE_URL": "https://YOUR_PROJECT.supabase.co",
        "SUPABASE_ANON_KEY": "YOUR_ANON_PUBLIC_KEY"
      }
    }
  }
}
```

Replace `/absolute/path/to/drp-infrastructure/` with the real path on your machine.

Restart Claude Code. You should now see two tools available:

### `issue_delegation_receipt`

Issues a cryptographically signed receipt and stores it in Supabase.

Parameters:
- `scope` (required) — what the agent is authorized to do
- `boundaries` (required) — what the agent must not do
- `operator_instructions` (required) — specific instructions embedded in the receipt
- `time_window_hours` (optional, default 24) — how long the receipt is valid

Example usage in Claude Code:
> "Issue me a delegation receipt authorizing you to search the web for competitor pricing but not access any internal documents, valid for 8 hours."

### `verify_action`

Verifies whether a proposed action is authorized under a receipt.

Parameters:
- `receipt_hash` (required) — the SHA-256 hash of the receipt
- `proposed_action` (required) — description of the action to check

Example usage in Claude Code:
> "Before searching, verify that action against receipt hash abc123..."

---

## 5. Environment variables summary

| Variable | Where used | How to get it |
|---|---|---|
| `SUPABASE_URL` | HTML app, MCP server | Supabase Dashboard → Settings → API |
| `SUPABASE_ANON_KEY` | HTML app, MCP server | Supabase Dashboard → Settings → API |
| `SUPABASE_SERVICE_ROLE_KEY` | Edge functions (auto-injected) | Supabase Dashboard → Settings → API |

---

## How it works

1. **Issue** — The browser generates an ECDSA P-256 keypair (persisted in IndexedDB). When you issue a receipt, the app signs a canonical JSON payload containing scope, boundaries, time window, and hashed operator instructions. The receipt + hash are stored in Supabase.

2. **Verify** — The `/verify` edge function retrieves the receipt, re-verifies the ECDSA signature server-side, checks the time window and revocation status, and optionally checks keyword alignment between the proposed action and the receipt's scope/boundaries.

3. **Revoke** — The `/revoke` edge function sets `revoked=true` in the database. All future `/verify` calls for that hash will fail the "Not revoked" check.

4. **MCP** — Claude Code agents call `issue_delegation_receipt` and `verify_action` via the MCP server, which proxies to the same Supabase endpoints.

---

## Security notes

- The **anon key** is safe to embed in the HTML — it can only read/insert receipts per the RLS policies.
- The **service_role key** is only used inside edge functions and never exposed to the browser.
- Receipts are signed with a device-specific key stored in IndexedDB. The private key is marked `extractable: true` to enable persistence — accept this trade-off or remove persistence for stricter security.
- For production, consider rate-limiting the `/verify` and insert endpoints via Supabase middleware.
