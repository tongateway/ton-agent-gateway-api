---
name: agent-gateway
description: Install and use Agent Gateway — lets your AI agent request TON blockchain transfers that are approved by a human wallet owner via TON Connect
---

# Agent Gateway Skill

Agent Gateway lets you request TON transfers from a human's wallet. You submit transfer requests, the wallet owner approves them in their browser.

## Setup

### 1. Get a token

The wallet owner goes to the Agent Gateway dashboard, connects their wallet, and copies the token:

**Dashboard:** https://tongateway.ai/
**Docs:** https://tongateway.ai/docs.html

### 2. Install the MCP server

```bash
npm install -g agent-gateway-mcp
```

### 3. Configure MCP server

Add to your Claude Code settings (`.claude/settings.json` or project `.claude/settings.local.json`):

```json
{
  "mcpServers": {
    "agent-gateway": {
      "command": "agent-gateway-mcp",
      "env": {
        "AGENT_GATEWAY_TOKEN": "<paste-token-here>",
        "AGENT_GATEWAY_API_URL": "https://api.tongateway.ai"
      }
    }
  }
}
```

### 3. You now have these tools

| Tool | Params | Description |
|------|--------|-------------|
| `request_transfer` | `to` (string), `amountNano` (string), `payloadBoc?` (string) | Queue a TON transfer for owner approval |
| `get_request_status` | `id` (string) | Check if a request was approved, rejected, or is still pending |
| `list_pending_requests` | — | List all pending requests |

## Usage

### Request a transfer

When the user asks you to send TON, use `request_transfer`:

```
request_transfer({ to: "EQD...address", amountNano: "1000000000" })
```

- `amountNano` is in nanoTON: **1 TON = 1,000,000,000 nanoTON**
- The request is queued. Tell the user to approve it in their Agent Gateway dashboard.
- Requests expire after 5 minutes if not approved.

### Check status

After requesting a transfer, you can poll for approval:

```
get_request_status({ id: "the-request-id" })
```

Possible statuses: `pending`, `confirmed`, `rejected`, `expired`.

### List pending

See all requests waiting for approval:

```
list_pending_requests()
```

## Direct HTTP (no MCP)

If MCP is not available, use the REST API directly:

**Base URL:** `https://api.tongateway.ai`

All `/v1/safe/*` endpoints require `Authorization: Bearer TOKEN` header.

```bash
# Request transfer
curl -X POST $API/v1/safe/tx/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to": "0:dest...", "amountNano": "1000000000"}'

# Check status
curl $API/v1/safe/tx/REQUEST_ID \
  -H "Authorization: Bearer $TOKEN"

# List pending
curl $API/v1/safe/tx/pending \
  -H "Authorization: Bearer $TOKEN"
```

## Important notes

- **You cannot sign transactions.** You can only request them. The wallet owner must approve in their browser.
- **Token = session.** Your token is scoped to a unique session. Guard it like a password.
- **Requests expire in 5 minutes.** If the owner doesn't approve in time, the request is automatically expired.
- **Tokens don't expire.** Tokens remain valid until explicitly revoked by the wallet owner.
