# Agent Gateway — API

Cloudflare Worker API for [Agent Gateway](https://tongateway.ai). Handles authentication, safe transfers, wallet reads, agent wallets, and TON Connect bridge.

**Live at [api.tongateway.ai](https://api.tongateway.ai/docs)**

## Endpoints

| Group | Endpoints |
|-------|-----------|
| **Auth** | `/v1/auth/token`, `/v1/auth/me`, `/v1/auth/request`, `/v1/auth/check/:id`, `/v1/auth/connect` |
| **Safe Transfers** | `/v1/safe/tx/transfer`, `/v1/safe/tx/pending`, `/v1/safe/tx/:id`, confirm, reject |
| **Wallet** | `/v1/wallet/balance`, `/v1/wallet/jettons`, `/v1/wallet/transactions`, `/v1/wallet/nfts` |
| **Lookup** | `/v1/dns/:domain/resolve`, `/v1/market/price` |
| **Agent Wallet** | `/v1/agent-wallet/deploy`, `/v1/agent-wallet/execute`, `/v1/agent-wallet/info`, `/v1/agent-wallet/list` |

## Deploy

Auto-deploys on push to `main` via GitHub Actions + Cloudflare Workers.

## Related

| Repository | Description |
|---|---|
| [@tongateway/mcp](https://github.com/tongateway/mcp) | MCP server (14 tools) |
| [ton-agent-gateway-client](https://github.com/tongateway/ton-agent-gateway-client) | Landing page + dashboard |
| [ton-agent-gateway-contract](https://github.com/tongateway/ton-agent-gateway-contract) | Agent Wallet smart contract |
| [ton-agent-gateway](https://github.com/tongateway/ton-agent-gateway) | Main repo with overview |
