# Agent API Monorepo (TON)

Two separate folders are created:

- `contract/` - TON FunC smart contract (`AgentVault`) with owner/admin/session-key policy
- `api/` - Fastify Swagger API for signing/building/broadcasting vault transactions

## Quick start

### Contract

```bash
cd contract
npm install
npm run build
npm test
```

### API

```bash
cd api
cp .env.example .env
npm install
npm run dev
```

Swagger will be available at `http://localhost:8080/docs`.

The API includes generic transaction routes plus open4dev order-book helpers:

- `POST /v1/open4dev/orders/create-ton`
- `POST /v1/open4dev/orders/create-jetton`
