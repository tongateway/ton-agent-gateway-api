import {
  buildSignedTransferMessage,
  wrapSignedBodyIntoExternalMessage,
} from './services/tonMessage';
import { TcSession, bridgeSendTransaction, bridgeSendMessages, bridgePollResponses, BridgeResponse } from './bridge';
import { SignAndExecuteSchema, ExecuteSignedSchema, RawExecuteSchema } from './schemas/tx';
import { resolveSecretKeyFromHex } from './utils/keys';
import { toSafeNumber } from './utils/numbers';
import { CreateJettonOrderSchema, CreateTonOrderSchema, SafeCreateTonOrderSchema, SafeCreateJettonOrderSchema } from './schemas/open4dev';
import { buildCreateJettonOrderMessage, buildCreateTonOrderMessage, buildTonOrderPayload, buildJettonOrderPayload } from './services/open4devOrderBook';
import { createTonApiClient } from './tonapi';

interface Env {
  TON_BROADCAST_URL?: string;
  TON_API_KEY?: string;
  TON_API_KEY_HEADER?: string;
  JWT_SECRET?: string;
  PENDING_STORE: KVNamespace;
  TONAPI_BASE_URL?: string;
  TONAPI_KEY?: string;
}

// --- CORS ---

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...CORS_HEADERS,
    },
  });
}

function html(body: string): Response {
  return new Response(body, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      ...CORS_HEADERS,
    },
  });
}

// --- JWT (HS256 via Web Crypto) ---

const encoder = new TextEncoder();

async function jwtSign(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const claims = { ...payload, iat: now };

  const b64Header = btoa(JSON.stringify(header)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const b64Payload = btoa(JSON.stringify(claims)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const data = `${b64Header}.${b64Payload}`;

  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const b64Sig = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${data}.${b64Sig}`;
}

async function jwtVerify(token: string, secret: string): Promise<Record<string, unknown> | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const data = `${parts[0]}.${parts[1]}`;
  const sig = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, sig, encoder.encode(data));
  if (!valid) return null;

  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

  return payload;
}

async function authenticate(request: Request, env: Env): Promise<{ address: string; sessionId: string } | null> {
  const auth = request.headers.get('Authorization');
  if (!auth?.startsWith('Bearer ')) return null;

  const payload = await jwtVerify(auth.slice(7), env.JWT_SECRET ?? 'change-me-in-production');
  if (!payload || typeof payload.address !== 'string' || typeof payload.sid !== 'string') return null;

  // Check session is not revoked
  const session = await env.PENDING_STORE.get(`ses:${payload.sid}`);
  if (!session) return null;

  return { address: payload.address, sessionId: payload.sid };
}

// --- Session Store (KV-backed) ---

interface Session {
  sid: string;
  address: string;
  label: string;
  createdAt: number;
}

async function createSession(kv: KVNamespace, sid: string, address: string, label: string): Promise<Session> {
  const session: Session = { sid, address, label, createdAt: Date.now() };
  await kv.put(`ses:${sid}`, JSON.stringify(session));
  await kv.put(`sidx:${address}:${sid}`, sid);
  return session;
}

async function listSessions(kv: KVNamespace, address: string): Promise<Session[]> {
  const list = await kv.list({ prefix: `sidx:${address}:` });
  const sessions: Session[] = [];
  for (const key of list.keys) {
    const sid = key.name.split(':').pop();
    const raw = await kv.get(`ses:${sid}`);
    if (raw) sessions.push(JSON.parse(raw));
  }
  return sessions;
}

async function revokeSession(kv: KVNamespace, sid: string, address: string): Promise<boolean> {
  const raw = await kv.get(`ses:${sid}`);
  if (!raw) return false;
  const session: Session = JSON.parse(raw);
  if (session.address !== address) return false;
  await kv.delete(`ses:${sid}`);
  await kv.delete(`sidx:${address}:${sid}`);
  return true;
}

async function revokeAllSessions(kv: KVNamespace, address: string, exceptSid: string): Promise<number> {
  const sessions = await listSessions(kv, address);
  let count = 0;
  for (const s of sessions) {
    if (s.sid === exceptSid) continue;
    await kv.delete(`ses:${s.sid}`);
    await kv.delete(`sidx:${address}:${s.sid}`);
    count++;
  }
  return count;
}

async function findSessionByLabel(kv: KVNamespace, address: string, label: string): Promise<Session | null> {
  const sessions = await listSessions(kv, address);
  return sessions.find(s => s.label === label) ?? null;
}

// --- TON Connect Session Storage ---

async function saveTcSession(kv: KVNamespace, address: string, session: TcSession): Promise<void> {
  await kv.put(`tc:${address}`, JSON.stringify(session));
}

async function loadTcSession(kv: KVNamespace, address: string): Promise<TcSession | null> {
  const raw = await kv.get(`tc:${address}`);
  return raw ? JSON.parse(raw) : null;
}

async function getTcLastEventId(kv: KVNamespace, address: string): Promise<string | undefined> {
  return (await kv.get(`tclast:${address}`)) ?? undefined;
}

async function setTcLastEventId(kv: KVNamespace, address: string, id: string): Promise<void> {
  await kv.put(`tclast:${address}`, id);
}

// --- Agent Wallet Storage ---

interface AgentWalletConfig {
  address: string;          // vault contract address
  adminAddress: string;     // owner wallet address
  ownerPublicKey: string;   // hex
  agentSecretKey: string;   // hex (64 bytes ed25519 secret key)
  agentPublicKey: string;   // hex (32 bytes)
  walletId: number;
  createdAt: number;
}

async function saveAgentWallet(kv: KVNamespace, config: AgentWalletConfig): Promise<void> {
  await kv.put(`aw:${config.address}`, JSON.stringify(config));
  // Index by admin address for listing
  await kv.put(`awidx:${config.adminAddress}:${config.address}`, config.address);
}

async function loadAgentWallet(kv: KVNamespace, address: string): Promise<AgentWalletConfig | null> {
  const raw = await kv.get(`aw:${address}`);
  return raw ? JSON.parse(raw) : null;
}

async function listAgentWallets(kv: KVNamespace, adminAddress: string): Promise<AgentWalletConfig[]> {
  const list = await kv.list({ prefix: `awidx:${adminAddress}:` });
  const wallets: AgentWalletConfig[] = [];
  for (const key of list.keys) {
    const addr = key.name.split(':').pop();
    if (!addr) continue;
    const raw = await kv.get(`aw:${addr}`);
    if (raw) wallets.push(JSON.parse(raw));
  }
  return wallets;
}

// --- DEX Pool Config ---

interface DexPairConfig {
  pair: string;            // e.g. "NOT/TON"
  direction: 'ton' | 'jetton'; // which side we're selling
  dexVaultAddress: string;
  oppositeVaultAddress: string;
  jettonMinter: string;    // the jetton's minter address
  providerFeeAddress: string;
  feeNum: number;
  feeDenom: number;
  matcherFeeNum: number;
  matcherFeeDenom: number;
  slippage: number;        // default slippage
}

// Hardcoded open4dev vault addresses
const DEX_VAULTS: Record<string, string> = {
  'TON':   'EQCoNUjjTEfzMAITVIPTUjSROXOiqS1K4vNAq9LW0EWNb1bg',
  'NOT':   'EQD7vaWSbY38DqQ0zY2hNvagO2M-AuL7InUHN4_x2ThceN6J',
  'USDT':  'EQBrozHGTEwumr5ND62CpUXqmfYyi1UucbIj-15ZJnlFLe9U',
  'DOGS':  'EQCzqK8_LNpqyXviutwVJUhw30FcAs6YL8HO9cMNCEaAybpt',
  'BUILD': 'EQDJ-N9sbbh2vNmbJ9DANEWpHdZqW2y8qAAnoBS5rY9fVdLO',
  'CBBTC': 'EQCYdHD4Pwz5ZtDlyCmSc5XjnfefXeAK2TE1Vz356xr6ILSZ',
  'PX':    'EQA6kzh2-YZbJa5L9PUu7dDCQDs52-uVQDxBIXFFp6b0ATmZ',
  'XAUT0': 'EQA9cFoL4hcjOsMTYHHxG0hNyGoikG11oabAQuVQwRKFUhq5',
  'AGNT':  'EQCfzBzukuhvyXvKwFXq9nffu_YRngAJugAuR5ibQ7Arcl1w',
};

const DEX_JETTON_MINTERS: Record<string, string> = {
  'NOT':   '0:2f956143c461769579baef2e32cc2d7bc18283f40d20bb03e432cd603ac33ffc',
  'USDT':  '0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe',
  'DOGS':  '0:afc49cb8786f21c87045b19ede78fc14b3257e54302a1f7c0e5228a26e6de710',
  'AGNT':  '0:9fcc1cee92e86fc97bcac055eaf677dfbbf6119e0009ba002e47989b43b02b72',
  'BUILD': '0:589d4ac897006b5aaa7fae5f95c5e481bd34765664df0b831a9d0eb9ee7fc150',
  'CBBTC': '0:e1c8fcdb223253fd69d8de01a9ae349850af5f88632358c7b3c4ef0c66251d7d',
  'PX':    '0:78db4c90b19a1b19ccb45580df48a1e91b6410970fa3d5ffed3eed49e3cf08ff',
  'XAUT0': '0:3547f2ee4022c794c80ea354b81bb63b5b571dd05ac091b035d19abbadd74ac6',
};

const DEX_DEFAULT_FEE_ADDRESS = '0:250b6998bae9a23f5690ff2333a759985181bc875dc973871d99602106a6aa99';
const DEX_DEFAULT_SLIPPAGE = 100; // 1%

const TOKEN_DECIMALS: Record<string, number> = {
  TON: 9, NOT: 9, BUILD: 9, DOGS: 9, PX: 9, AGNT: 9, CBBTC: 9,
  USDT: 6, XAUT0: 6,
};

function getTokenDecimals(symbol: string): number {
  return TOKEN_DECIMALS[symbol.toUpperCase()] ?? 9;
}

function calculatePriceRate(price: number, toDecimals: number, fromDecimals: number): bigint {
  // Convert to 18-decimal base
  const priceStr = price.toFixed(18);
  const [whole, frac = ''] = priceStr.split('.');
  const paddedFrac = frac.padEnd(18, '0').slice(0, 18);
  const priceRateBase = BigInt(whole + paddedFrac);

  // Adjust for decimal difference
  if (fromDecimals > toDecimals) {
    const diff = fromDecimals - toDecimals;
    return priceRateBase / BigInt(10 ** diff);
  } else if (fromDecimals < toDecimals) {
    const diff = toDecimals - fromDecimals;
    return priceRateBase * BigInt(10 ** diff);
  }
  return priceRateBase;
}

function calculateSlippage(slippagePercent: number): bigint {
  // 1% = 10^7, stored as uint30
  return BigInt(Math.floor(slippagePercent * 10_000_000));
}

function getDexPair(fromToken: string, toToken: string): DexPairConfig | null {
  const from = fromToken.toUpperCase();
  const to = toToken.toUpperCase();
  const fromVault = DEX_VAULTS[from];
  const toVault = DEX_VAULTS[to];
  if (!fromVault || !toVault) return null;

  const isTonSell = from === 'TON';
  return {
    pair: `${from}/${to}`,
    direction: isTonSell ? 'ton' : 'jetton',
    dexVaultAddress: fromVault,
    oppositeVaultAddress: toVault,
    jettonMinter: DEX_JETTON_MINTERS[to] ?? '',  // target token minter (what we're buying)
    providerFeeAddress: DEX_DEFAULT_FEE_ADDRESS,
    feeNum: 100,
    feeDenom: 10000,
    matcherFeeNum: 200,
    matcherFeeDenom: 10000,
    slippage: DEX_DEFAULT_SLIPPAGE,
  };
}

function listAvailablePairs(): string[] {
  const tokens = Object.keys(DEX_VAULTS);
  const pairs: string[] = [];
  for (const a of tokens) {
    for (const b of tokens) {
      if (a !== b) pairs.push(`${a}/${b}`);
    }
  }
  return pairs;
}

// --- Agent Auth Flow ---

interface AuthRequest {
  authId: string;
  status: 'pending' | 'completed';
  token?: string;
  address?: string;
  sessionId?: string;
  createdAt: number;
  expiresAt: number;
  // TC keypair generated server-side for bridge push
  tcSecretKey?: string;
  tcPublicKey?: string;
}

async function createAuthRequest(kv: KVNamespace): Promise<AuthRequest> {
  const authId = crypto.randomUUID();
  const now = Date.now();

  // Generate TC keypair server-side for bridge push
  const nacl = await import('tweetnacl');
  const tcKp = nacl.default.box.keyPair();
  const tcSecretKey = Array.from(tcKp.secretKey).map(b => b.toString(16).padStart(2, '0')).join('');
  const tcPublicKey = Array.from(tcKp.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');

  const req: AuthRequest = {
    authId,
    status: 'pending',
    createdAt: now,
    expiresAt: now + 10 * 60 * 1000,
    tcSecretKey,
    tcPublicKey,
  };
  await kv.put(`auth:${authId}`, JSON.stringify(req), { expirationTtl: 600 });
  return req;
}

async function getAuthRequest(kv: KVNamespace, authId: string): Promise<AuthRequest | null> {
  const raw = await kv.get(`auth:${authId}`);
  return raw ? JSON.parse(raw) : null;
}

async function completeAuthRequest(kv: KVNamespace, authId: string, token: string, address: string, sessionId: string): Promise<AuthRequest | null> {
  const raw = await kv.get(`auth:${authId}`);
  if (!raw) return null;
  const req: AuthRequest = JSON.parse(raw);
  if (req.status !== 'pending') return null;
  req.status = 'completed';
  req.token = token;
  req.address = address;
  req.sessionId = sessionId;
  await kv.put(`auth:${authId}`, JSON.stringify(req)); // no TTL — token is permanent
  return req;
}

async function processBridgeResponses(kv: KVNamespace, address: string, env: Env): Promise<void> {
  const tcSession = await loadTcSession(kv, address);
  if (!tcSession) return;

  const lastEventId = await getTcLastEventId(kv, address);
  const { responses, lastEventId: newLastEventId } = await bridgePollResponses(tcSession, lastEventId);

  if (newLastEventId && newLastEventId !== lastEventId) {
    await setTcLastEventId(kv, address, newLastEventId);
  }

  for (const response of responses) {
    const reqId = response.id;
    const req = await kvGetByIdForWallet(kv, reqId, address);
    if (!req || req.status !== 'pending') continue;

    if (response.error) {
      req.status = 'rejected';
      await kvUpdate(kv, req);
    } else if (response.result) {
      req.status = 'confirmed';
      req.txHash = response.result;
      // Broadcast signed BOC
      try {
        if (env.TON_BROADCAST_URL) {
          const headers: Record<string, string> = { 'content-type': 'application/json' };
          if (env.TON_API_KEY && env.TON_API_KEY_HEADER) {
            headers[env.TON_API_KEY_HEADER] = env.TON_API_KEY;
          }
          const broadcastRes = await fetch(env.TON_BROADCAST_URL, {
            method: 'POST',
            headers,
            body: JSON.stringify({ boc: response.result }),
          });
          if (broadcastRes.ok) {
            req.broadcastResult = 'success';
          } else {
            const errBody = await broadcastRes.text();
            req.broadcastResult = 'failed';
            req.broadcastError = `${broadcastRes.status}: ${errBody.slice(0, 200)}`;
          }
        }
      } catch (e: any) {
        req.broadcastResult = 'failed';
        req.broadcastError = e.message;
        console.error('Broadcast failed:', e);
      }
      await kvUpdate(kv, req);
    }
  }
}

// --- Pending Store (KV-backed) ---

interface PendingRequest {
  id: string;
  sessionId: string;
  walletAddress: string;
  type: 'transfer';
  to: string;
  amountNano: string;
  payload?: string;
  stateInit?: string;
  status: 'pending' | 'confirmed' | 'rejected' | 'expired';
  createdAt: number;
  expiresAt: number;
  txHash?: string;
  broadcastResult?: 'success' | 'failed';
  broadcastError?: string;
}

const TTL_SEC = 5 * 60; // 5 minutes

async function kvCreatePending(kv: KVNamespace, sessionId: string, walletAddress: string, to: string, amountNano: string, payload?: string, stateInit?: string): Promise<PendingRequest> {
  const now = Date.now();
  const req: PendingRequest = {
    id: crypto.randomUUID(),
    sessionId,
    walletAddress,
    type: 'transfer',
    to,
    amountNano,
    payload, stateInit,
    status: 'pending',
    createdAt: now,
    expiresAt: now + TTL_SEC * 1000,
  };
  await kv.put(`req:${req.id}`, JSON.stringify(req), { expirationTtl: TTL_SEC });
  // Index by sessionId so the token holder can list their own requests
  await kv.put(`idx:${sessionId}:${req.id}`, req.id, { expirationTtl: TTL_SEC });
  // Index by wallet address so the dashboard can list ALL pending for this wallet
  await kv.put(`widx:${walletAddress}:${req.id}`, req.id, { expirationTtl: TTL_SEC });
  return req;
}

async function kvGetPending(kv: KVNamespace, sessionId: string): Promise<PendingRequest[]> {
  const list = await kv.list({ prefix: `idx:${sessionId}:` });
  const results: PendingRequest[] = [];
  for (const key of list.keys) {
    const raw = await kv.get(`req:${key.name.split(':').pop()}`);
    if (!raw) continue;
    const req: PendingRequest = JSON.parse(raw);
    if (req.status === 'pending') results.push(req);
  }
  return results;
}

async function kvGetPendingByWallet(kv: KVNamespace, walletAddress: string): Promise<PendingRequest[]> {
  const list = await kv.list({ prefix: `widx:${walletAddress}:` });
  const results: PendingRequest[] = [];
  for (const key of list.keys) {
    const raw = await kv.get(`req:${key.name.split(':').pop()}`);
    if (!raw) continue;
    const req: PendingRequest = JSON.parse(raw);
    if (req.status === 'pending') results.push(req);
  }
  return results;
}

async function kvGetById(kv: KVNamespace, id: string, sessionId: string): Promise<PendingRequest | null> {
  const raw = await kv.get(`req:${id}`);
  if (!raw) return null;
  const req: PendingRequest = JSON.parse(raw);
  if (req.sessionId !== sessionId) return null;
  return req;
}

async function kvGetByIdForWallet(kv: KVNamespace, id: string, walletAddress: string): Promise<PendingRequest | null> {
  const raw = await kv.get(`req:${id}`);
  if (!raw) return null;
  const req: PendingRequest = JSON.parse(raw);
  if (req.walletAddress !== walletAddress) return null;
  return req;
}

async function kvUpdate(kv: KVNamespace, req: PendingRequest): Promise<void> {
  await kv.put(`req:${req.id}`, JSON.stringify(req), { expirationTtl: 3600 });
}

// --- Helpers ---

function swaggerHtml(openapiUrl: string): string {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Agent Gateway API Swagger</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>body { margin: 0; } #swagger-ui { max-width: 1200px; margin: 0 auto; }</style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: '${openapiUrl}',
        dom_id: '#swagger-ui'
      });
    </script>
  </body>
</html>`;
}

async function broadcastViaEnv(externalMessageBoc: string, env: Env) {
  const tonBroadcastUrl = env.TON_BROADCAST_URL ?? 'https://testnet.toncenter.com/api/v2/sendBoc';
  const tonApiKeyHeader = env.TON_API_KEY_HEADER ?? 'X-API-Key';

  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (env.TON_API_KEY) headers[tonApiKeyHeader] = env.TON_API_KEY;

  const response = await fetch(tonBroadcastUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ boc: externalMessageBoc }),
  });

  const raw = await response.text();
  let body: unknown = raw;
  try { body = JSON.parse(raw); } catch {}

  if (!response.ok) {
    throw new Error(`Broadcast failed (${response.status}): ${typeof body === 'string' ? body : JSON.stringify(body)}`);
  }

  return { status: response.status, body };
}

async function parseJson(request: Request): Promise<unknown> {
  try { return await request.json(); }
  catch { throw new Error('Invalid JSON body'); }
}

// --- Worker ---

const OPENAPI_SPEC = {
  openapi: '3.1.0',
  info: {
    title: 'Agent Gateway API',
    description: 'A secure gateway that lets AI agents request TON blockchain transactions while wallet owners keep full signing control.',
    version: '0.2.0',
  },
  tags: [
    { name: 'Auth', description: 'Authentication — create tokens, manage sessions' },
    { name: 'Safe Transfers', description: 'Request transfers that require wallet owner approval via TON Connect' },
    { name: 'Blockchain Raw', description: 'Direct blockchain operations — sign, execute, and broadcast transactions' },
    { name: 'Open4dev DEX', description: 'Create orders on the open4dev on-chain order book' },
    { name: 'Wallet', description: 'Wallet data — balances, tokens, NFTs, DNS, prices' },
    { name: 'Agent Wallet', description: 'Deploy and manage autonomous agent wallets (no approval needed for transfers)' },
    { name: 'DEX', description: 'Swap tokens via open4dev order book' },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    },
    schemas: {
      Error: {
        type: 'object',
        properties: { error: { type: 'string' } },
        required: ['error'],
      },
      PendingRequest: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          sessionId: { type: 'string' },
          type: { type: 'string' },
          to: { type: 'string' },
          amountNano: { type: 'string' },
          payload: { type: 'string' },
          status: { type: 'string', enum: ['pending', 'confirmed', 'rejected', 'expired'] },
          createdAt: { type: 'number' },
          expiresAt: { type: 'number' },
          txHash: { type: 'string' },
          broadcastResult: { type: 'string', enum: ['success', 'failed'] },
          broadcastError: { type: 'string' },
        },
      },
      Session: {
        type: 'object',
        properties: {
          sid: { type: 'string' },
          address: { type: 'string' },
          label: { type: 'string' },
          createdAt: { type: 'number' },
        },
      },
    },
  },
  paths: {
    '/health': {
      get: {
        summary: 'Health check',
        tags: ['Auth'],
        responses: { '200': { description: 'OK' } },
      },
    },
    '/v1/auth/token': {
      post: {
        summary: 'Create auth token',
        description: 'Exchange a TON wallet address for a JWT token. Each token creates an isolated session.',
        tags: ['Auth'],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['address'],
            properties: {
              address: { type: 'string', description: 'TON wallet address (raw or friendly)' },
              label: { type: 'string', description: 'Label for this token (e.g. "my-agent")', default: 'default' },
              reuse: { type: 'boolean', description: 'Reuse existing session with same label', default: false },
            },
          } } },
        },
        responses: {
          '200': { description: 'Token created', content: { 'application/json': { schema: {
            type: 'object',
            properties: {
              token: { type: 'string' },
              address: { type: 'string' },
              sessionId: { type: 'string' },
              label: { type: 'string' },
            },
          } } } },
          '400': { description: 'Invalid address', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/auth/me': {
      get: {
        summary: 'Verify token',
        description: 'Returns the wallet address and session ID for the current bearer token.',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Token valid', content: { 'application/json': { schema: {
            type: 'object',
            properties: { address: { type: 'string' }, sessionId: { type: 'string' } },
          } } } },
          '401': { description: 'Unauthorized', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/auth/sessions': {
      get: {
        summary: 'List sessions',
        description: 'Returns all active sessions for the authenticated wallet address.',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Sessions list', content: { 'application/json': { schema: {
            type: 'object',
            properties: { sessions: { type: 'array', items: { '$ref': '#/components/schemas/Session' } } },
          } } } },
        },
      },
    },
    '/v1/auth/revoke': {
      post: {
        summary: 'Revoke a session',
        description: 'Revoke a specific session by its ID. Cannot revoke your own session.',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['sessionId'],
            properties: { sessionId: { type: 'string' } },
          } } },
        },
        responses: {
          '200': { description: 'Session revoked' },
          '400': { description: 'Invalid request', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/auth/revoke-all': {
      post: {
        summary: 'Revoke all other sessions',
        description: 'Revoke all sessions for this wallet except the current one.',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Sessions revoked', content: { 'application/json': { schema: {
            type: 'object',
            properties: { revoked: { type: 'number' } },
          } } } },
        },
      },
    },
    '/v1/auth/connect': {
      post: {
        summary: 'Save TON Connect session',
        description: 'Persist the TON Connect session so the server can push signing requests directly to the wallet.',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['secretKey', 'publicKey', 'walletPublicKey', 'bridgeUrl'],
            properties: {
              secretKey: { type: 'string' },
              publicKey: { type: 'string' },
              walletPublicKey: { type: 'string' },
              bridgeUrl: { type: 'string' },
            },
          } } },
        },
        responses: {
          '200': { description: 'Session saved' },
          '400': { description: 'Missing fields', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/auth/tx-log': {
      get: {
        summary: 'Transaction log',
        description: 'Returns recent transactions for the authenticated wallet.',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Transaction log', content: { 'application/json': { schema: {
            type: 'object',
            properties: { transactions: { type: 'array', items: { '$ref': '#/components/schemas/PendingRequest' } } },
          } } } },
        },
      },
    },
    '/v1/auth/request': {
      post: {
        summary: 'Request authentication',
        description: 'Creates a one-time authentication link. The user opens it, connects their wallet, and the agent gets a token.',
        tags: ['Auth'],
        requestBody: {
          content: { 'application/json': { schema: {
            type: 'object',
            properties: {
              label: { type: 'string', description: 'Label for the token', default: 'agent' },
            },
          } } },
        },
        responses: {
          '200': { description: 'Auth request created', content: { 'application/json': { schema: {
            type: 'object',
            properties: {
              authId: { type: 'string' },
              authUrl: { type: 'string' },
              expiresAt: { type: 'number' },
            },
          } } } },
        },
      },
    },
    '/v1/auth/check/{authId}': {
      get: {
        summary: 'Check auth status',
        description: 'Poll for authentication completion. Returns token when the user has connected their wallet.',
        tags: ['Auth'],
        parameters: [{ name: 'authId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Auth status', content: { 'application/json': { schema: {
            type: 'object',
            properties: {
              status: { type: 'string', enum: ['pending', 'completed'] },
              authId: { type: 'string' },
              token: { type: 'string' },
              address: { type: 'string' },
            },
          } } } },
          '404': { description: 'Not found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/safe/tx/transfer': {
      post: {
        summary: 'Request a transfer',
        description: 'Creates a pending TON transfer request. The wallet owner must approve it via TON Connect within 5 minutes.',
        tags: ['Safe Transfers'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['to', 'amountNano'],
            properties: {
              to: { type: 'string', description: 'Destination TON address' },
              amountNano: { type: 'string', description: 'Amount in nanoTON (1 TON = 1000000000)' },
              payload: { type: 'string', description: 'Optional BOC payload for the transaction' },
              stateInit: { type: 'string', description: 'Optional stateInit BOC for contract deployment' },
            },
          } } },
        },
        responses: {
          '200': { description: 'Request created', content: { 'application/json': { schema: { '$ref': '#/components/schemas/PendingRequest' } } } },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/safe/tx/pending': {
      get: {
        summary: 'List pending requests',
        description: 'Returns all pending transfer requests for the authenticated wallet.',
        tags: ['Safe Transfers'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Pending requests', content: { 'application/json': { schema: {
            type: 'object',
            properties: { requests: { type: 'array', items: { '$ref': '#/components/schemas/PendingRequest' } } },
          } } } },
        },
      },
    },
    '/v1/safe/tx/{id}': {
      get: {
        summary: 'Get request by ID',
        description: 'Returns a specific transfer request by its ID.',
        tags: ['Safe Transfers'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Request found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/PendingRequest' } } } },
          '404': { description: 'Not found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/safe/tx/{id}/confirm': {
      post: {
        summary: 'Confirm a request',
        description: 'Mark a pending request as confirmed after the wallet signs the transaction.',
        tags: ['Safe Transfers'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          content: { 'application/json': { schema: {
            type: 'object',
            properties: { txHash: { type: 'string', description: 'Transaction BOC from wallet' } },
          } } },
        },
        responses: {
          '200': { description: 'Request confirmed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/PendingRequest' } } } },
          '400': { description: 'Not pending', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
          '404': { description: 'Not found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/safe/tx/{id}/reject': {
      post: {
        summary: 'Reject a request',
        description: 'Reject a pending transfer request.',
        tags: ['Safe Transfers'],
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Request rejected', content: { 'application/json': { schema: { '$ref': '#/components/schemas/PendingRequest' } } } },
          '400': { description: 'Not pending', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
          '404': { description: 'Not found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/tx/sign-and-execute': {
      post: {
        summary: 'Sign and execute transfer',
        description: 'Build, sign, and broadcast a TON transfer in one call. Requires server-side secret key.',
        tags: ['Blockchain Raw'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['to', 'amountNano', 'walletAddress', 'secretKeyHex'],
            properties: {
              to: { type: 'string' },
              amountNano: { type: 'string' },
              walletAddress: { type: 'string' },
              secretKeyHex: { type: 'string' },
              payload: { type: 'string' },
            },
          } } },
        },
        responses: {
          '200': { description: 'Transaction broadcast result' },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/tx/execute-signed': {
      post: {
        summary: 'Execute signed body',
        description: 'Wrap a pre-signed message body into an external message and broadcast it.',
        tags: ['Blockchain Raw'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['signedBodyBoc', 'walletAddress'],
            properties: {
              signedBodyBoc: { type: 'string' },
              walletAddress: { type: 'string' },
            },
          } } },
        },
        responses: {
          '200': { description: 'Transaction broadcast result' },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/tx/raw-execute': {
      post: {
        summary: 'Execute raw BOC',
        description: 'Broadcast a fully constructed external message BOC directly to the network.',
        tags: ['Blockchain Raw'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['boc'],
            properties: { boc: { type: 'string' } },
          } } },
        },
        responses: {
          '200': { description: 'Transaction broadcast result' },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/open4dev/orders/create-ton': {
      post: {
        summary: 'Create TON order',
        description: 'Create a TON-side order on the open4dev on-chain order book. Signs and broadcasts directly.',
        tags: ['Open4dev DEX'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Order created and broadcast' },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/open4dev/orders/create-jetton': {
      post: {
        summary: 'Create Jetton order',
        description: 'Create a Jetton-side order on the open4dev on-chain order book. Signs and broadcasts directly.',
        tags: ['Open4dev DEX'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Order created and broadcast' },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/safe/open4dev/orders/create-ton': {
      post: {
        summary: 'Request TON order (safe mode)',
        description: 'Create a pending TON order that requires wallet owner approval before execution.',
        tags: ['Open4dev DEX'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Pending order created', content: { 'application/json': { schema: { '$ref': '#/components/schemas/PendingRequest' } } } },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/safe/open4dev/orders/create-jetton': {
      post: {
        summary: 'Request Jetton order (safe mode)',
        description: 'Create a pending Jetton order that requires wallet owner approval before execution.',
        tags: ['Open4dev DEX'],
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Pending order created', content: { 'application/json': { schema: { '$ref': '#/components/schemas/PendingRequest' } } } },
          '400': { description: 'Invalid input', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
        },
      },
    },
    '/v1/wallet/balance': {
      get: { summary: 'Get wallet balance', description: 'Returns TON balance and account status.', tags: ['Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Wallet balance', content: { 'application/json': { schema: { type: 'object', properties: { address: { type: 'string' }, balance: { type: 'string' }, status: { type: 'string' } } } } } } } } },
    '/v1/wallet/jettons': {
      get: { summary: 'Get jetton balances', description: 'Returns all jetton (token) balances.', tags: ['Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Jetton balances' } } } },
    '/v1/wallet/transactions': {
      get: { summary: 'Get transaction history', description: 'Returns recent transactions.', tags: ['Wallet'], security: [{ bearerAuth: [] }],
        parameters: [{ name: 'limit', in: 'query', schema: { type: 'number', default: 20 } }],
        responses: { '200': { description: 'Transactions' } } } },
    '/v1/wallet/nfts': {
      get: { summary: 'Get NFTs', description: 'Returns NFTs owned by the wallet.', tags: ['Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'NFT list' } } } },
    '/v1/dns/{domain}/resolve': {
      get: { summary: 'Resolve .ton domain', description: 'Resolve a .ton domain to a wallet address.', tags: ['Wallet'],
        parameters: [{ name: 'domain', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Resolved address' } } } },
    '/v1/market/price': {
      get: { summary: 'Get token prices', description: 'Get current prices for TON and jettons.', tags: ['Wallet'],
        parameters: [{ name: 'tokens', in: 'query', schema: { type: 'string', default: 'TON' } }, { name: 'currencies', in: 'query', schema: { type: 'string', default: 'USD' } }],
        responses: { '200': { description: 'Price rates' } } } },
    '/v1/agent-wallet/deploy': {
      post: { summary: 'Generate agent wallet keypair', description: 'Generate an agent keypair for a new agent wallet deployment.', tags: ['Agent Wallet'], security: [{ bearerAuth: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['ownerPublicKey'], properties: { ownerPublicKey: { type: 'string' } } } } } },
        responses: { '200': { description: 'Keypair generated' } } } },
    '/v1/agent-wallet/register': {
      post: { summary: 'Register deployed agent wallet', description: 'Store agent wallet config after deployment.', tags: ['Agent Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Registered' } } } },
    '/v1/agent-wallet/execute': {
      post: { summary: 'Execute transfer from agent wallet', description: 'Sign and broadcast transfer from agent wallet. No approval needed.', tags: ['Agent Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Transfer executed' }, '501': { description: 'Use MCP tool instead' } } } },
    '/v1/agent-wallet/set-agent': {
      post: { summary: 'Set agent key', description: 'Send adminSetAgent to the vault. Requires wallet approval.', tags: ['Agent Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Request created' } } } },
    '/v1/agent-wallet/revoke-agent': {
      post: { summary: 'Revoke agent key', description: 'Send adminRevokeAgent to the vault. Requires wallet approval.', tags: ['Agent Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Request created' } } } },
    '/v1/agent-wallet/list': {
      get: { summary: 'List agent wallets', description: 'List all agent wallets for the authenticated wallet.', tags: ['Agent Wallet'], security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Wallet list' } } } },
    '/v1/agent-wallet/{address}/info': {
      get: { summary: 'Get agent wallet info', description: 'Get balance, seqno, and agent key status.', tags: ['Agent Wallet'], security: [{ bearerAuth: [] }],
        parameters: [{ name: 'address', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Wallet info' } } } },
    '/v1/dex/order': {
      post: { summary: 'Create swap order', description: 'Swap tokens via open4dev DEX. Agent provides token pair, amount, and price.', tags: ['DEX'], security: [{ bearerAuth: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['fromToken', 'toToken', 'amount', 'price'],
          properties: {
            fromToken: { type: 'string', description: 'Token to sell (e.g. "NOT", "TON")' },
            toToken: { type: 'string', description: 'Token to buy (e.g. "TON", "NOT")' },
            amount: { type: 'string', description: 'Amount in smallest unit (nanoTON or jetton decimals)' },
            price: { type: 'number', description: 'Human-readable price (e.g. 20 for "1 USDT = 20 AGNT")' },
          } } } } },
        responses: { '200': { description: 'Swap order created' }, '404': { description: 'Pair not found' } } } },
    '/v1/dex/pairs': {
      get: { summary: 'List available pairs', description: 'List all configured DEX trading pairs.', tags: ['DEX'],
        responses: { '200': { description: 'Pair list' } } } },
  },
};

const handler: ExportedHandler<Env> = {
  async scheduled(event, env, ctx) {
    // Cron: check bridge for wallet responses for all connected wallets
    const tcKeys = await env.PENDING_STORE.list({ prefix: 'tc:' });
    for (const key of tcKeys.keys) {
      const address = key.name.slice(3);
      try {
        await processBridgeResponses(env.PENDING_STORE, address, env);
      } catch (e) {
        console.error(`Cron: bridge check failed for ${address}:`, e);
      }
    }
  },

  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // --- Static / docs ---

    if (request.method === 'GET' && path === '/health') {
      return json({ ok: true });
    }

    if (request.method === 'GET' && path === '/openapi.json') {
      return json(OPENAPI_SPEC);
    }

    if (request.method === 'GET' && (path === '/docs' || path === '/docs/')) {
      return html(swaggerHtml(new URL('/openapi.json', request.url).toString()));
    }

    try {
      // --- Auth ---

      if (request.method === 'POST' && path === '/v1/auth/token') {
        const body = await parseJson(request) as Record<string, unknown>;
        const address = body.address;
        if (!address || typeof address !== 'string' || address.length < 10) {
          return json({ error: 'Invalid address' }, 400);
        }
        const label = typeof body.label === 'string' && body.label.trim() ? body.label.trim() : 'default';
        const reuse = body.reuse === true;
        const secret = env.JWT_SECRET ?? 'change-me-in-production';

        // If reuse flag is set, try to find an existing session with the same label
        if (reuse) {
          const existing = await findSessionByLabel(env.PENDING_STORE, address, label);
          if (existing) {
            const token = await jwtSign({ address, sid: existing.sid }, secret);
            return json({ token, address, sessionId: existing.sid, label: existing.label });
          }
        }

        const sid = crypto.randomUUID();
        const token = await jwtSign({ address, sid }, secret);
        await createSession(env.PENDING_STORE, sid, address, label);
        return json({ token, address, sessionId: sid, label });
      }

      if (request.method === 'GET' && path === '/v1/auth/me') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        return json({ address: user.address, sessionId: user.sessionId });
      }

      if (request.method === 'GET' && path === '/v1/auth/sessions') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        return json({ sessions: await listSessions(env.PENDING_STORE, user.address) });
      }

      if (request.method === 'POST' && path === '/v1/auth/revoke') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const body = await parseJson(request) as Record<string, unknown>;
        const sid = body.sessionId;
        if (!sid || typeof sid !== 'string') {
          return json({ error: 'Missing sessionId' }, 400);
        }
        if (sid === user.sessionId) {
          return json({ error: 'Cannot revoke your own active session' }, 400);
        }
        const ok = await revokeSession(env.PENDING_STORE, sid, user.address);
        if (!ok) return json({ error: 'Session not found' }, 404);
        return json({ revoked: true, sessionId: sid });
      }

      if (request.method === 'POST' && path === '/v1/auth/revoke-all') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const count = await revokeAllSessions(env.PENDING_STORE, user.address, user.sessionId);
        return json({ revoked: count });
      }

      if (request.method === 'POST' && path === '/v1/auth/connect') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const session: TcSession = {
          secretKey: body.secretKey as string,
          publicKey: body.publicKey as string,
          walletPublicKey: body.walletPublicKey as string,
          bridgeUrl: body.bridgeUrl as string,
          walletAddress: user.address,
        };

        if (!session.secretKey || !session.publicKey || !session.walletPublicKey || !session.bridgeUrl) {
          return json({ error: 'Missing TON Connect session fields' }, 400);
        }

        await saveTcSession(env.PENDING_STORE, user.address, session);
        return json({ ok: true });
      }

      if (request.method === 'GET' && path === '/v1/auth/tx-log') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        // Check bridge for any new responses first
        try { await processBridgeResponses(env.PENDING_STORE, user.address, env); } catch {}

        const list = await env.PENDING_STORE.list({ prefix: `widx:${user.address}:` });
        const transactions: PendingRequest[] = [];
        for (const key of list.keys) {
          const id = key.name.split(':').pop();
          if (!id) continue;
          const raw = await env.PENDING_STORE.get(`req:${id}`);
          if (raw) transactions.push(JSON.parse(raw));
        }
        transactions.sort((a, b) => b.createdAt - a.createdAt);
        return json({ transactions });
      }

      // --- Agent Auth Flow ---

      if (request.method === 'POST' && path === '/v1/auth/request') {
        const body = await parseJson(request) as Record<string, unknown>;
        const label = typeof body.label === 'string' && body.label.trim() ? body.label.trim() : 'agent';
        const authReq = await createAuthRequest(env.PENDING_STORE);
        const baseUrl = new URL(request.url).origin.replace('api.', '');
        return json({
          authId: authReq.authId,
          authUrl: `https://tongateway.ai/connect?authId=${authReq.authId}`,
          expiresAt: authReq.expiresAt,
          label,
          tcPublicKey: authReq.tcPublicKey,
        });
      }

      const authCheckMatch = path.match(/^\/v1\/auth\/check\/([^/]+)$/);
      if (authCheckMatch && request.method === 'GET') {
        const authId = authCheckMatch[1];
        const authReq = await getAuthRequest(env.PENDING_STORE, authId);
        if (!authReq) return json({ error: 'Auth request not found or expired' }, 404);
        if (authReq.status === 'pending') {
          return json({ status: 'pending', authId, expiresAt: authReq.expiresAt });
        }
        return json({
          status: 'completed',
          authId,
          token: authReq.token,
          address: authReq.address,
          sessionId: authReq.sessionId,
        });
      }

      const authCompleteMatch = path.match(/^\/v1\/auth\/complete\/([^/]+)$/);
      if (authCompleteMatch && request.method === 'POST') {
        const authId = authCompleteMatch[1];
        const authReq = await getAuthRequest(env.PENDING_STORE, authId);
        if (!authReq) return json({ error: 'Auth request not found or expired' }, 404);
        if (authReq.status !== 'pending') return json({ error: 'Auth request already completed' }, 400);

        const body = await parseJson(request) as Record<string, unknown>;
        const address = body.address as string;
        const label = typeof body.label === 'string' ? body.label : 'agent';
        if (!address || typeof address !== 'string' || address.length < 10) {
          return json({ error: 'Invalid address' }, 400);
        }

        const secret = env.JWT_SECRET ?? 'change-me-in-production';
        const sid = crypto.randomUUID();
        const token = await jwtSign({ address, sid }, secret);
        await createSession(env.PENDING_STORE, sid, address, label);

        // Save TC session — MUST use TonConnectUI's keypair (what the wallet connected to)
        const tcData = body.tcSession as Record<string, unknown> | undefined;
        if (tcData && tcData.secretKey && tcData.publicKey && tcData.walletPublicKey && tcData.bridgeUrl) {
          const tcSession: TcSession = {
            secretKey: tcData.secretKey as string,
            publicKey: tcData.publicKey as string,
            walletPublicKey: tcData.walletPublicKey as string,
            bridgeUrl: tcData.bridgeUrl as string,
            walletAddress: address,
          };
          await saveTcSession(env.PENDING_STORE, address, tcSession);
          console.log('TC session saved from browser, publicKey:', tcSession.publicKey.slice(0, 8));
        } else {
          console.log('WARNING: No TC session received from connect page — wallet push will not work');
        }

        await completeAuthRequest(env.PENDING_STORE, authId, token, address, sid);
        return json({ ok: true, token, address, sessionId: sid });
      }

      // --- Wallet Read ---

      if (request.method === 'GET' && path === '/v1/wallet/balance') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const client = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        try {
          const data = await client.getAccount(user.address);
          return json({ address: data.address, balance: String(data.balance), status: data.status });
        } catch (e: any) {
          return json({ error: e.message }, 502);
        }
      }

      if (request.method === 'GET' && path === '/v1/wallet/jettons') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const client = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        try {
          const data = await client.getJettonBalances(user.address);
          const balances = (data.balances ?? []).map((b: any) => ({
            balance: b.balance,
            symbol: b.jetton?.symbol,
            name: b.jetton?.name,
            decimals: b.jetton?.decimals,
            address: b.jetton?.address,
          }));
          return json({ balances });
        } catch (e: any) {
          return json({ error: e.message }, 502);
        }
      }

      if (request.method === 'GET' && path === '/v1/wallet/transactions') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const limit = Number(new URL(request.url).searchParams.get('limit') ?? '20');
        const client = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        try {
          const data = await client.getTransactions(user.address, limit);
          return json({ events: data.events ?? [] });
        } catch (e: any) {
          return json({ error: e.message }, 502);
        }
      }

      if (request.method === 'GET' && path === '/v1/wallet/nfts') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        const client = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        try {
          const data = await client.getNftItems(user.address);
          const items = (data.nft_items ?? []).map((n: any) => ({
            address: n.address,
            name: n.metadata?.name,
            image: n.metadata?.image,
            collection: n.collection?.name,
          }));
          return json({ nfts: items });
        } catch (e: any) {
          return json({ error: e.message }, 502);
        }
      }

      // --- Public Read (no auth) ---

      const dnsMatch = path.match(/^\/v1\/dns\/([^/]+)\/resolve$/);
      if (dnsMatch && request.method === 'GET') {
        const domain = decodeURIComponent(dnsMatch[1]);
        const client = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        try {
          const data = await client.resolveDns(domain);
          return json({ domain, address: data.wallet?.address ?? null, name: data.wallet?.name ?? null });
        } catch (e: any) {
          return json({ error: e.message }, 502);
        }
      }

      if (request.method === 'GET' && path === '/v1/market/price') {
        const params = new URL(request.url).searchParams;
        const tokens = (params.get('tokens') ?? 'TON').split(',');
        const currencies = (params.get('currencies') ?? 'USD').split(',');
        const client = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        try {
          const data = await client.getRates(tokens, currencies);
          return json({ rates: data.rates ?? {} });
        } catch (e: any) {
          return json({ error: e.message }, 502);
        }
      }

      // --- Agent Wallet ---

      if (request.method === 'POST' && path === '/v1/agent-wallet/deploy') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const ownerPublicKey = body.ownerPublicKey as string;
        if (!ownerPublicKey || typeof ownerPublicKey !== 'string' || ownerPublicKey.length !== 64) {
          return json({ error: 'ownerPublicKey must be 64-char hex (32 bytes ed25519 public key)' }, 400);
        }

        // Generate agent keypair
        const agentSeed = new Uint8Array(32);
        crypto.getRandomValues(agentSeed);

        // We need to use tweetnacl for ed25519 sign keypair from seed
        const nacl = await import('tweetnacl');
        const agentKp = nacl.default.sign.keyPair.fromSeed(agentSeed);
        const agentPublicKey = Array.from(agentKp.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
        const agentSecretKey = Array.from(agentKp.secretKey).map(b => b.toString(16).padStart(2, '0')).join('');

        const walletId = Math.floor(Date.now() / 1000);

        // Return deploy info — the client/MCP will build the stateInit
        // We store the config so execute can use the agent key later
        const config: AgentWalletConfig = {
          address: '', // will be set after deploy
          adminAddress: user.address,
          ownerPublicKey,
          agentSecretKey,
          agentPublicKey,
          walletId,
          createdAt: Date.now(),
        };

        return json({
          ownerPublicKey,
          agentPublicKey,
          agentSecretKey, // returned once for the deployer to know
          walletId,
          adminAddress: user.address,
        });
      }

      if (request.method === 'POST' && path === '/v1/agent-wallet/register') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const address = body.address as string;
        const agentSecretKey = body.agentSecretKey as string;
        const agentPublicKey = body.agentPublicKey as string;
        const ownerPublicKey = body.ownerPublicKey as string;
        const walletId = body.walletId as number;

        if (!address || !agentSecretKey || !agentPublicKey || !ownerPublicKey || !walletId) {
          return json({ error: 'Missing required fields' }, 400);
        }

        const config: AgentWalletConfig = {
          address,
          adminAddress: user.address,
          ownerPublicKey,
          agentSecretKey,
          agentPublicKey,
          walletId,
          createdAt: Date.now(),
        };

        await saveAgentWallet(env.PENDING_STORE, config);
        return json({ ok: true, address });
      }

      if (request.method === 'POST' && path === '/v1/agent-wallet/execute') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const walletAddress = body.walletAddress as string;
        const to = body.to as string;
        const amountNano = body.amountNano as string;

        if (!walletAddress || !to || !amountNano) {
          return json({ error: 'Missing required fields: walletAddress, to, amountNano' }, 400);
        }

        const config = await loadAgentWallet(env.PENDING_STORE, walletAddress);
        if (!config) return json({ error: 'Agent wallet not found' }, 404);
        if (config.adminAddress !== user.address) return json({ error: 'Not your agent wallet' }, 403);

        // Get seqno from chain
        const tonapiClient = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        let seqno: number;
        try {
          const methods = await fetch(`${env.TONAPI_BASE_URL ?? 'https://tonapi.io'}/v2/blockchain/accounts/${encodeURIComponent(walletAddress)}/methods/seqno`, {
            headers: env.TONAPI_KEY ? { Authorization: `Bearer ${env.TONAPI_KEY}` } : {},
          });
          const methodResult = await methods.json() as any;
          seqno = parseInt(methodResult.stack?.[0]?.num ?? '0', 16);
        } catch {
          return json({ error: 'Failed to get seqno from chain' }, 502);
        }

        // Build and sign external message
        // We need to replicate AgentVault.buildSignedBody logic here
        // Import nacl for signing
        const nacl2 = await import('tweetnacl');
        const secretKey = new Uint8Array(Buffer.from(config.agentSecretKey, 'hex'));

        const validUntil = Math.floor(Date.now() / 1000) + 300;

        // Build unsigned body: prefix(32) + walletId(32) + validUntil(32) + seqno(32) + maybeRef(actions)
        // Build transfer message: 0x18(6) + address + coins + 0(1+4+4+64+32+1+1)
        // This is complex TVM cell building - we need @ton/core
        // For now, return the params and let the MCP build it
        return json({
          error: 'Execute requires @ton/core for cell building. Use MCP tool execute_agent_wallet_transfer instead.',
          hint: 'The MCP tool has @ton/core available and can build+sign+broadcast the external message.',
          seqno,
          walletId: config.walletId,
          agentPublicKey: config.agentPublicKey,
        }, 501);
      }

      if (request.method === 'POST' && path === '/v1/agent-wallet/set-agent') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const walletAddress = body.walletAddress as string;
        const validUntil = body.validUntil as number;

        if (!walletAddress) return json({ error: 'Missing walletAddress' }, 400);

        const config = await loadAgentWallet(env.PENDING_STORE, walletAddress);
        if (!config) return json({ error: 'Agent wallet not found' }, 404);
        if (config.adminAddress !== user.address) return json({ error: 'Not your agent wallet' }, 403);

        const agentPubKeyBuf = Buffer.from(config.agentPublicKey, 'hex');
        const expiry = validUntil ?? Math.floor(Date.now() / 1000) + 365 * 24 * 3600;

        // Build adminSetAgent payload: op(32) + queryId(64) + agentPubKey(256) + validUntil(32)
        // op::admin_set_agent = 0x61677374
        const payloadHex = '61677374' + '0000000000000000' +
          config.agentPublicKey +
          expiry.toString(16).padStart(8, '0');

        // Create safe transfer request to send this as internal message to the vault
        const payload = Buffer.from(payloadHex, 'hex').toString('base64');

        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, walletAddress, '50000000', payload);

        // Auto-push to wallet via TON Connect bridge
        try {
          const tcSession = await loadTcSession(env.PENDING_STORE, user.address);
          if (tcSession) {
            await bridgeSendTransaction(tcSession, req.id, walletAddress, '50000000', payload);
          }
        } catch {}

        return json({ ...req, agentPublicKey: config.agentPublicKey, validUntil: expiry });
      }

      if (request.method === 'POST' && path === '/v1/agent-wallet/revoke-agent') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const walletAddress = body.walletAddress as string;

        if (!walletAddress) return json({ error: 'Missing walletAddress' }, 400);

        const config = await loadAgentWallet(env.PENDING_STORE, walletAddress);
        if (!config) return json({ error: 'Agent wallet not found' }, 404);
        if (config.adminAddress !== user.address) return json({ error: 'Not your agent wallet' }, 403);

        // Build adminRevokeAgent payload: op(32) + queryId(64)
        // op::admin_revoke_agent = 0x6172766B
        const payloadHex = '6172766b' + '0000000000000000';
        const payload = Buffer.from(payloadHex, 'hex').toString('base64');

        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, walletAddress, '50000000', payload);

        try {
          const tcSession = await loadTcSession(env.PENDING_STORE, user.address);
          if (tcSession) {
            await bridgeSendTransaction(tcSession, req.id, walletAddress, '50000000', payload);
          }
        } catch {}

        return json(req);
      }

      if (request.method === 'GET' && path === '/v1/agent-wallet/list') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const wallets = await listAgentWallets(env.PENDING_STORE, user.address);
        // Don't expose secret keys in list
        const safe = wallets.map(w => ({
          address: w.address,
          agentPublicKey: w.agentPublicKey,
          walletId: w.walletId,
          createdAt: w.createdAt,
        }));
        return json({ wallets: safe });
      }

      const awInfoMatch = path.match(/^\/v1\/agent-wallet\/([^/]+)\/info$/);
      if (awInfoMatch && request.method === 'GET') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const walletAddress = decodeURIComponent(awInfoMatch[1]);
        const config = await loadAgentWallet(env.PENDING_STORE, walletAddress);
        if (!config) return json({ error: 'Agent wallet not found' }, 404);
        if (config.adminAddress !== user.address) return json({ error: 'Not your agent wallet' }, 403);

        // Get balance and seqno from chain
        const tonapiClient = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
        try {
          const account = await tonapiClient.getAccount(walletAddress);
          let seqno = 0;
          try {
            const methods = await fetch(`${env.TONAPI_BASE_URL ?? 'https://tonapi.io'}/v2/blockchain/accounts/${encodeURIComponent(walletAddress)}/methods/seqno`, {
              headers: env.TONAPI_KEY ? { Authorization: `Bearer ${env.TONAPI_KEY}` } : {},
            });
            const methodResult = await methods.json() as any;
            seqno = parseInt(methodResult.stack?.[0]?.num ?? '0', 16);
          } catch {}

          return json({
            address: walletAddress,
            balance: String(account.balance),
            status: account.status,
            seqno,
            agentPublicKey: config.agentPublicKey,
            walletId: config.walletId,
            createdAt: config.createdAt,
          });
        } catch (e: any) {
          return json({ error: e.message }, 502);
        }
      }

      // --- DEX ---

      if (request.method === 'POST' && path === '/v1/dex/order') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;

        // Step 1: Normalize input into orders array
        // Accept either { orders: [...] } or flat { fromToken, toToken, amount, price }
        type OrderInput = { fromToken: string; toToken: string; amount: number; price: number };
        let orders: OrderInput[];

        if (Array.isArray(body.orders)) {
          orders = (body.orders as Array<Record<string, unknown>>).map((o) => ({
            fromToken: (String(o.fromToken || '')).toUpperCase(),
            toToken: (String(o.toToken || '')).toUpperCase(),
            amount: Number(o.amount),
            price: Number(o.price),
          }));
        } else {
          orders = [{
            fromToken: (body.fromToken as string || '').toUpperCase(),
            toToken: (body.toToken as string || '').toUpperCase(),
            amount: Number(body.amount),
            price: Number(body.price),
          }];
        }

        if (!orders.length) {
          return json({ error: 'At least one order is required' }, 400);
        }
        if (orders.length > 4) {
          return json({ error: 'Max 4 orders per batch (v4 wallet limit)' }, 400);
        }

        // Validate all orders upfront
        for (let i = 0; i < orders.length; i++) {
          const o = orders[i];
          if (!o.fromToken || !o.toToken || !o.amount || isNaN(o.amount) || o.amount <= 0 || !o.price || isNaN(o.price) || o.price <= 0) {
            return json({ error: `Order ${i + 1}: Missing required fields: fromToken, toToken, amount (human-readable, e.g. 10000), price (human-readable, e.g. 0.000289)` }, 400);
          }
        }

        try {
          // Step 2: Loop to build all order payloads

          // Fetch jetton balances ONCE if any order sells a jetton (optimization)
          const needsJettonBalances = orders.some(o => o.fromToken !== 'TON');
          let jettonBalances: any[] | null = null;
          if (needsJettonBalances) {
            const tonapiClient = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
            const jettons = await tonapiClient.getJettonBalances(user.address);
            jettonBalances = jettons.balances || [];
          }

          const messages: Array<{ address: string; amount: string; payload?: string }> = [];
          const swaps: Array<{ fromToken: string; toToken: string; amount: number; amountRaw: string; price: number; priceRateNano: string; slippage: number; pool: string }> = [];

          for (let i = 0; i < orders.length; i++) {
            const o = orders[i];

            const fromDecimals = getTokenDecimals(o.fromToken);
            const toDecimals = getTokenDecimals(o.toToken);

            // Convert human-readable amount to raw units
            const amountStr = o.amount.toFixed(fromDecimals);
            const [amountWhole, amountFrac = ''] = amountStr.split('.');
            const amountRaw = BigInt(amountWhole + amountFrac.padEnd(fromDecimals, '0').slice(0, fromDecimals)).toString();

            const priceRateNano = calculatePriceRate(o.price, toDecimals, fromDecimals).toString();

            // Slippage must include fees: user slippage (1%) + platform fee (1%) + matcher fee (2%) = 4%
            const effectiveSlippage = 1 + 1 + 2; // 4%
            const slippageValue = Number(calculateSlippage(effectiveSlippage));

            const activePool = getDexPair(o.fromToken, o.toToken);
            if (!activePool) {
              return json({ error: `Order ${i + 1}: Pair ${o.fromToken}/${o.toToken} not found. Available tokens: ${Object.keys(DEX_VAULTS).join(', ')}` }, 404);
            }

            let orderResult: { to: string; amountNano: string; payloadBoc: string };

            if (activePool.direction === 'ton' || o.fromToken === 'TON') {
              // Selling TON for jetton
              orderResult = buildTonOrderPayload({
                dexVaultTonAddress: activePool.dexVaultAddress,
                sendValueNano: (BigInt(amountRaw) + 100000000n).toString(),
                orderAmountNano: amountRaw,
                priceRateNano,
                slippage: slippageValue,
                toJettonMinter: activePool.jettonMinter,
                providerFeeAddress: activePool.providerFeeAddress,
                feeNum: activePool.feeNum,
                feeDenom: activePool.feeDenom,
                matcherFeeNum: activePool.matcherFeeNum,
                matcherFeeDenom: activePool.matcherFeeDenom,
                oppositeVaultAddress: activePool.oppositeVaultAddress,
              });
            } else {
              // Selling jetton for TON
              const fromMinter = DEX_JETTON_MINTERS[o.fromToken] ?? '';
              const jetton = (jettonBalances || []).find((b: any) =>
                b.jetton?.symbol?.toUpperCase() === o.fromToken ||
                b.jetton?.name?.toUpperCase() === o.fromToken ||
                b.jetton?.symbol?.replace(/[^A-Z0-9]/gi, '').toUpperCase() === o.fromToken ||
                (fromMinter && b.jetton?.address === fromMinter)
              );
              if (!jetton) {
                return json({ error: `Order ${i + 1}: You don't hold ${o.fromToken} tokens` }, 400);
              }

              orderResult = buildJettonOrderPayload({
                jettonWalletAddress: jetton.wallet_address?.address ?? jetton.wallet_address ?? jetton.jetton?.address,
                attachedTonAmountNano: '150000000', // 0.15 TON for gas
                jettonAmountNano: amountRaw,
                dexVaultAddress: activePool.dexVaultAddress,
                ownerAddress: user.address,
                forwardTonAmountNano: '100000000', // 0.1 TON forward
                priceRateNano,
                slippage: slippageValue,
                toJettonMinter: activePool.jettonMinter,
                providerFeeAddress: activePool.providerFeeAddress,
                feeNum: activePool.feeNum,
                feeDenom: activePool.feeDenom,
                matcherFeeNum: activePool.matcherFeeNum,
                matcherFeeDenom: activePool.matcherFeeDenom,
                oppositeVaultAddress: activePool.oppositeVaultAddress,
              });
            }

            messages.push({
              address: orderResult.to,
              amount: orderResult.amountNano,
              payload: orderResult.payloadBoc,
            });

            swaps.push({
              fromToken: o.fromToken,
              toToken: o.toToken,
              amount: o.amount,
              amountRaw,
              price: o.price,
              priceRateNano,
              slippage: effectiveSlippage,
              pool: activePool.pair,
            });
          }

          // Step 3: Create pending request and batch-send
          const totalNano = messages.reduce((sum, m) => (BigInt(sum) + BigInt(m.amount)).toString(), '0');
          const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, messages[0].address, totalNano);

          // Push all messages as one transaction via bridgeSendMessages
          try {
            const tcSession = await loadTcSession(env.PENDING_STORE, user.address);
            if (tcSession) {
              await bridgeSendMessages(tcSession, req.id, messages);
            }
          } catch {}

          return json({
            ...req,
            orders: swaps,
            // Backward-compat: include `swap` field when single order
            ...(swaps.length === 1 ? { swap: swaps[0] } : {}),
          });
        } catch (e: any) {
          return json({ error: e.message }, 400);
        }
      }

      if (request.method === 'GET' && path === '/v1/dex/pairs') {
        return json({ tokens: Object.keys(DEX_VAULTS), pairs: listAvailablePairs() });
      }

      // --- Safe TX ---

      if (request.method === 'POST' && path === '/v1/safe/tx/batch') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const transfers = body.transfers as Array<{ to: string; amountNano: string; payload?: string; comment?: string }>;
        if (!transfers || !Array.isArray(transfers) || !transfers.length) {
          return json({ error: 'Missing transfers array' }, 400);
        }
        if (transfers.length > 4) {
          return json({ error: 'Max 4 transfers per batch (v4 wallet limit). Use agent_wallet.batch_transfer for more.' }, 400);
        }

        // Build messages for TON Connect
        const messages: Array<{ address: string; amount: string; payload?: string }> = [];
        for (const t of transfers) {
          if (!t.to || !t.amountNano) {
            return json({ error: 'Each transfer needs to and amountNano' }, 400);
          }
          messages.push({
            address: t.to,
            amount: t.amountNano,
            ...(t.payload ? { payload: t.payload } : {}),
          });
        }

        // Create a single pending request for tracking
        const totalNano = transfers.reduce((sum, t) => (BigInt(sum) + BigInt(t.amountNano)).toString(), '0');
        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, transfers[0].to, totalNano);

        // Push all messages as one transaction to wallet
        try {
          const tcSession = await loadTcSession(env.PENDING_STORE, user.address);
          if (tcSession) {
            await bridgeSendMessages(tcSession, req.id, messages);
          }
        } catch (e) {
          console.error('Bridge batch send failed:', e);
        }

        return json({
          ...req,
          batch: { count: transfers.length, totalNano },
        });
      }

      if (request.method === 'POST' && path === '/v1/safe/tx/transfer') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;

        // Support both human-readable and raw formats
        let to = body.to as string;
        let amountNano = body.amountNano as string | undefined;

        if (!to || typeof to !== 'string') {
          return json({ error: 'Missing required field: to' }, 400);
        }

        // Auto-resolve .ton domain names
        if (to.endsWith('.ton') || to.endsWith('.t.me')) {
          try {
            const tonapiClient = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
            const dnsResult = await tonapiClient.resolveDns(to);
            if (dnsResult.wallet?.address) {
              to = dnsResult.wallet.address;
            } else {
              return json({ error: `Could not resolve domain: ${body.to}` }, 400);
            }
          } catch (e: any) {
            return json({ error: `DNS resolution failed: ${e.message}` }, 400);
          }
        }

        // Convert human-readable amount if provided
        if (!amountNano && body.amount) {
          const amount = Number(body.amount);
          const token = ((body.token as string) || 'TON').toUpperCase();
          if (isNaN(amount) || amount <= 0) {
            return json({ error: 'Invalid amount' }, 400);
          }
          const decimals = getTokenDecimals(token);
          const amountStr = amount.toFixed(decimals);
          const [whole, frac = ''] = amountStr.split('.');
          amountNano = BigInt(whole + frac.padEnd(decimals, '0').slice(0, decimals)).toString();
        }

        if (!amountNano) {
          return json({ error: 'Missing required field: amount or amountNano' }, 400);
        }

        // Payload: use provided BOC or leave to MCP to encode comments
        let payload = typeof body.payload === 'string' ? body.payload : undefined;

        const stateInit = typeof body.stateInit === 'string' ? body.stateInit : undefined;
        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, to, amountNano, payload, stateInit);

        // Auto-push to wallet via TON Connect bridge
        try {
          const tcSession = await loadTcSession(env.PENDING_STORE, user.address);
          if (tcSession) {
            console.log('Bridge push: sending to wallet, session publicKey:', tcSession.publicKey?.slice(0, 8), 'walletPubKey:', tcSession.walletPublicKey?.slice(0, 8));
            await bridgeSendTransaction(tcSession, req.id, to, amountNano, payload, stateInit);
            console.log('Bridge push: sent successfully');
          } else {
            console.log('Bridge push: no TC session found for address', user.address.slice(0, 16));
          }
        } catch (e) {
          console.error('Bridge send failed:', e);
        }

        return json({ ...req, resolved: body.to !== to ? { from: body.to, to } : undefined });
      }

      if (request.method === 'GET' && path === '/v1/safe/tx/pending') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        // Check bridge for updates before listing
        try { await processBridgeResponses(env.PENDING_STORE, user.address, env); } catch {}
        return json({ requests: await kvGetPendingByWallet(env.PENDING_STORE, user.address) });
      }

      // Match /v1/safe/tx/:id, /v1/safe/tx/:id/confirm, /v1/safe/tx/:id/reject
      const safeTxMatch = path.match(/^\/v1\/safe\/tx\/([^/]+)(\/confirm|\/reject)?$/);
      if (safeTxMatch) {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const id = safeTxMatch[1];
        const action = safeTxMatch[2]; // /confirm, /reject, or undefined

        if (!action && request.method === 'GET') {
          const req = await kvGetByIdForWallet(env.PENDING_STORE, id, user.address);
          if (!req) return json({ error: 'Not found' }, 404);
          // Check bridge for updates if still pending
          if (req.status === 'pending') {
            try { await processBridgeResponses(env.PENDING_STORE, user.address, env); } catch {}
            const updated = await kvGetByIdForWallet(env.PENDING_STORE, id, user.address);
            if (updated && updated.status !== 'pending') return json(updated);

            // Fallback: check on-chain if bridge failed
            try {
              const tonapiClient = createTonApiClient(env.TONAPI_BASE_URL ?? 'https://tonapi.io', env.TONAPI_KEY);
              const events = await tonapiClient.getTransactions(user.address, 5);
              const recentTxs = events.events ?? [];
              for (const tx of recentTxs) {
                // Match by destination and approximate time
                const txTime = (tx.timestamp ?? 0) * 1000;
                if (txTime > req.createdAt - 5000 && txTime < req.expiresAt) {
                  for (const action of (tx.actions ?? [])) {
                    if (action.type === 'TonTransfer' || action.type === 'JettonTransfer') {
                      const dest = action.TonTransfer?.recipient?.address ?? action.JettonTransfer?.recipient?.address ?? '';
                      if (dest === req.to || dest.includes(req.to.slice(2, 10))) {
                        req.status = 'confirmed';
                        req.broadcastResult = 'success';
                        await kvUpdate(env.PENDING_STORE, req);
                        return json(req);
                      }
                    }
                  }
                }
              }
            } catch {}
          }
          return json(req);
        }

        if (action === '/confirm' && request.method === 'POST') {
          const req = await kvGetByIdForWallet(env.PENDING_STORE, id, user.address);
          if (!req) return json({ error: 'Not found' }, 404);
          if (req.status !== 'pending') return json({ error: 'Request is not pending' }, 400);

          let txHash: string | undefined;
          try {
            const body = await parseJson(request) as Record<string, unknown>;
            if (typeof body.txHash === 'string') txHash = body.txHash;
          } catch {}

          req.status = 'confirmed';
          req.txHash = txHash;
          await kvUpdate(env.PENDING_STORE, req);
          return json(req);
        }

        if (action === '/reject' && request.method === 'POST') {
          const req = await kvGetByIdForWallet(env.PENDING_STORE, id, user.address);
          if (!req) return json({ error: 'Not found' }, 404);
          if (req.status !== 'pending') return json({ error: 'Request is not pending' }, 400);
          req.status = 'rejected';
          await kvUpdate(env.PENDING_STORE, req);
          return json(req);
        }
      }

      // --- Safe Open4dev Orders ---

      if (request.method === 'POST' && path === '/v1/safe/open4dev/orders/create-ton') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const input = SafeCreateTonOrderSchema.parse(await parseJson(request));
        const order = buildTonOrderPayload({
          dexVaultTonAddress: input.dexVaultTonAddress,
          sendValueNano: input.sendValueNano,
          orderAmountNano: input.orderAmountNano,
          priceRateNano: input.priceRateNano,
          slippage: toSafeNumber(input.slippage),
          toJettonMinter: input.toJettonMinter,
          providerFeeAddress: input.providerFeeAddress,
          feeNum: toSafeNumber(input.feeNum),
          feeDenom: toSafeNumber(input.feeDenom),
          matcherFeeNum: toSafeNumber(input.matcherFeeNum),
          matcherFeeDenom: toSafeNumber(input.matcherFeeDenom),
          oppositeVaultAddress: input.oppositeVaultAddress,
          createdAt: input.createdAt !== undefined ? toSafeNumber(input.createdAt) : undefined,
        });

        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, order.to, order.amountNano, order.payload);
        return json(req);
      }

      if (request.method === 'POST' && path === '/v1/safe/open4dev/orders/create-jetton') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const input = SafeCreateJettonOrderSchema.parse(await parseJson(request));
        const order = buildJettonOrderPayload({
          jettonWalletAddress: input.jettonWalletAddress,
          attachedTonAmountNano: input.attachedTonAmountNano,
          jettonAmountNano: input.jettonAmountNano,
          dexVaultAddress: input.dexVaultAddress,
          ownerAddress: input.ownerAddress,
          forwardTonAmountNano: input.forwardTonAmountNano,
          priceRateNano: input.priceRateNano,
          slippage: toSafeNumber(input.slippage),
          toJettonMinter: input.toJettonMinter,
          providerFeeAddress: input.providerFeeAddress,
          feeNum: toSafeNumber(input.feeNum),
          feeDenom: toSafeNumber(input.feeDenom),
          matcherFeeNum: toSafeNumber(input.matcherFeeNum),
          matcherFeeDenom: toSafeNumber(input.matcherFeeDenom),
          oppositeVaultAddress: input.oppositeVaultAddress,
          customPayloadBoc: input.customPayloadBoc,
          createdAt: input.createdAt !== undefined ? toSafeNumber(input.createdAt) : undefined,
          queryId: input.queryId,
        });

        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, order.to, order.amountNano, order.payload);
        return json(req);
      }

      // --- TX ---

      if (request.method === 'POST' && path === '/v1/tx/sign-and-execute') {
        const input = SignAndExecuteSchema.parse(await parseJson(request));
        const result = buildSignedTransferMessage({
          vaultAddress: input.vaultAddress,
          walletId: toSafeNumber(input.walletId),
          seqno: toSafeNumber(input.seqno),
          validUntil: toSafeNumber(input.validUntil),
          to: input.to,
          amountNano: input.amountNano,
          queryId: input.queryId,
          payload: input.payload,
          secretKey: resolveSecretKeyFromHex(input.privateKeyHex),
        });

        if (input.dryRun) return json({ ...result, broadcasted: false });
        const providerResponse = await broadcastViaEnv(result.externalMessageBoc, env);
        return json({ ...result, broadcasted: true, providerResponse });
      }

      if (request.method === 'POST' && path === '/v1/tx/execute-signed') {
        const input = ExecuteSignedSchema.parse(await parseJson(request));
        const externalMessageBoc = wrapSignedBodyIntoExternalMessage(input.vaultAddress, input.signedBodyBoc);

        if (input.dryRun) return json({ externalMessageBoc, broadcasted: false });
        const providerResponse = await broadcastViaEnv(externalMessageBoc, env);
        return json({ externalMessageBoc, broadcasted: true, providerResponse });
      }

      if (request.method === 'POST' && path === '/v1/tx/raw-execute') {
        const input = RawExecuteSchema.parse(await parseJson(request));

        if (input.dryRun) return json({ externalMessageBoc: input.externalMessageBoc, broadcasted: false });
        const providerResponse = await broadcastViaEnv(input.externalMessageBoc, env);
        return json({ externalMessageBoc: input.externalMessageBoc, broadcasted: true, providerResponse });
      }

      // --- Open4dev ---

      if (request.method === 'POST' && path === '/v1/open4dev/orders/create-ton') {
        const input = CreateTonOrderSchema.parse(await parseJson(request));
        const result = buildCreateTonOrderMessage({
          vaultAddress: input.vaultAddress,
          walletId: toSafeNumber(input.walletId),
          seqno: toSafeNumber(input.seqno),
          validUntil: toSafeNumber(input.validUntil),
          dexVaultTonAddress: input.dexVaultTonAddress,
          sendValueNano: input.sendValueNano,
          orderAmountNano: input.orderAmountNano,
          priceRateNano: input.priceRateNano,
          slippage: toSafeNumber(input.slippage),
          toJettonMinter: input.toJettonMinter,
          providerFeeAddress: input.providerFeeAddress,
          feeNum: toSafeNumber(input.feeNum),
          feeDenom: toSafeNumber(input.feeDenom),
          matcherFeeNum: toSafeNumber(input.matcherFeeNum),
          matcherFeeDenom: toSafeNumber(input.matcherFeeDenom),
          oppositeVaultAddress: input.oppositeVaultAddress,
          createdAt: input.createdAt !== undefined ? toSafeNumber(input.createdAt) : undefined,
          queryId: input.queryId,
          secretKey: resolveSecretKeyFromHex(input.privateKeyHex),
        });

        if (input.dryRun) return json({ ...result, broadcasted: false });
        const providerResponse = await broadcastViaEnv(result.externalMessageBoc, env);
        return json({ ...result, broadcasted: true, providerResponse });
      }

      if (request.method === 'POST' && path === '/v1/open4dev/orders/create-jetton') {
        const input = CreateJettonOrderSchema.parse(await parseJson(request));
        const result = buildCreateJettonOrderMessage({
          vaultAddress: input.vaultAddress,
          walletId: toSafeNumber(input.walletId),
          seqno: toSafeNumber(input.seqno),
          validUntil: toSafeNumber(input.validUntil),
          jettonWalletAddress: input.jettonWalletAddress,
          attachedTonAmountNano: input.attachedTonAmountNano,
          jettonAmountNano: input.jettonAmountNano,
          dexVaultAddress: input.dexVaultAddress,
          ownerAddress: input.ownerAddress,
          forwardTonAmountNano: input.forwardTonAmountNano,
          priceRateNano: input.priceRateNano,
          slippage: toSafeNumber(input.slippage),
          toJettonMinter: input.toJettonMinter,
          providerFeeAddress: input.providerFeeAddress,
          feeNum: toSafeNumber(input.feeNum),
          feeDenom: toSafeNumber(input.feeDenom),
          matcherFeeNum: toSafeNumber(input.matcherFeeNum),
          matcherFeeDenom: toSafeNumber(input.matcherFeeDenom),
          oppositeVaultAddress: input.oppositeVaultAddress,
          customPayloadBoc: input.customPayloadBoc,
          createdAt: input.createdAt !== undefined ? toSafeNumber(input.createdAt) : undefined,
          queryId: input.queryId,
          secretKey: resolveSecretKeyFromHex(input.privateKeyHex),
        });

        if (input.dryRun) return json({ ...result, broadcasted: false });
        const providerResponse = await broadcastViaEnv(result.externalMessageBoc, env);
        return json({ ...result, broadcasted: true, providerResponse });
      }

      return json({ error: 'Not found' }, 404);
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : 'Unknown error' }, 400);
    }
  },
};

export default handler;
