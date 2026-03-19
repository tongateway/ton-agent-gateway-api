import {
  buildSignedTransferMessage,
  wrapSignedBodyIntoExternalMessage,
} from './services/tonMessage';
import { TcSession, bridgeSendTransaction, bridgePollResponses, BridgeResponse } from './bridge';
import { SignAndExecuteSchema, ExecuteSignedSchema, RawExecuteSchema } from './schemas/tx';
import { resolveSecretKeyFromHex } from './utils/keys';
import { toSafeNumber } from './utils/numbers';
import { CreateJettonOrderSchema, CreateTonOrderSchema, SafeCreateTonOrderSchema, SafeCreateJettonOrderSchema } from './schemas/open4dev';
import { buildCreateJettonOrderMessage, buildCreateTonOrderMessage, buildTonOrderPayload, buildJettonOrderPayload } from './services/open4devOrderBook';

interface Env {
  TON_BROADCAST_URL?: string;
  TON_API_KEY?: string;
  TON_API_KEY_HEADER?: string;
  JWT_SECRET?: string;
  PENDING_STORE: KVNamespace;
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

// --- Agent Auth Flow ---

interface AuthRequest {
  authId: string;
  status: 'pending' | 'completed';
  token?: string;
  address?: string;
  sessionId?: string;
  createdAt: number;
  expiresAt: number;
}

async function createAuthRequest(kv: KVNamespace): Promise<AuthRequest> {
  const authId = crypto.randomUUID();
  const now = Date.now();
  const req: AuthRequest = {
    authId,
    status: 'pending',
    createdAt: now,
    expiresAt: now + 10 * 60 * 1000, // 10 minutes TTL
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
  await kv.put(`auth:${authId}`, JSON.stringify(req), { expirationTtl: 3600 }); // keep for 1 hour after completion
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
      // Broadcast signed BOC
      try {
        if (env.TON_BROADCAST_URL) {
          const headers: Record<string, string> = { 'content-type': 'application/json' };
          if (env.TON_API_KEY && env.TON_API_KEY_HEADER) {
            headers[env.TON_API_KEY_HEADER] = env.TON_API_KEY;
          }
          await fetch(env.TON_BROADCAST_URL, {
            method: 'POST',
            headers,
            body: JSON.stringify({ boc: response.result }),
          });
        }
      } catch (e) {
        console.error('Broadcast failed:', e);
      }
      req.status = 'confirmed';
      req.txHash = response.result;
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
  payloadBoc?: string;
  status: 'pending' | 'confirmed' | 'rejected' | 'expired';
  createdAt: number;
  expiresAt: number;
  txHash?: string;
}

const TTL_SEC = 5 * 60; // 5 minutes

async function kvCreatePending(kv: KVNamespace, sessionId: string, walletAddress: string, to: string, amountNano: string, payloadBoc?: string): Promise<PendingRequest> {
  const now = Date.now();
  const req: PendingRequest = {
    id: crypto.randomUUID(),
    sessionId,
    walletAddress,
    type: 'transfer',
    to,
    amountNano,
    payloadBoc,
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
          payloadBoc: { type: 'string' },
          status: { type: 'string', enum: ['pending', 'confirmed', 'rejected', 'expired'] },
          createdAt: { type: 'number' },
          expiresAt: { type: 'number' },
          txHash: { type: 'string' },
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
              payloadBoc: { type: 'string', description: 'Optional BOC payload for the transaction' },
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
              payloadBoc: { type: 'string' },
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
          authUrl: `https://tongateway.ai/connect.html?authId=${authReq.authId}`,
          expiresAt: authReq.expiresAt,
          label,
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

        // Save TC session if provided
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
        }

        await completeAuthRequest(env.PENDING_STORE, authId, token, address, sid);
        return json({ ok: true, token, address, sessionId: sid });
      }

      // --- Safe TX ---

      if (request.method === 'POST' && path === '/v1/safe/tx/transfer') {
        const user = await authenticate(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401);

        const body = await parseJson(request) as Record<string, unknown>;
        const to = body.to;
        const amountNano = body.amountNano;
        if (!to || typeof to !== 'string' || !amountNano || typeof amountNano !== 'string') {
          return json({ error: 'Missing required fields: to, amountNano' }, 400);
        }

        const payloadBoc = typeof body.payloadBoc === 'string' ? body.payloadBoc : undefined;
        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, to, amountNano, payloadBoc);

        // Auto-push to wallet via TON Connect bridge
        try {
          const tcSession = await loadTcSession(env.PENDING_STORE, user.address);
          if (tcSession) {
            await bridgeSendTransaction(tcSession, req.id, to, amountNano, payloadBoc);
          }
        } catch (e) {
          console.error('Bridge send failed:', e);
        }

        return json(req);
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
            if (updated) return json(updated);
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

        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, order.to, order.amountNano, order.payloadBoc);
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

        const req = await kvCreatePending(env.PENDING_STORE, user.sessionId, user.address, order.to, order.amountNano, order.payloadBoc);
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
          payloadBoc: input.payloadBoc,
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
