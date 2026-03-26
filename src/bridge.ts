// TON Connect bridge client for server-side signing
// Handles encryption, sending transaction requests, and polling for wallet responses

import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';

// --- Types ---

export interface TcSession {
  secretKey: string;       // hex-encoded dApp NaCl secret key
  publicKey: string;       // hex-encoded dApp NaCl public key
  walletPublicKey: string; // hex-encoded wallet's NaCl public key
  bridgeUrl: string;       // e.g. "https://bridge.tonapi.io/bridge"
  walletAddress: string;
}

interface SendTransactionRequest {
  method: 'sendTransaction';
  params: [string]; // JSON-encoded transaction
  id: string;
}

interface BridgeEvent {
  from: string;
  message: string; // base64-encoded encrypted message
}

export interface BridgeResponse {
  id: string;
  result?: string;  // signed BOC (base64)
  error?: { code: number; message: string };
}

// --- Helpers ---

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Encryption ---

function encrypt(message: string, secretKey: Uint8Array, receiverPublicKey: Uint8Array): Uint8Array {
  const encoded = naclUtil.decodeUTF8(message);
  const nonce = nacl.randomBytes(24);
  const encrypted = nacl.box(encoded, nonce, receiverPublicKey, secretKey);
  const result = new Uint8Array(nonce.length + encrypted.length);
  result.set(nonce);
  result.set(encrypted, nonce.length);
  return result;
}

function decrypt(message: Uint8Array, secretKey: Uint8Array, senderPublicKey: Uint8Array): string {
  const nonce = message.slice(0, 24);
  const encrypted = message.slice(24);
  const decrypted = nacl.box.open(encrypted, nonce, senderPublicKey, secretKey);
  if (!decrypted) {
    throw new Error('Failed to decrypt bridge message');
  }
  return naclUtil.encodeUTF8(decrypted);
}

// --- Bridge Communication ---

/**
 * Send a sendTransaction request to the wallet via the TON Connect bridge.
 */
export interface BridgeMessage {
  address: string;
  amount: string;
  payload?: string;
  stateInit?: string;
}

export async function bridgeSendTransaction(
  session: TcSession,
  requestId: string,
  to: string,
  amountNano: string,
  payload?: string,
  stateInit?: string,
): Promise<void> {
  return bridgeSendMessages(session, requestId, [{
    address: to,
    amount: amountNano,
    ...(payload ? { payload } : {}),
    ...(stateInit ? { stateInit } : {}),
  }]);
}

export async function bridgeSendMessages(
  session: TcSession,
  requestId: string,
  messages: BridgeMessage[],
): Promise<void> {
  const transaction = {
    valid_until: Math.floor(Date.now() / 1000) + 300,
    messages,
  };

  const request: SendTransactionRequest = {
    method: 'sendTransaction',
    params: [JSON.stringify(transaction)],
    id: requestId,
  };

  const secretKey = hexToBytes(session.secretKey);
  const walletPubKey = hexToBytes(session.walletPublicKey);
  const clientId = session.publicKey;

  const encrypted = encrypt(JSON.stringify(request), secretKey, walletPubKey);
  const body = naclUtil.encodeBase64(encrypted);

  const bridgeBase = session.bridgeUrl.replace(/\/+$/, ''); // strip trailing slashes
  const url = new URL(`${bridgeBase}/message`);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('to', session.walletPublicKey);
  url.searchParams.set('ttl', '300');
  url.searchParams.set('topic', 'sendTransaction');

  console.log('Bridge URL:', url.toString().slice(0, 80));
  const res = await fetch(url.toString(), {
    method: 'POST',
    body,
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    console.error('Bridge response:', res.status, errBody.slice(0, 200));
    throw new Error(`Bridge send failed: ${res.status}`);
  }
}

/**
 * Poll the bridge for wallet responses.
 */
export async function bridgePollResponses(
  session: TcSession,
  lastEventId?: string,
): Promise<{ responses: BridgeResponse[]; lastEventId?: string }> {
  const clientId = session.publicKey;
  const bridgeBase2 = session.bridgeUrl.replace(/\/+$/, '');
  const url = new URL(`${bridgeBase2}/events`);
  url.searchParams.set('client_id', clientId);
  if (lastEventId) {
    url.searchParams.set('last_event_id', lastEventId);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(url.toString(), {
      headers: { Accept: 'text/event-stream' },
      signal: controller.signal,
    });

    if (!res.ok || !res.body) {
      return { responses: [], lastEventId };
    }

    const text = await res.text();
    const secretKey = hexToBytes(session.secretKey);
    const walletPubKey = hexToBytes(session.walletPublicKey);

    const responses: BridgeResponse[] = [];
    let newLastEventId = lastEventId;

    // Parse SSE events
    const events = text.split('\n\n').filter(Boolean);
    for (const event of events) {
      const lines = event.split('\n');
      let id: string | undefined;
      let data: string | undefined;

      for (const line of lines) {
        if (line.startsWith('id:')) id = line.slice(3).trim();
        if (line.startsWith('data:')) data = line.slice(5).trim();
      }

      if (id) newLastEventId = id;
      if (!data || data === 'heartbeat') continue;

      try {
        const parsed: BridgeEvent = JSON.parse(data);
        if (parsed.from !== session.walletPublicKey) continue;

        const encryptedBytes = naclUtil.decodeBase64(parsed.message);
        const decrypted = decrypt(encryptedBytes, secretKey, walletPubKey);
        const response: BridgeResponse = JSON.parse(decrypted);
        responses.push(response);
      } catch {
        // Skip malformed events
      }
    }

    return { responses, lastEventId: newLastEventId };
  } catch (e: unknown) {
    if (e instanceof Error && e.name === 'AbortError') {
      return { responses: [], lastEventId };
    }
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}
