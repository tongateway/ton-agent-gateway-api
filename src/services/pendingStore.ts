import { randomUUID } from 'crypto';

export type PendingStatus = 'pending' | 'confirmed' | 'rejected' | 'expired';

export interface PendingRequest {
  id: string;
  walletAddress: string;
  type: 'transfer';
  to: string;
  amountNano: string;
  payloadBoc?: string;
  status: PendingStatus;
  createdAt: number;
  expiresAt: number;
  txHash?: string;
}

const TTL_MS = 5 * 60 * 1000; // 5 minutes

const store = new Map<string, PendingRequest>();

export function createPendingRequest(
  walletAddress: string,
  params: { to: string; amountNano: string; payloadBoc?: string },
): PendingRequest {
  const now = Date.now();
  const request: PendingRequest = {
    id: randomUUID(),
    walletAddress,
    type: 'transfer',
    to: params.to,
    amountNano: params.amountNano,
    payloadBoc: params.payloadBoc,
    status: 'pending',
    createdAt: now,
    expiresAt: now + TTL_MS,
  };

  store.set(request.id, request);
  return request;
}

export function getPendingRequests(walletAddress: string): PendingRequest[] {
  const now = Date.now();
  const results: PendingRequest[] = [];

  for (const req of store.values()) {
    if (req.walletAddress !== walletAddress) continue;
    if (req.status === 'pending' && req.expiresAt < now) {
      req.status = 'expired';
    }
    if (req.status === 'pending') {
      results.push(req);
    }
  }

  return results;
}

export function getRequest(id: string): PendingRequest | undefined {
  const req = store.get(id);
  if (!req) return undefined;

  if (req.status === 'pending' && req.expiresAt < Date.now()) {
    req.status = 'expired';
  }

  return req;
}

export function confirmRequest(id: string, txHash?: string): PendingRequest | undefined {
  const req = store.get(id);
  if (!req || req.status !== 'pending') return undefined;

  req.status = 'confirmed';
  req.txHash = txHash;
  return req;
}

export function rejectRequest(id: string): PendingRequest | undefined {
  const req = store.get(id);
  if (!req || req.status !== 'pending') return undefined;

  req.status = 'rejected';
  return req;
}
