import { config } from '../config';

export type BroadcastResponse = {
  status: number;
  body: unknown;
};

export async function broadcastExternalMessage(externalMessageBoc: string): Promise<BroadcastResponse> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
  };

  if (config.TON_API_KEY) {
    headers[config.TON_API_KEY_HEADER] = config.TON_API_KEY;
  }

  const response = await fetch(config.TON_BROADCAST_URL, {
    method: 'POST',
    headers,
    body: JSON.stringify({ boc: externalMessageBoc }),
  });

  const raw = await response.text();
  let body: unknown = raw;

  try {
    body = JSON.parse(raw);
  } catch {
    // keep raw string
  }

  if (!response.ok) {
    throw new Error(`Broadcast failed (${response.status}): ${typeof body === 'string' ? body : JSON.stringify(body)}`);
  }

  return {
    status: response.status,
    body,
  };
}
