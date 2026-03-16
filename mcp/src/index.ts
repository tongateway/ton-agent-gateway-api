#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API_URL = process.env.AGENT_GATEWAY_API_URL ?? 'https://api.tongateway.ai';
const TOKEN = process.env.AGENT_GATEWAY_TOKEN;

if (!TOKEN) {
  console.error('AGENT_GATEWAY_TOKEN environment variable is required');
  process.exit(1);
}

async function apiCall(path: string, options: RequestInit = {}) {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TOKEN}`,
      ...options.headers,
    },
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error ?? `API error ${res.status}`);
  }
  return data;
}

const server = new McpServer({
  name: 'agent-gateway',
  version: '0.1.0',
});

server.tool(
  'request_transfer',
  'Request a TON transfer from the wallet owner. The request will be queued and the owner must approve it via TON Connect.',
  {
    to: z.string().describe('Destination TON address'),
    amountNano: z.string().describe('Amount in nanoTON (1 TON = 1000000000)'),
    payloadBoc: z.string().optional().describe('Optional BOC-encoded payload for the transaction'),
  },
  async ({ to, amountNano, payloadBoc }) => {
    try {
      const body: Record<string, string> = { to, amountNano };
      if (payloadBoc) body.payloadBoc = payloadBoc;

      const result = await apiCall('/v1/safe/tx/transfer', {
        method: 'POST',
        body: JSON.stringify(body),
      });

      return {
        content: [
          {
            type: 'text' as const,
            text: [
              `Transfer request created.`,
              `ID: ${result.id}`,
              `To: ${result.to}`,
              `Amount: ${result.amountNano} nanoTON`,
              `Status: ${result.status}`,
              `Expires: ${new Date(result.expiresAt).toISOString()}`,
              ``,
              `The wallet owner must approve this in their TON Connect client.`,
            ].join('\n'),
          },
        ],
      };
    } catch (e: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${e.message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  'get_request_status',
  'Check the status of a previously submitted transfer request.',
  {
    id: z.string().describe('The request ID returned by request_transfer'),
  },
  async ({ id }) => {
    try {
      const result = await apiCall(`/v1/safe/tx/${id}`);

      return {
        content: [
          {
            type: 'text' as const,
            text: [
              `Request ${result.id}`,
              `Status: ${result.status}`,
              `To: ${result.to}`,
              `Amount: ${result.amountNano} nanoTON`,
              result.txHash ? `TX Hash: ${result.txHash}` : null,
              `Created: ${new Date(result.createdAt).toISOString()}`,
              `Expires: ${new Date(result.expiresAt).toISOString()}`,
            ]
              .filter(Boolean)
              .join('\n'),
          },
        ],
      };
    } catch (e: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${e.message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  'list_pending_requests',
  'List all pending transfer requests waiting for wallet owner approval.',
  {},
  async () => {
    try {
      const data = await apiCall('/v1/safe/tx/pending');
      const requests = data.requests;

      if (!requests.length) {
        return {
          content: [{ type: 'text' as const, text: 'No pending requests.' }],
        };
      }

      const lines = requests.map(
        (r: any) =>
          `- ${r.id}: ${r.amountNano} nanoTON → ${r.to} (expires ${new Date(r.expiresAt).toISOString()})`,
      );

      return {
        content: [
          {
            type: 'text' as const,
            text: `${requests.length} pending request(s):\n${lines.join('\n')}`,
          },
        ],
      };
    } catch (e: any) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${e.message}` }],
        isError: true,
      };
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
