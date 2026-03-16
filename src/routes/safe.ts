import { FastifyInstance } from 'fastify';
import { SafeTransferSchema, ConfirmRequestSchema } from '../schemas/safe';
import {
  createPendingRequest,
  getPendingRequests,
  getRequest,
  confirmRequest,
  rejectRequest,
} from '../services/pendingStore';

async function authenticate(request: any, reply: any) {
  try {
    await request.jwtVerify();
  } catch {
    return reply.code(401).send({ error: 'Unauthorized' });
  }
}

const pendingResponseSchema = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    walletAddress: { type: 'string' },
    type: { type: 'string' },
    to: { type: 'string' },
    amountNano: { type: 'string' },
    payloadBoc: { type: 'string' },
    status: { type: 'string' },
    createdAt: { type: 'number' },
    expiresAt: { type: 'number' },
    txHash: { type: 'string' },
  },
} as const;

export async function registerSafeRoutes(app: FastifyInstance) {
  // Agent calls this with JWT to request a transfer
  app.post('/v1/safe/tx/transfer', {
    preHandler: authenticate,
    schema: {
      summary: 'Request a safe transfer',
      description: 'Creates a pending transfer that the wallet owner must approve via TON Connect.',
      tags: ['safe'],
      headers: {
        type: 'object',
        properties: { authorization: { type: 'string' } },
      },
      body: {
        type: 'object',
        required: ['to', 'amountNano'],
        properties: {
          to: { type: 'string' },
          amountNano: { type: 'string' },
          payloadBoc: { type: 'string' },
        },
      },
      response: {
        200: pendingResponseSchema,
        400: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    try {
      const input = SafeTransferSchema.parse(request.body);
      const { address } = request.user as { address: string };

      const pending = createPendingRequest(address, {
        to: input.to,
        amountNano: input.amountNano,
        payloadBoc: input.payloadBoc,
      });

      return pending;
    } catch (error) {
      return reply.code(400).send({
        error: error instanceof Error ? error.message : 'Invalid input',
      });
    }
  });

  // Client polls this to get pending requests for the connected wallet
  app.get('/v1/safe/tx/pending', {
    preHandler: authenticate,
    schema: {
      summary: 'List pending requests',
      description: 'Returns all pending transfer requests for the authenticated wallet.',
      tags: ['safe'],
      headers: {
        type: 'object',
        properties: { authorization: { type: 'string' } },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            requests: { type: 'array', items: pendingResponseSchema },
          },
          required: ['requests'],
        },
      },
    },
  }, async (request) => {
    const { address } = request.user as { address: string };
    return { requests: getPendingRequests(address) };
  });

  // Get a specific request
  app.get('/v1/safe/tx/:id', {
    preHandler: authenticate,
    schema: {
      summary: 'Get request by ID',
      tags: ['safe'],
      params: {
        type: 'object',
        properties: { id: { type: 'string' } },
        required: ['id'],
      },
      response: {
        200: pendingResponseSchema,
        404: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { address } = request.user as { address: string };
    const req = getRequest(id);

    if (!req || req.walletAddress !== address) {
      return reply.code(404).send({ error: 'Not found' });
    }

    return req;
  });

  // Client calls this after user approves in wallet
  app.post('/v1/safe/tx/:id/confirm', {
    preHandler: authenticate,
    schema: {
      summary: 'Confirm a pending request',
      description: 'Mark a pending request as confirmed after wallet signs the transaction.',
      tags: ['safe'],
      params: {
        type: 'object',
        properties: { id: { type: 'string' } },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          txHash: { type: 'string' },
        },
      },
      response: {
        200: pendingResponseSchema,
        400: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
        404: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { address } = request.user as { address: string };
    const existing = getRequest(id);

    if (!existing || existing.walletAddress !== address) {
      return reply.code(404).send({ error: 'Not found' });
    }

    const body = ConfirmRequestSchema.safeParse(request.body);
    const req = confirmRequest(id, body.success ? body.data.txHash : undefined);

    if (!req) {
      return reply.code(400).send({ error: 'Request is not pending' });
    }

    return req;
  });

  // Client calls this if user rejects
  app.post('/v1/safe/tx/:id/reject', {
    preHandler: authenticate,
    schema: {
      summary: 'Reject a pending request',
      tags: ['safe'],
      params: {
        type: 'object',
        properties: { id: { type: 'string' } },
        required: ['id'],
      },
      response: {
        200: pendingResponseSchema,
        400: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
        404: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { address } = request.user as { address: string };
    const existing = getRequest(id);

    if (!existing || existing.walletAddress !== address) {
      return reply.code(404).send({ error: 'Not found' });
    }

    const req = rejectRequest(id);

    if (!req) {
      return reply.code(400).send({ error: 'Request is not pending' });
    }

    return req;
  });
}
