import { FastifyInstance } from 'fastify';

export async function registerAuthRoutes(app: FastifyInstance) {
  app.post('/v1/auth/token', {
    schema: {
      summary: 'Get auth token',
      description: 'Exchange TON wallet address for a JWT token. In production, verify ton_proof signature.',
      tags: ['auth'],
      body: {
        type: 'object',
        required: ['address'],
        properties: {
          address: { type: 'string', description: 'TON wallet address (raw or friendly)' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            token: { type: 'string' },
            address: { type: 'string' },
          },
          required: ['token', 'address'],
        },
        400: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    const { address } = request.body as { address: string };

    if (!address || typeof address !== 'string' || address.length < 10) {
      return reply.code(400).send({ error: 'Invalid address' });
    }

    // TODO: verify ton_proof signature for production
    const token = app.jwt.sign({ address }, { expiresIn: '24h' });
    return { token, address };
  });

  app.get('/v1/auth/me', {
    schema: {
      summary: 'Verify token',
      description: 'Returns the wallet address associated with the bearer token.',
      tags: ['auth'],
      headers: {
        type: 'object',
        properties: {
          authorization: { type: 'string' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: { address: { type: 'string' } },
          required: ['address'],
        },
        401: {
          type: 'object',
          properties: { error: { type: 'string' } },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    try {
      await request.jwtVerify();
      return { address: (request.user as { address: string }).address };
    } catch {
      return reply.code(401).send({ error: 'Unauthorized' });
    }
  });
}
