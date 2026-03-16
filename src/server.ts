import Fastify from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import fastifyJwt from '@fastify/jwt';
import cors from '@fastify/cors';
import { config } from './config';
import { registerTxRoutes } from './routes/tx';
import { registerOpen4DevRoutes } from './routes/open4dev';
import { registerAuthRoutes } from './routes/auth';
import { registerSafeRoutes } from './routes/safe';

export async function buildServer() {
  const app = Fastify({
    logger: true,
  });

  await app.register(cors, { origin: true });

  await app.register(fastifyJwt, { secret: config.JWT_SECRET });

  await app.register(swagger, {
    openapi: {
      info: {
        title: 'Agent Gateway API',
        description: 'Simple TON transaction API for AI agents (session key compatible).',
        version: '0.2.0',
      },
      tags: [
        { name: 'system', description: 'System endpoints' },
        { name: 'auth', description: 'Authentication' },
        { name: 'tx', description: 'Transaction endpoints' },
        { name: 'safe', description: 'Safe transaction endpoints (requires wallet approval)' },
        { name: 'open4dev', description: 'open4dev order-book endpoints' },
      ],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          },
        },
      },
    },
  });

  await app.register(swaggerUI, {
    routePrefix: '/docs',
  });

  await registerTxRoutes(app);
  await registerOpen4DevRoutes(app);
  await registerAuthRoutes(app);
  await registerSafeRoutes(app);

  return app;
}
