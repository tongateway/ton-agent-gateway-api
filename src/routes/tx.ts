import { FastifyInstance } from 'fastify';
import { broadcastExternalMessage } from '../services/broadcaster';
import { buildSignedTransferMessage, wrapSignedBodyIntoExternalMessage } from '../services/tonMessage';
import { ExecuteSignedSchema, RawExecuteSchema, SignAndExecuteSchema } from '../schemas/tx';
import { resolveSecretKeyFromHex } from '../utils/keys';
import { toSafeNumber } from '../utils/numbers';

const booleanDryRunProperty = {
  type: 'boolean',
  description: 'If true, only build/validate message and skip blockchain broadcast.',
  default: false,
} as const;

export async function registerTxRoutes(app: FastifyInstance) {
  app.get('/health', {
    schema: {
      summary: 'Health check',
      tags: ['system'],
      response: {
        200: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
          },
          required: ['ok'],
        },
      },
    },
  }, async () => ({ ok: true }));

  app.post('/v1/tx/sign-and-execute', {
    schema: {
      summary: 'Sign transfer and execute',
      description: 'Build signed external transfer for AgentVault and optionally broadcast it.',
      tags: ['tx'],
      body: {
        type: 'object',
        required: ['vaultAddress', 'walletId', 'seqno', 'validUntil', 'to', 'amountNano', 'privateKeyHex'],
        properties: {
          vaultAddress: { type: 'string' },
          walletId: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          seqno: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          validUntil: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          to: { type: 'string' },
          amountNano: { type: 'string' },
          privateKeyHex: { type: 'string', description: '32-byte seed or 64-byte secret key in hex.' },
          queryId: { type: 'string' },
          payloadBoc: { type: 'string', description: 'Optional cell BOC (base64) used as transfer payload reference.' },
          dryRun: booleanDryRunProperty,
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            signedBodyBoc: { type: 'string' },
            externalMessageBoc: { type: 'string' },
            signatureHex: { type: 'string' },
            messageHashHex: { type: 'string' },
            broadcasted: { type: 'boolean' },
            providerResponse: {},
          },
          required: ['signedBodyBoc', 'externalMessageBoc', 'signatureHex', 'messageHashHex', 'broadcasted'],
        },
        400: {
          type: 'object',
          properties: {
            error: { type: 'string' },
          },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    try {
      const input = SignAndExecuteSchema.parse(request.body);
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

      if (input.dryRun) {
        return {
          ...result,
          broadcasted: false,
        };
      }

      const providerResponse = await broadcastExternalMessage(result.externalMessageBoc);
      return {
        ...result,
        broadcasted: true,
        providerResponse,
      };
    } catch (error) {
      app.log.error(error);
      return reply.code(400).send({
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  app.post('/v1/tx/execute-signed', {
    schema: {
      summary: 'Execute signed body',
      description: 'Wrap already signed body into external message and optionally broadcast it.',
      tags: ['tx'],
      body: {
        type: 'object',
        required: ['vaultAddress', 'signedBodyBoc'],
        properties: {
          vaultAddress: { type: 'string' },
          signedBodyBoc: { type: 'string' },
          dryRun: booleanDryRunProperty,
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            externalMessageBoc: { type: 'string' },
            broadcasted: { type: 'boolean' },
            providerResponse: {},
          },
          required: ['externalMessageBoc', 'broadcasted'],
        },
        400: {
          type: 'object',
          properties: {
            error: { type: 'string' },
          },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    try {
      const input = ExecuteSignedSchema.parse(request.body);
      const externalMessageBoc = wrapSignedBodyIntoExternalMessage(input.vaultAddress, input.signedBodyBoc);

      if (input.dryRun) {
        return {
          externalMessageBoc,
          broadcasted: false,
        };
      }

      const providerResponse = await broadcastExternalMessage(externalMessageBoc);
      return {
        externalMessageBoc,
        broadcasted: true,
        providerResponse,
      };
    } catch (error) {
      app.log.error(error);
      return reply.code(400).send({
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  app.post('/v1/tx/raw-execute', {
    schema: {
      summary: 'Execute raw external BOC',
      description: 'Broadcast a fully prepared external message BOC.',
      tags: ['tx'],
      body: {
        type: 'object',
        required: ['externalMessageBoc'],
        properties: {
          externalMessageBoc: { type: 'string' },
          dryRun: booleanDryRunProperty,
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            externalMessageBoc: { type: 'string' },
            broadcasted: { type: 'boolean' },
            providerResponse: {},
          },
          required: ['externalMessageBoc', 'broadcasted'],
        },
        400: {
          type: 'object',
          properties: {
            error: { type: 'string' },
          },
          required: ['error'],
        },
      },
    },
  }, async (request, reply) => {
    try {
      const input = RawExecuteSchema.parse(request.body);

      if (input.dryRun) {
        return {
          externalMessageBoc: input.externalMessageBoc,
          broadcasted: false,
        };
      }

      const providerResponse = await broadcastExternalMessage(input.externalMessageBoc);
      return {
        externalMessageBoc: input.externalMessageBoc,
        broadcasted: true,
        providerResponse,
      };
    } catch (error) {
      app.log.error(error);
      return reply.code(400).send({
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
}
