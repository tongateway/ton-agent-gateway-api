import { FastifyInstance } from 'fastify';
import { broadcastExternalMessage } from '../services/broadcaster';
import {
  buildCreateJettonOrderMessage,
  buildCreateTonOrderMessage,
} from '../services/open4devOrderBook';
import { CreateJettonOrderSchema, CreateTonOrderSchema } from '../schemas/open4dev';
import { resolveSecretKeyFromHex } from '../utils/keys';
import { toSafeNumber } from '../utils/numbers';

const boolDryRun = {
  type: 'boolean',
  default: false,
  description: 'If true, returns generated message without broadcast.',
} as const;

const executeResponseSchema = {
  200: {
    type: 'object',
    properties: {
      orderPayloadBoc: { type: 'string' },
      signedBodyBoc: { type: 'string' },
      externalMessageBoc: { type: 'string' },
      signatureHex: { type: 'string' },
      messageHashHex: { type: 'string' },
      broadcasted: { type: 'boolean' },
      providerResponse: {},
    },
    required: ['orderPayloadBoc', 'signedBodyBoc', 'externalMessageBoc', 'signatureHex', 'messageHashHex', 'broadcasted'],
  },
  400: {
    type: 'object',
    properties: {
      error: { type: 'string' },
    },
    required: ['error'],
  },
} as const;

export async function registerOpen4DevRoutes(app: FastifyInstance) {
  app.post('/v1/open4dev/orders/create-ton', {
    schema: {
      summary: 'Create TON-side order (open4dev order-book)',
      tags: ['open4dev'],
      body: {
        type: 'object',
        required: [
          'vaultAddress',
          'privateKeyHex',
          'walletId',
          'seqno',
          'validUntil',
          'dexVaultTonAddress',
          'sendValueNano',
          'orderAmountNano',
          'priceRateNano',
          'slippage',
          'toJettonMinter',
          'providerFeeAddress',
          'feeNum',
          'feeDenom',
          'matcherFeeNum',
          'matcherFeeDenom',
          'oppositeVaultAddress',
        ],
        properties: {
          vaultAddress: { type: 'string' },
          privateKeyHex: { type: 'string' },
          walletId: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          seqno: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          validUntil: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          dexVaultTonAddress: { type: 'string' },
          sendValueNano: { type: 'string' },
          orderAmountNano: { type: 'string' },
          priceRateNano: { type: 'string' },
          slippage: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          toJettonMinter: { type: 'string' },
          providerFeeAddress: { type: 'string' },
          feeNum: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          feeDenom: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          matcherFeeNum: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          matcherFeeDenom: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          oppositeVaultAddress: { type: 'string' },
          createdAt: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          queryId: { type: 'string' },
          dryRun: boolDryRun,
        },
      },
      response: executeResponseSchema,
    },
  }, async (request, reply) => {
    try {
      const input = CreateTonOrderSchema.parse(request.body);
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

  app.post('/v1/open4dev/orders/create-jetton', {
    schema: {
      summary: 'Create Jetton-side order (open4dev order-book)',
      tags: ['open4dev'],
      body: {
        type: 'object',
        required: [
          'vaultAddress',
          'privateKeyHex',
          'walletId',
          'seqno',
          'validUntil',
          'jettonWalletAddress',
          'attachedTonAmountNano',
          'jettonAmountNano',
          'dexVaultAddress',
          'ownerAddress',
          'forwardTonAmountNano',
          'priceRateNano',
          'slippage',
          'providerFeeAddress',
          'feeNum',
          'feeDenom',
          'matcherFeeNum',
          'matcherFeeDenom',
          'oppositeVaultAddress',
        ],
        properties: {
          vaultAddress: { type: 'string' },
          privateKeyHex: { type: 'string' },
          walletId: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          seqno: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          validUntil: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          jettonWalletAddress: { type: 'string' },
          attachedTonAmountNano: { type: 'string' },
          jettonAmountNano: { type: 'string' },
          dexVaultAddress: { type: 'string' },
          ownerAddress: { type: 'string' },
          forwardTonAmountNano: { type: 'string' },
          priceRateNano: { type: 'string' },
          slippage: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          toJettonMinter: { type: 'string' },
          providerFeeAddress: { type: 'string' },
          feeNum: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          feeDenom: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          matcherFeeNum: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          matcherFeeDenom: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          oppositeVaultAddress: { type: 'string' },
          customPayloadBoc: { type: 'string' },
          createdAt: { anyOf: [{ type: 'number' }, { type: 'string' }] },
          queryId: { type: 'string' },
          dryRun: boolDryRun,
        },
      },
      response: executeResponseSchema,
    },
  }, async (request, reply) => {
    try {
      const input = CreateJettonOrderSchema.parse(request.body);
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
}
