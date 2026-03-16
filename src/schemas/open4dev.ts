import { z } from 'zod';

const uintLike = z.union([z.number().int().nonnegative(), z.string().regex(/^\d+$/)]);

export const CreateTonOrderSchema = z.object({
  vaultAddress: z.string().min(1),
  privateKeyHex: z.string().min(1),
  walletId: uintLike,
  seqno: uintLike,
  validUntil: uintLike,

  dexVaultTonAddress: z.string().min(1),
  sendValueNano: z.string().regex(/^\d+$/),
  orderAmountNano: z.string().regex(/^\d+$/),
  priceRateNano: z.string().regex(/^\d+$/),
  slippage: uintLike,
  toJettonMinter: z.string().min(1),
  providerFeeAddress: z.string().min(1),
  feeNum: uintLike,
  feeDenom: uintLike,
  matcherFeeNum: uintLike,
  matcherFeeDenom: uintLike,
  oppositeVaultAddress: z.string().min(1),

  createdAt: uintLike.optional(),
  queryId: z.string().regex(/^\d+$/).optional(),
  dryRun: z.boolean().optional().default(false),
});

export const CreateJettonOrderSchema = z.object({
  vaultAddress: z.string().min(1),
  privateKeyHex: z.string().min(1),
  walletId: uintLike,
  seqno: uintLike,
  validUntil: uintLike,

  jettonWalletAddress: z.string().min(1),
  attachedTonAmountNano: z.string().regex(/^\d+$/),
  jettonAmountNano: z.string().regex(/^\d+$/),
  dexVaultAddress: z.string().min(1),
  ownerAddress: z.string().min(1),
  forwardTonAmountNano: z.string().regex(/^\d+$/),
  priceRateNano: z.string().regex(/^\d+$/),
  slippage: uintLike,
  toJettonMinter: z.string().optional(),
  providerFeeAddress: z.string().min(1),
  feeNum: uintLike,
  feeDenom: uintLike,
  matcherFeeNum: uintLike,
  matcherFeeDenom: uintLike,
  oppositeVaultAddress: z.string().min(1),

  customPayloadBoc: z.string().optional(),
  createdAt: uintLike.optional(),
  queryId: z.string().regex(/^\d+$/).optional(),
  dryRun: z.boolean().optional().default(false),
});

export type CreateTonOrderInput = z.infer<typeof CreateTonOrderSchema>;
export type CreateJettonOrderInput = z.infer<typeof CreateJettonOrderSchema>;

// --- Safe-mode schemas (no private key, no signing fields) ---

export const SafeCreateTonOrderSchema = z.object({
  dexVaultTonAddress: z.string().min(1),
  sendValueNano: z.string().regex(/^\d+$/),
  orderAmountNano: z.string().regex(/^\d+$/),
  priceRateNano: z.string().regex(/^\d+$/),
  slippage: uintLike,
  toJettonMinter: z.string().min(1),
  providerFeeAddress: z.string().min(1),
  feeNum: uintLike,
  feeDenom: uintLike,
  matcherFeeNum: uintLike,
  matcherFeeDenom: uintLike,
  oppositeVaultAddress: z.string().min(1),
  createdAt: uintLike.optional(),
});

export const SafeCreateJettonOrderSchema = z.object({
  jettonWalletAddress: z.string().min(1),
  attachedTonAmountNano: z.string().regex(/^\d+$/),
  jettonAmountNano: z.string().regex(/^\d+$/),
  dexVaultAddress: z.string().min(1),
  ownerAddress: z.string().min(1),
  forwardTonAmountNano: z.string().regex(/^\d+$/),
  priceRateNano: z.string().regex(/^\d+$/),
  slippage: uintLike,
  toJettonMinter: z.string().optional(),
  providerFeeAddress: z.string().min(1),
  feeNum: uintLike,
  feeDenom: uintLike,
  matcherFeeNum: uintLike,
  matcherFeeDenom: uintLike,
  oppositeVaultAddress: z.string().min(1),
  customPayloadBoc: z.string().optional(),
  createdAt: uintLike.optional(),
  queryId: z.string().regex(/^\d+$/).optional(),
});

export type SafeCreateTonOrderInput = z.infer<typeof SafeCreateTonOrderSchema>;
export type SafeCreateJettonOrderInput = z.infer<typeof SafeCreateJettonOrderSchema>;
