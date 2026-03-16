import { z } from 'zod';

const baseUnsignedNumber = z.union([z.number().int().nonnegative(), z.string().regex(/^\d+$/)]);

export const SignAndExecuteSchema = z.object({
  vaultAddress: z.string().min(1),
  walletId: baseUnsignedNumber,
  seqno: baseUnsignedNumber,
  validUntil: baseUnsignedNumber,
  to: z.string().min(1),
  amountNano: z.string().regex(/^\d+$/),
  privateKeyHex: z.string().min(1),
  queryId: z.string().regex(/^\d+$/).optional(),
  payloadBoc: z.string().optional(),
  dryRun: z.boolean().optional().default(false),
});

export const ExecuteSignedSchema = z.object({
  vaultAddress: z.string().min(1),
  signedBodyBoc: z.string().min(1),
  dryRun: z.boolean().optional().default(false),
});

export const RawExecuteSchema = z.object({
  externalMessageBoc: z.string().min(1),
  dryRun: z.boolean().optional().default(false),
});

export type SignAndExecuteInput = z.infer<typeof SignAndExecuteSchema>;
export type ExecuteSignedInput = z.infer<typeof ExecuteSignedSchema>;
export type RawExecuteInput = z.infer<typeof RawExecuteSchema>;
