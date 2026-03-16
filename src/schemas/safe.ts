import { z } from 'zod';

export const SafeTransferSchema = z.object({
  to: z.string().min(1),
  amountNano: z.string().regex(/^\d+$/),
  payloadBoc: z.string().optional(),
});

export const ConfirmRequestSchema = z.object({
  txHash: z.string().optional(),
});

export type SafeTransferInput = z.infer<typeof SafeTransferSchema>;
export type ConfirmRequestInput = z.infer<typeof ConfirmRequestSchema>;
