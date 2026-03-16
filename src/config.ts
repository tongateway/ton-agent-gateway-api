import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const EnvSchema = z.object({
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(8080),
  TON_BROADCAST_URL: z.string().url().default('https://testnet.toncenter.com/api/v2/sendBoc'),
  TON_API_KEY: z.string().optional(),
  TON_API_KEY_HEADER: z.string().default('X-API-Key'),
  JWT_SECRET: z.string().default('change-me-in-production'),
});

const parsed = EnvSchema.safeParse(process.env);
if (!parsed.success) {
  throw new Error(`Invalid environment config: ${parsed.error.message}`);
}

export const config = parsed.data;
