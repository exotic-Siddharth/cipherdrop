import { PrismaClient } from '@prisma/client';
import { env } from '../config/env';

/** A new client. Prisma never logs query parameters here (only warnings and errors). */
export function createPrisma(url: string = env.DATABASE_URL): PrismaClient {
  return new PrismaClient({ datasourceUrl: url, log: ['warn', 'error'] });
}

let shared: PrismaClient | undefined;
/** Process-wide client (index.ts and createApp() defaults). */
export function getPrisma(): PrismaClient {
  shared ??= createPrisma();
  return shared;
}
