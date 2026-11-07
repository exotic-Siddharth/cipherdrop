import { testSchema } from './config';
import { setupTestDatabase } from './db';

/** Runs once per `vitest run`: create cipherdrop_test if missing and migrate TEST_SCHEMA (R2). */
export default async function globalSetup(): Promise<void> {
  await setupTestDatabase(testSchema());
}
