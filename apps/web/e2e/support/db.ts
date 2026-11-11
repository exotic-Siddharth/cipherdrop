/** Direct access to the e2e database for the few things the UI cannot do (promote an admin, age a drop). */
import { PrismaClient } from '@prisma/client';

const E2E_DATABASE_URL =
  'postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop_e2e?schema=public';

let client: PrismaClient | null = null;
function prisma(): PrismaClient {
  client ??= new PrismaClient({ datasourceUrl: E2E_DATABASE_URL });
  return client;
}

export async function promoteToAdmin(email: string): Promise<void> {
  await prisma().user.update({ where: { email: email.toLowerCase() }, data: { role: 'ADMIN' } });
}

export async function expireDrop(dropId: string): Promise<void> {
  await prisma().drop.update({
    where: { id: dropId },
    data: { expiresAt: new Date(Date.now() - 60_000) },
  });
}

export async function dropStatus(dropId: string): Promise<string | null> {
  const row = await prisma().drop.findUnique({ where: { id: dropId }, select: { status: true } });
  return row?.status ?? null;
}

export async function disconnectDb(): Promise<void> {
  if (client) await client.$disconnect();
  client = null;
}

/** The drop id is the path segment after /d/ in a share link. */
export function dropIdOf(link: string): string {
  const match = /\/d\/([^/#?]+)/.exec(link);
  if (!match?.[1]) throw new Error(`not a share link: ${link}`);
  return match[1];
}

export async function downloadCount(dropId: string): Promise<number> {
  const row = await prisma().drop.findUnique({
    where: { id: dropId },
    select: { downloadCount: true },
  });
  return row?.downloadCount ?? -1;
}

export async function userRole(email: string): Promise<string | null> {
  const row = await prisma().user.findUnique({
    where: { email: email.toLowerCase() },
    select: { role: true },
  });
  return row?.role ?? null;
}

export async function userQuotaBytes(email: string): Promise<bigint | null> {
  const row = await prisma().user.findUnique({
    where: { email: email.toLowerCase() },
    select: { storageQuotaBytes: true },
  });
  return row?.storageQuotaBytes ?? null;
}
