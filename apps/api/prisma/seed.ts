/**
 * Seed (spec section 13). `npm run db:seed` (package.json prisma.seed = tsx prisma/seed.ts).
 *
 * Creates zero-knowledge accounts and real encrypted drops with @cipherdrop/crypto in Node, stores the
 * ciphertext chunks through the configured storage driver and prints the demo credentials and share links.
 *
 * Idempotent: users are looked up by email and drops by a deterministic id (SHA-256 of a seed label), so a
 * second run creates nothing and only reprints the credentials and links. To rebuild the links of drops that
 * already exist, the seed unwraps each `ownerWrappedKey` with the demo account key, which it derives from the
 * demo password (if the password changed since the first run, run `npm run db:reset && npm run db:seed`).
 * LOCAL DEV DATA ONLY: passwords come from SEED_ADMIN_PASSWORD / SEED_DEMO_PASSWORD in apps/api/.env.
 */
import { createHash } from 'node:crypto';
import { crc32, deflateSync } from 'node:zlib';
import {
  AAD,
  CHUNK_SIZE,
  KDF_DEFAULT,
  b64urlEncode,
  buildShareLink,
  chunkCount,
  createAccountBundle,
  createPasswordProtection,
  decryptManifest,
  deriveAccountKeys,
  deriveFileKey,
  encryptChunk,
  encryptManifest,
  generateDropKey,
  generateFileId,
  importAesKey,
  toHex,
  unwrapKey,
  utf8Encode,
  wrapKey,
  type Manifest,
} from '@cipherdrop/crypto';
import type { AuditAction, Prisma, PrismaClient, User } from '@prisma/client';
import { env } from '../src/config/env';
import { createPrisma } from '../src/db/prisma';
import { hashAuthKey } from '../src/lib/argon2';
import { createStorage, type StorageDriver } from '../src/storage';

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

const ADMIN_EMAIL = 'admin@cipherdrop.local';
const DEMO_EMAIL = 'demo@cipherdrop.local';
const DROP_PASSWORD = 'correct horse battery staple';
const SEED_IP_PREFIX = '203.0.113.0/24';
const SEED_UA = 'Chrome on Windows';

/** Plaintext of one seeded file. */
interface SeedFile {
  name: string;
  type: string;
  data: Uint8Array;
}

interface SeedDropSpec {
  /** Stable label: the drop id is derived from it, which is what makes the seed idempotent. */
  label: string;
  title: string;
  files: SeedFile[];
  note: string | null;
  maxDownloads: number;
  /** Created `ageMs` ago, expiring `expiresInMs` after creation. */
  ageMs: number;
  expiresInMs: number;
  password?: string;
  state: 'READY' | 'EXPIRED';
}

/* ------------------------------------------------------------------ helpers */

/** Deterministic drop id (b64url of 16 bytes), so reruns find their own drops. */
function seedDropId(label: string): string {
  return createHash('sha256')
    .update(`cipherdrop-seed/${label}`)
    .digest()
    .subarray(0, 16)
    .toString('base64url');
}

/** A small PNG (RGB, 8-bit) drawn programmatically: teal boxes on paper joined by arrows. */
function makeDiagramPng(width = 480, height = 240): Uint8Array {
  const paper = [247, 245, 240];
  const ink = [15, 23, 42];
  const teal = [15, 118, 110];
  const tealSoft = [204, 232, 228];
  const px = new Uint8Array(width * height * 3);
  const set = (x: number, y: number, c: number[]) => {
    if (x < 0 || y < 0 || x >= width || y >= height) return;
    const o = (y * width + x) * 3;
    px[o] = c[0]!;
    px[o + 1] = c[1]!;
    px[o + 2] = c[2]!;
  };
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) set(x, y, paper);
  const rect = (x0: number, y0: number, w: number, h: number, fill: number[], border: number[]) => {
    for (let y = y0; y < y0 + h; y++) {
      for (let x = x0; x < x0 + w; x++) {
        const edge = x < x0 + 3 || x >= x0 + w - 3 || y < y0 + 3 || y >= y0 + h - 3;
        set(x, y, edge ? border : fill);
      }
    }
  };
  const boxW = 110;
  const boxH = 90;
  const top = 75;
  const xs = [30, 185, 340] as const;
  rect(xs[0], top, boxW, boxH, tealSoft, teal); // sender (browser)
  rect(xs[1], top, boxW, boxH, paper, ink); // server: ciphertext only
  rect(xs[2], top, boxW, boxH, tealSoft, teal); // recipient (browser)
  for (const bx of [xs[0], xs[2]]) {
    // padlock: a body and a shackle
    rect(bx + 40, top + 42, 30, 24, teal, teal);
    for (let t = 0; t < 4; t++) {
      for (let x = bx + 46; x < bx + 64; x++) set(x, top + 22 + t, teal);
      for (let y = top + 22; y < top + 42; y++) {
        set(bx + 46 + t, y, teal);
        set(bx + 60 + t, y, teal);
      }
    }
  }
  for (let row = 0; row < 5; row++) {
    for (let x = xs[1] + 14; x < xs[1] + boxW - 14; x++) {
      if (((x >> 2) + row) % 2 === 0)
        for (let t = 0; t < 4; t++) set(x, top + 18 + row * 12 + t, ink);
    }
  }
  const arrow = (xa: number, xb: number) => {
    const y = top + boxH / 2;
    for (let x = xa; x < xb; x++) for (let t = -1; t <= 1; t++) set(x, y + t, ink);
    for (let k = 0; k < 9; k++) for (let t = -k; t <= k; t++) set(xb - 9 + k, y + t, ink);
  };
  arrow(xs[0] + boxW + 6, xs[1] - 6);
  arrow(xs[1] + boxW + 6, xs[2] - 6);

  const stride = 1 + width * 3;
  const raw = new Uint8Array(height * stride);
  for (let y = 0; y < height; y++) {
    raw.set(px.subarray(y * width * 3, (y + 1) * width * 3), y * stride + 1); // filter byte 0 = none
  }
  const chunk = (type: string, data: Uint8Array): Buffer => {
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: RGB
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', new Uint8Array(0)),
  ]);
}

/* ------------------------------------------------------------------ users */

async function ensureUser(
  prisma: PrismaClient,
  email: string,
  password: string,
  role: 'ADMIN' | 'USER',
): Promise<{ user: User; created: boolean; recoveryKey: string | null }> {
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return { user: existing, created: false, recoveryKey: null };
  const bundle = await createAccountBundle(password, KDF_DEFAULT);
  const user = await prisma.user.create({
    data: {
      email,
      role,
      authKeyHash: await hashAuthKey(bundle.authKey),
      kdfSalt: bundle.kdf.salt,
      kdfMemoryKiB: bundle.kdf.memoryKiB,
      kdfIterations: bundle.kdf.iterations,
      kdfParallelism: bundle.kdf.parallelism,
      wrappedAccountKey: bundle.wrappedAccountKey,
      wrappedAccountKeyRecovery: bundle.wrappedAccountKeyRecovery,
      recoveryAuthHash: bundle.recoveryAuthHash,
      storageQuotaBytes: BigInt(env.USER_DEFAULT_QUOTA_BYTES),
    },
  });
  return { user, created: true, recoveryKey: bundle.recoveryKey };
}

/** The account key, unwrapped from the stored wrappedAccountKey with the user's password. */
async function unlockAccountKey(user: User, password: string): Promise<Uint8Array> {
  const { encKey } = await deriveAccountKeys(password, {
    salt: user.kdfSalt,
    memoryKiB: user.kdfMemoryKiB,
    iterations: user.kdfIterations,
    parallelism: user.kdfParallelism,
  });
  return unwrapKey(encKey, user.wrappedAccountKey, AAD.WRAP_ACCOUNT);
}

/* ------------------------------------------------------------------ drops */

/** Encrypt and store one seeded drop (rows, blobs, quota, audit). Returns its drop key. */
async function createSeedDrop(
  prisma: PrismaClient,
  storage: StorageDriver,
  owner: User,
  accountKey: Uint8Array,
  spec: SeedDropSpec,
  now: Date,
): Promise<Uint8Array> {
  const id = seedDropId(spec.label);
  await storage.deleteDrop(id); // stale blobs of an earlier database (db:reset keeps the blob directory)
  const dk = generateDropKey();
  const createdAt = new Date(now.getTime() - spec.ageMs);
  const expiresAt = new Date(createdAt.getTime() + spec.expiresInMs);
  const ready = spec.state === 'READY';

  const files = spec.files.map((f) => ({ ...f, id: generateFileId() }));
  const manifest: Manifest = {
    v: 1,
    createdAt: createdAt.getTime(),
    note: spec.note,
    files: files.map((f) => ({
      id: f.id,
      name: f.name,
      size: f.data.length,
      type: f.type,
      lastModified: createdAt.getTime() - DAY_MS,
      chunkSize: CHUNK_SIZE,
      chunkCount: chunkCount(f.data.length),
    })),
  };

  // Ciphertext chunks. The EXPIRED drop has no blobs: they were purged when it expired.
  const chunkRows: Prisma.DropChunkCreateManyInput[] = [];
  const fileRows: Prisma.DropFileCreateWithoutDropInput[] = [];
  let totalBytes = 0;
  for (const f of files) {
    const count = chunkCount(f.data.length);
    const key = await deriveFileKey(dk, f.id);
    let fileBytes = 0;
    for (let i = 0; i < count; i++) {
      const pt = f.data.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
      const ct = await encryptChunk(key, i, i === count - 1, pt);
      fileBytes += ct.length;
      if (ready) {
        await storage.putChunk(id, f.id, i, Buffer.from(ct));
        chunkRows.push({
          dropId: id,
          fileId: f.id,
          index: i,
          size: ct.length,
          sha256: toHex(createHash('sha256').update(ct).digest()),
        });
      }
    }
    totalBytes += fileBytes;
    fileRows.push({ id: f.id, ciphertextBytes: BigInt(fileBytes), chunkCount: count });
  }

  const protection = spec.password ? await createPasswordProtection(dk, spec.password) : null;
  const ownerWrappedKey = await wrapKey(await importAesKey(accountKey), dk, AAD.WRAP_OWNER);
  const encryptedManifest = await encryptManifest(dk, manifest);
  const tokenHash = () => createHash('sha256').update(generateDropKey()).digest('base64url');

  await prisma.$transaction(async (tx) => {
    await tx.drop.create({
      data: {
        id,
        ownerId: owner.id,
        ownerTokenHash: tokenHash(),
        uploadTokenHash: tokenHash(),
        status: spec.state,
        encryptedManifest,
        ownerWrappedKey,
        passwordProtected: Boolean(protection),
        pwKdfSalt: protection?.kdf.salt ?? null,
        pwKdfMemoryKiB: protection?.kdf.memoryKiB ?? null,
        pwKdfIterations: protection?.kdf.iterations ?? null,
        pwKdfParallelism: protection?.kdf.parallelism ?? null,
        wrappedDropKey: protection?.wrappedDropKey ?? null,
        authKeyHash: protection?.authKeyHash ?? null,
        totalCiphertextBytes: BigInt(totalBytes),
        fileCount: files.length,
        maxDownloads: spec.maxDownloads,
        downloadCount: ready ? 0 : 2,
        expiresAt,
        createdAt,
        readyAt: new Date(createdAt.getTime() + 20_000),
        lastOpenedAt: ready ? null : new Date(createdAt.getTime() + HOUR_MS),
        blobsDeletedAt: ready ? null : expiresAt,
        files: { create: fileRows },
      },
    });
    if (chunkRows.length > 0) await tx.dropChunk.createMany({ data: chunkRows });
    if (ready) {
      await tx.user.update({
        where: { id: owner.id },
        data: { storageUsedBytes: { increment: BigInt(totalBytes) } },
      });
    }
    const events: [AuditAction, number][] = [
      ['DROP_CREATED', 0],
      ['DROP_COMPLETED', 20_000],
    ];
    if (!ready) {
      events.push(['DROP_OPENED', HOUR_MS], ['DROP_EXPIRED', spec.expiresInMs]);
    }
    await tx.auditEvent.createMany({
      data: events.map(([action, offsetMs]) => ({
        userId: owner.id,
        dropId: id,
        action,
        ipPrefix: SEED_IP_PREFIX,
        userAgent: SEED_UA,
        createdAt: new Date(createdAt.getTime() + offsetMs),
      })),
    });
  });
  return dk;
}

/* ------------------------------------------------------------------ main */

function demoSpecs(): SeedDropSpec[] {
  const csv =
    'name,department,score\nAda Lovelace,Engineering,98\nGrace Hopper,Compilers,97\nAlan Turing,Research,99\n';
  return [
    {
      label: 'welcome',
      title: 'welcome.txt + sample.csv',
      files: [
        {
          name: 'welcome.txt',
          type: 'text/plain',
          data: utf8Encode(
            'Welcome to CipherDrop.\n\nThis file was encrypted in your browser before upload. The server only ever stored ciphertext; the key lives in the link after the # and is never sent to it.\n',
          ),
        },
        { name: 'sample.csv', type: 'text/csv', data: utf8Encode(csv) },
      ],
      note: 'Two small files to try the download flow.',
      maxDownloads: 10,
      ageMs: 2 * HOUR_MS,
      expiresInMs: 7 * DAY_MS,
      state: 'READY',
    },
    {
      label: 'diagram',
      title: 'diagram.png (password-protected)',
      files: [{ name: 'diagram.png', type: 'image/png', data: makeDiagramPng() }],
      note: null,
      maxDownloads: 5,
      ageMs: 5 * HOUR_MS,
      expiresInMs: 3 * DAY_MS,
      password: DROP_PASSWORD,
      state: 'READY',
    },
    {
      label: 'burn-note',
      title: 'burn-note.txt (1 download)',
      files: [
        {
          name: 'burn-note.txt',
          type: 'text/plain',
          data: utf8Encode(
            'This note can be downloaded exactly once. After that, the drop is gone.\n',
          ),
        },
      ],
      note: null,
      maxDownloads: 1,
      ageMs: 30 * MINUTE_MS,
      expiresInMs: DAY_MS,
      state: 'READY',
    },
    {
      label: 'expired-report',
      title: 'old-report.pdf (expired)',
      files: [
        {
          name: 'old-report.pdf',
          type: 'application/pdf',
          data: utf8Encode('%PDF-1.4\n% seeded placeholder\n'),
        },
      ],
      note: null,
      maxDownloads: 5,
      ageMs: 9 * DAY_MS,
      expiresInMs: 7 * DAY_MS,
      state: 'EXPIRED',
    },
  ];
}

async function main(): Promise<void> {
  const adminPassword = env.SEED_ADMIN_PASSWORD;
  const demoPassword = env.SEED_DEMO_PASSWORD;
  if (!adminPassword || !demoPassword) {
    throw new Error('Set SEED_ADMIN_PASSWORD and SEED_DEMO_PASSWORD (see apps/api/.env.example).');
  }
  const prisma = createPrisma();
  const storage = createStorage(env);
  await storage.init();
  const now = new Date();
  const origin = env.WEB_ORIGIN;

  try {
    const admin = await ensureUser(prisma, ADMIN_EMAIL, adminPassword, 'ADMIN');
    const demo = await ensureUser(prisma, DEMO_EMAIL, demoPassword, 'USER');
    let accountKey: Uint8Array;
    try {
      accountKey = await unlockAccountKey(demo.user, demoPassword);
    } catch {
      throw new Error(
        `${DEMO_EMAIL} exists but SEED_DEMO_PASSWORD no longer matches it. Run "npm run db:reset && npm run db:seed".`,
      );
    }

    if (demo.created) {
      const ago = (min: number) => new Date(now.getTime() - min * MINUTE_MS);
      const events: [AuditAction, Date][] = [
        ['REGISTER', ago(60 * 24 * 9)],
        ['LOGIN_SUCCESS', ago(60 * 24 * 9 - 1)],
        ['LOGIN_FAILURE', ago(60 * 24 * 3)],
        ['LOGIN_SUCCESS', ago(60 * 24 * 3 - 2)],
        ['LOGIN_SUCCESS', ago(30)],
      ];
      await prisma.auditEvent.createMany({
        data: events.map(([action, createdAt]) => ({
          userId: demo.user.id,
          action,
          ipPrefix: SEED_IP_PREFIX,
          userAgent: SEED_UA,
          createdAt,
        })),
      });
    }
    if (admin.created) {
      await prisma.auditEvent.create({
        data: {
          userId: admin.user.id,
          action: 'REGISTER',
          ipPrefix: SEED_IP_PREFIX,
          userAgent: SEED_UA,
        },
      });
    }

    console.log('\nCipherDrop seed');
    console.log('===============');
    console.log(
      `Admin : ${ADMIN_EMAIL} / ${adminPassword}${admin.created ? '' : '  (already existed)'}`,
    );
    console.log(
      `Demo  : ${DEMO_EMAIL} / ${demoPassword}${demo.created ? '' : '  (already existed)'}`,
    );
    if (demo.recoveryKey) {
      console.log(`Demo recovery key (dev data): ${demo.recoveryKey}`);
    }
    console.log('\nDemo drops:');

    const vaultKey = await importAesKey(accountKey);
    let reportTarget: { id: string; dk: Uint8Array } | null = null;
    for (const spec of demoSpecs()) {
      const id = seedDropId(spec.label);
      let drop = await prisma.drop.findUnique({ where: { id } });
      const isNew = !drop;
      let dk: Uint8Array | null = null;
      if (!drop) {
        dk = await createSeedDrop(prisma, storage, demo.user, accountKey, spec, now);
        drop = await prisma.drop.findUniqueOrThrow({ where: { id } });
      } else if (drop.ownerWrappedKey) {
        dk = await unwrapKey(vaultKey, drop.ownerWrappedKey, AAD.WRAP_OWNER);
      }
      const names = dk
        ? (await decryptManifest(dk, drop.encryptedManifest)).files.map((f) => f.name).join(', ')
        : '?';
      console.log(`  - [${drop.status}${isNew ? ', new' : ''}] ${spec.title}  (${names})`);
      if (spec.state === 'EXPIRED') {
        console.log(
          '      expired: shows as an expired drop in the dashboard; its link no longer works',
        );
      } else if (drop.passwordProtected) {
        console.log(`      ${origin}/d/${id}   password: ${DROP_PASSWORD}`);
      } else if (dk) {
        console.log(`      ${buildShareLink(origin, id, dk)}`);
      }
      if (spec.label === 'diagram' && dk) reportTarget = { id, dk };
    }

    // One OPEN abuse report on the password drop, with the reporter-provided key so admins can Review it.
    if (reportTarget && (await prisma.report.count({ where: { dropId: reportTarget.id } })) === 0) {
      await prisma.report.create({
        data: {
          dropId: reportTarget.id,
          reason: 'OTHER',
          details: 'Seeded example report: please check that this diagram is harmless.',
          providedKey: b64urlEncode(reportTarget.dk),
          reporterIpPrefix: '198.51.100.0/24',
          status: 'OPEN',
        },
      });
      await prisma.auditEvent.create({
        data: {
          userId: demo.user.id,
          dropId: reportTarget.id,
          action: 'DROP_REPORTED',
          createdAt: new Date(now.getTime() - 10 * MINUTE_MS),
        },
      });
    }
    console.log(`\nOpen ${origin} and use "Use demo account" on the login page.`);
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
