/**
 * Spec section 12 for the drop flows (auth/logs.test.ts covers the auth flows): owner, upload and download
 * tokens, encrypted manifests, wrapped keys, password proofs, a reporter's opt-in decryption key and file
 * bytes never reach the logs: not on success, not on 4xx, not on a forced 5xx. Prisma's own warnings and
 * errors go through the same pino logger (db/prisma.ts), so they land in the captured output too; anything
 * printed on the console instead would bypass pino and its redaction, so the console is captured as well.
 */
import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createAdminRecord, createUserRecord } from '../../../test/factories';
import { env } from '../../config/env';
import { createPrisma } from '../../db/prisma';
import { createLogger } from '../../lib/logger';
import {
  chunkData,
  createBody,
  createDropOk,
  createReadyDrop,
  fakeManifest,
  fakeWrappedKey,
  getChunk,
  openDrop,
  passwordFixture,
  putChunk,
  testFile,
  token32,
  type ReadyDrop,
} from './test-utils';

const lines: string[] = [];
const logger = createLogger({
  level: 'trace',
  destination: { write: (s: string) => lines.push(s) },
});
let consoleOut: string[] = [];
let prisma: PrismaClient;
let t: TestApp;

beforeAll(async () => {
  // The app and its Prisma client share the capturing logger.
  prisma = createPrisma(env.DATABASE_URL, logger);
  t = await createTestApp({ logger, prisma });
  await resetTables(t.prisma);
});

beforeEach(() => {
  consoleOut = [];
  const capture = (...args: unknown[]) => {
    consoleOut.push(args.map(String).join(' '));
  };
  for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, method).mockImplementation(capture);
  }
  for (const stream of [process.stdout, process.stderr]) {
    vi.spyOn(stream, 'write').mockImplementation((chunk: string | Uint8Array) => {
      consoleOut.push(String(chunk));
      return true;
    });
  }
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  await t.close();
  await prisma.$disconnect();
});

/** What a leak of file bytes would look like in a JSON log line: base64, base64url, hex, a Buffer's array. */
function byteVariants(bytes: Buffer): string[] {
  const head = bytes.subarray(0, 48);
  return [
    head.toString('base64'),
    head.toString('base64url'),
    head.toString('hex'),
    head.subarray(0, 16).join(','),
  ];
}

/** Runs `flow` and returns the pino output it produced (plus the console output of the test). */
async function logsOf(flow: () => Promise<void>): Promise<{ output: string; console: string }> {
  const from = lines.length;
  await flow();
  return { output: lines.slice(from).join(''), console: consoleOut.join('') };
}

function expectNoSecrets(logs: { output: string; console: string }, secrets: string[]): void {
  for (const s of secrets) {
    expect(s.length).toBeGreaterThan(5);
    const hint = `(${s.slice(0, 4)}...)`;
    expect(logs.output.includes(s), `log output contains a secret ${hint}`).toBe(false);
    expect(logs.console.includes(s), `console output contains a secret ${hint}`).toBe(false);
  }
  expect(logs.output).not.toMatch(/"(authorization|cookie|x-owner-token)"\s*:\s*"[^[]/i);
}

const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });
const accessToken = (header: string) => header.replace(/^Bearer /, '');

describe('drop logging', () => {
  it('create, chunk PUT and GET, complete, open, unlock, delete, report and admin review log no secret', async () => {
    const secrets: string[] = [];
    const keep = (drop: ReadyDrop, manifest: string) => {
      secrets.push(drop.ownerToken, drop.uploadToken, manifest);
      for (const chunks of drop.chunks.values()) {
        for (const c of chunks) secrets.push(...byteVariants(c));
      }
    };

    const logs = await logsOf(async () => {
      // An anonymous drop: create, chunk PUTs, complete (createReadyDrop), then meta, open and a chunk GET.
      const anonManifest = fakeManifest();
      const anon = await createReadyDrop(t.app, {
        files: [testFile(3000)],
        body: { encryptedManifest: anonManifest },
      });
      keep(anon, anonManifest);
      expect((await request(t.app).get(`/api/drops/${anon.dropId}`)).status).toBe(200);
      const opened = await openDrop(t.app, anon.dropId);
      expect(opened.status).toBe(200);
      secrets.push(opened.body.downloadToken as string);
      const file = anon.files[0]!;
      const got = await getChunk(t.app, anon.dropId, opened.body.downloadToken, file.id, 0);
      expect(got.status).toBe(200);

      // A signed-in owner's drop with its owner-wrapped key, deleted with the session.
      const user = await createUserRecord(t.prisma);
      const userAuth = authHeader(user);
      secrets.push(accessToken(userAuth));
      const ownerWrappedKey = fakeWrappedKey();
      const ownedManifest = fakeManifest();
      secrets.push(ownerWrappedKey);
      const owned = await createReadyDrop(t.app, {
        body: { ownerWrappedKey, encryptedManifest: ownedManifest },
        headers: { Authorization: userAuth },
      });
      keep(owned, ownedManifest);
      const delOwned = await request(t.app)
        .delete(`/api/drops/${owned.dropId}`)
        .set('Authorization', userAuth);
      expect(delOwned.status).toBe(204);

      // A password drop: a wrong proof (401), a malformed one (400), the right one, then open with it.
      const pw = passwordFixture();
      secrets.push(pw.authKey, pw.password.wrappedDropKey, pw.password.authKeyHash);
      const pwManifest = fakeManifest();
      const locked = await createReadyDrop(t.app, {
        body: { password: pw.password, encryptedManifest: pwManifest },
      });
      keep(locked, pwManifest);
      const wrongKey = token32();
      const malformedKey = randomBytes(30).toString('base64url');
      secrets.push(wrongKey, malformedKey);
      const unlockPath = `/api/drops/${locked.dropId}/unlock`;
      expect((await request(t.app).post(unlockPath).send({ authKey: wrongKey })).status).toBe(401);
      expect((await request(t.app).post(unlockPath).send({ authKey: malformedKey })).status).toBe(
        400,
      );
      expect((await request(t.app).post(unlockPath).send({ authKey: pw.authKey })).status).toBe(
        200,
      );
      const pwOpen = await openDrop(t.app, locked.dropId, { authKey: pw.authKey });
      expect(pwOpen.status).toBe(200);
      secrets.push(pwOpen.body.downloadToken as string);

      // A drop still uploading: its upload status, and a chunk PUT whose X-Chunk-SHA256 does not match (400).
      const pendingFiles = [testFile(800)];
      const pendingBody = createBody(pendingFiles);
      const pending = await createDropOk(t.app, pendingBody);
      secrets.push(
        pending.ownerToken,
        pending.uploadToken,
        pendingBody.encryptedManifest as string,
      );
      const data = chunkData(pendingFiles[0]!, 0);
      secrets.push(...byteVariants(data));
      const badSha = await putChunk(
        t.app,
        pending.dropId,
        pending.uploadToken,
        pendingFiles[0]!.id,
        0,
        data,
        'a'.repeat(64),
      );
      expect(badSha.status).toBe(400);
      const status = await request(t.app)
        .get(`/api/drops/${pending.dropId}/upload-status`)
        .set(bearer(pending.uploadToken));
      expect(status.status).toBe(200);

      // A report WITH the opt-in decryption key, and one with a malformed key (400).
      const decryptionKey = randomBytes(32).toString('base64url');
      const details = 'it contains the payroll export of march';
      const badReportKey = randomBytes(33).toString('base64url');
      secrets.push(decryptionKey, details, badReportKey);
      const reportPath = `/api/drops/${anon.dropId}/report`;
      const reported = await request(t.app)
        .post(reportPath)
        .send({ reason: 'MALWARE', details, decryptionKey });
      expect(reported.status).toBe(201);
      expect(
        (
          await request(t.app)
            .post(reportPath)
            .send({ reason: 'MALWARE', decryptionKey: badReportKey })
        ).status,
      ).toBe(400);

      // Admin review: the report list (which returns the key), a review grant, a chunk GET, dismiss.
      const admin = await createAdminRecord(t.prisma);
      const adminAuth = authHeader(admin);
      secrets.push(accessToken(adminAuth));
      const list = await request(t.app).get('/api/admin/reports').set('Authorization', adminAuth);
      expect(list.status).toBe(200);
      expect(JSON.stringify(list.body)).toContain(decryptionKey);
      const grant = await request(t.app)
        .post(`/api/admin/drops/${anon.dropId}/grant`)
        .set('Authorization', adminAuth);
      expect(grant.status).toBe(200);
      secrets.push(grant.body.downloadToken as string);
      const reviewed = await getChunk(t.app, anon.dropId, grant.body.downloadToken, file.id, 0);
      expect(reviewed.status).toBe(200);
      const resolved = await request(t.app)
        .post(`/api/admin/reports/${reported.body.id as string}/resolve`)
        .set('Authorization', adminAuth)
        .send({ action: 'DISMISS' });
      expect(resolved.status).toBe(204);

      // Owner delete with the owner token: first a wrong token (403), then the right one.
      const wrongOwner = token32();
      secrets.push(wrongOwner);
      const delPath = `/api/drops/${anon.dropId}`;
      expect((await request(t.app).delete(delPath).set('x-owner-token', wrongOwner)).status).toBe(
        403,
      );
      expect(
        (await request(t.app).delete(delPath).set('x-owner-token', anon.ownerToken)).status,
      ).toBe(204);
    });

    // The flows were logged (paths and status codes only), just without their secrets.
    expect(logs.output).toContain(`"path":"/api/drops"`);
    expect(logs.output).toContain('/report"');
    expect(logs.output).toContain('"statusCode":401');
    expect(logs.output).toContain('"statusCode":403');
    expectNoSecrets(logs, secrets);
  });

  it('a storage failure on chunk PUT (500) logs the error, not the token or the bytes', async () => {
    const files = [testFile(1200)];
    const body = createBody(files);
    const drop = await createDropOk(t.app, body);
    const data = chunkData(files[0]!, 0);
    vi.spyOn(t.storage, 'putChunk').mockRejectedValueOnce(
      Object.assign(new Error('EIO: i/o error, write'), { code: 'EIO' }),
    );
    const logs = await logsOf(async () => {
      const res = await putChunk(t.app, drop.dropId, drop.uploadToken, files[0]!.id, 0, data);
      expect(res.status).toBe(500);
    });
    expect(logs.output).toContain('"msg":"request failed"');
    expect(logs.output).toContain('EIO: i/o error, write');
    expectNoSecrets(logs, [
      drop.ownerToken,
      drop.uploadToken,
      body.encryptedManifest as string,
      ...byteVariants(data),
    ]);
  });

  it('a Prisma error while storing a report with its key (500) logs safe fields, never the key', async () => {
    const drop = await createReadyDrop(t.app);
    const realCreate = t.prisma.report.create.bind(t.prisma.report);
    const create = vi.spyOn(t.prisma.report, 'create');
    const keys = [randomBytes(32).toString('base64url'), randomBytes(32).toString('base64url')];
    const logs = await logsOf(async () => {
      // A bug that makes Prisma reject the arguments: Prisma renders them, the key included, into the
      // message and stack of a PrismaClientValidationError (and into its own error log).
      create.mockImplementationOnce(((args: { data: object }) =>
        realCreate({ ...args, data: { ...args.data, reason: 'NOT_A_REASON' } } as never)) as never);
      // The drop row vanishing between the check and the insert: a foreign key error (P2003).
      create.mockImplementationOnce(((args: { data: object }) =>
        realCreate({ ...args, data: { ...args.data, dropId: 'no-such-drop' } } as never)) as never);
      for (const decryptionKey of keys) {
        const res = await request(t.app)
          .post(`/api/drops/${drop.dropId}/report`)
          .send({ reason: 'MALWARE', decryptionKey });
        expect(res.status).toBe(500);
        expect(JSON.stringify(res.body)).not.toContain(decryptionKey);
      }
    });
    expect(create).toHaveBeenCalledTimes(2);
    expectNoSecrets(logs, [...keys, drop.ownerToken, drop.uploadToken]);
    // Useful, safe fields: the error class, the Prisma code, the failed call and the stack frames.
    expect(logs.output).toContain('"type":"PrismaClientValidationError"');
    expect(logs.output).toContain('"prismaCode":"P2003"');
    expect(logs.output).toContain('"target":"report.create"');
    expect(logs.output).toMatch(/at reportDrop \(/);
  });
});
