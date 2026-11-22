/**
 * Per-grant byte budget (critic-2): one consumed download serves at most DOWNLOAD_GRANT_BYTE_FACTOR times the drop's
 * ciphertext size, so a published token cannot be replayed without limit for 24 h, while resumes and retries fit.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { createAdminRecord, steppedUpAuthHeader } from '../../../test/factories';
import request from 'supertest';
import { GRANT_BUDGET_SPENT_MESSAGE } from './service';
import { createReadyDrop, getChunk, openDrop, testFile } from './test-utils';

describe('download grant byte budget (critic-2)', () => {
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp({ env: { DOWNLOAD_GRANT_BYTE_FACTOR: 2 } });
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await t.close();
  });

  it('serves a resume and a retry, then refuses the grant once it has served 2x the drop', async () => {
    // Two chunks: the budget is 2 x (chunk 0 + chunk 1).
    const file = testFile(5 * 1024 * 1024);
    expect(file.chunkSizes).toHaveLength(2);
    const drop = await createReadyDrop(t.app, { files: [file], body: { maxDownloads: 5 } });
    const opened = await openDrop(t.app, drop.dropId);
    expect(opened.status).toBe(200);
    const token = opened.body.downloadToken as string;
    const get = (index: number) => getChunk(t.app, drop.dropId, token, file.id, index);

    // A first try that fails after chunk 0, then a full download, then chunk 0 again: 2 x chunk 0 + chunk 1 ...
    expect((await get(0)).status).toBe(200);
    expect((await get(0)).status).toBe(200);
    expect((await get(1)).status).toBe(200);
    // ... and chunk 1 once more reaches exactly 2x: still served.
    expect((await get(1)).status).toBe(200);
    const grant = await t.prisma.downloadGrant.findFirstOrThrow({ where: { dropId: drop.dropId } });
    expect(grant.servedBytes).toBe(BigInt(2 * (file.chunkSizes[0]! + file.chunkSizes[1]!)));

    // Past the budget the grant is spent; nothing is charged for the refusal.
    const spent = await get(1);
    expect(spent.status).toBe(401);
    expect(JSON.parse(spent.body.toString()).error.message).toBe(GRANT_BUDGET_SPENT_MESSAGE);
    const after = await t.prisma.downloadGrant.findUniqueOrThrow({ where: { id: grant.id } });
    expect(after.servedBytes).toBe(grant.servedBytes);

    // A new open (another download of the drop) gets a fresh budget.
    const again = await openDrop(t.app, drop.dropId);
    expect(again.status).toBe(200);
    expect((await getChunk(t.app, drop.dropId, again.body.downloadToken, file.id, 1)).status).toBe(
      200,
    );
  });

  it('applies to admin review grants too', async () => {
    const file = testFile(1000);
    const drop = await createReadyDrop(t.app, { files: [file] });
    const admin = await createAdminRecord(t.prisma);
    const grant = await request(t.app)
      .post(`/api/admin/drops/${drop.dropId}/grant`)
      .set('Authorization', await steppedUpAuthHeader(t.prisma, admin));
    expect(grant.status).toBe(200);
    const get = () => getChunk(t.app, drop.dropId, grant.body.downloadToken, file.id, 0);
    expect((await get()).status).toBe(200);
    expect((await get()).status).toBe(200);
    expect((await get()).status).toBe(401);
  });
});
