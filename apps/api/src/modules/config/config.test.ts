/**
 * ops-3 operator switches: ALLOW_ANONYMOUS_UPLOADS and ALLOW_REGISTRATION, and GET /api/config, which tells
 * the SPA about them.
 */
import { FeatureDisabledDetailsSchema, PublicConfigSchema } from '@cipherdrop/shared';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createUserRecord, TEST_ACCOUNT, uniqueEmail } from '../../../test/factories';
import {
  chunkData,
  complete,
  createBody,
  createDropOk,
  fakeWrappedKey,
  postDrop,
  putChunk,
  testFile,
} from '../drops/test-utils';

const registerBody = () => ({
  email: uniqueEmail('switch'),
  authKey: TEST_ACCOUNT.authKey,
  kdf: TEST_ACCOUNT.kdf,
  wrappedAccountKey: TEST_ACCOUNT.wrappedAccountKey,
  wrappedAccountKeyRecovery: TEST_ACCOUNT.wrappedAccountKeyRecovery,
  recoveryAuthHash: TEST_ACCOUNT.recoveryAuthHash,
});

describe('GET /api/config', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });

  it('is public, uncached and reports both switches on by default', async () => {
    const res = await request(t.app).get('/api/config');
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(PublicConfigSchema.strict().parse(res.body)).toEqual({
      anonymousUploads: true,
      registration: true,
    });
  });

  it('is in the OpenAPI document with its schema', async () => {
    const doc = (await request(t.app).get('/api/openapi.json')).body;
    const get = doc.paths['/api/config']?.get;
    expect(get).toBeDefined();
    expect(JSON.stringify(get.responses['200'])).toContain('anonymousUploads');
  });
});

describe('ALLOW_ANONYMOUS_UPLOADS=false', () => {
  let open: TestApp;
  let closed: TestApp;
  beforeAll(async () => {
    open = await createTestApp();
    closed = await createTestApp({
      env: { ALLOW_ANONYMOUS_UPLOADS: false },
      rateLimits: { createDropAnon: true },
    });
    await resetTables(closed.prisma);
  });
  afterAll(async () => {
    await resetTables(closed.prisma);
    await closed.close();
    await open.close();
  });

  it('GET /api/config says so', async () => {
    expect((await request(closed.app).get('/api/config')).body).toEqual({
      anonymousUploads: false,
      registration: true,
    });
  });

  it('refuses an anonymous create with 403 FEATURE_DISABLED before the limiter counts it', async () => {
    for (let i = 0; i < 12; i++) {
      const res = await postDrop(closed.app, createBody([testFile(10)]), {
        'X-Forwarded-For': '198.51.100.30',
      });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FEATURE_DISABLED');
      expect(FeatureDisabledDetailsSchema.parse(res.body.error.details)).toEqual({
        feature: 'anonymousUploads',
      });
    }
    expect(await closed.prisma.drop.count({ where: { ownerId: null } })).toBe(0);
  });

  it('still accepts signed-in senders', async () => {
    const user = await createUserRecord(closed.prisma);
    const res = await postDrop(
      closed.app,
      createBody([testFile(10)], { ownerWrappedKey: fakeWrappedKey() }),
      { Authorization: authHeader(user) },
    );
    expect(res.status).toBe(201);
  });

  it('lets an anonymous drop created before the switch finish its upload', async () => {
    const f = testFile(10);
    const drop = await createDropOk(open.app, createBody([f]));
    const put = await putChunk(closed.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0));
    expect(put.status).toBe(204);
    expect((await complete(closed.app, drop)).status).toBe(200);
  });
});

describe('ALLOW_REGISTRATION=false', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp({ env: { ALLOW_REGISTRATION: false }, rateLimits: { register: true } });
  });
  afterAll(async () => {
    await resetTables(t.prisma);
    await t.close();
  });

  it('GET /api/config says so', async () => {
    expect((await request(t.app).get('/api/config')).body).toEqual({
      anonymousUploads: true,
      registration: false,
    });
  });

  it('refuses POST /auth/register with 403 FEATURE_DISABLED and creates nothing', async () => {
    for (let i = 0; i < 7; i++) {
      const body = registerBody();
      const res = await request(t.app)
        .post('/api/auth/register')
        .set('X-Forwarded-For', '198.51.100.31')
        .send(body);
      expect(res.status).toBe(403);
      expect(res.body.error).toMatchObject({
        code: 'FEATURE_DISABLED',
        details: { feature: 'registration' },
      });
      expect(await t.prisma.user.count({ where: { email: body.email } })).toBe(0);
    }
  });

  it('existing accounts still sign in', async () => {
    const user = await createUserRecord(t.prisma);
    const res = await request(t.app)
      .post('/api/auth/login')
      .send({ email: user.email, authKey: TEST_ACCOUNT.authKey });
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toEqual(expect.any(String));
  });
});
