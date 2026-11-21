/**
 * Operator CLI (ops-9): every command against the test database, audited as the operator.
 */
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../test/app';
import { resetTables } from '../../test/db';
import { createAdminRecord, createUserRecord } from '../../test/factories';
import { bearer, loginViaApi, newSession, registerViaApi } from '../modules/auth/testkit';
import { createReadyDrop } from '../modules/drops/test-utils';
import { CLI_HELP, runCli } from './commands';

describe('operator CLI', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await resetTables(t.prisma);
  });

  async function cli(...argv: string[]) {
    const lines: string[] = [];
    const code = await runCli(t.ctx, argv, (l) => lines.push(l));
    return { code, out: lines.join('\n') };
  }

  const operatorEvents = (action: string) =>
    t.prisma.auditEvent.findMany({ where: { action: action as never, actorId: null } });

  it('prints the help with the compose exec form', async () => {
    const res = await cli('help');
    expect(res.code).toBe(0);
    expect(res.out).toBe(CLI_HELP);
    expect(res.out).toContain(
      'docker compose -f docker-compose.prod.yml exec api node dist/cli.js',
    );
    expect((await cli()).code).toBe(2);
    expect((await cli('nope')).code).toBe(2);
  });

  it('promotes only an existing account with two-step verification, and demotes', async () => {
    const without = await createUserRecord(t.prisma);
    const refused = await cli('admin:promote', without.email);
    expect(refused.code).toBe(1);
    expect(refused.out).toMatch(/two-step verification/);
    expect((await cli('admin:promote', 'nobody@example.com')).code).toBe(2);

    const user = await createUserRecord(t.prisma, { totpEnabledAt: new Date() });
    const ok = await cli('admin:promote', user.email.toUpperCase());
    expect(ok).toEqual({ code: 0, out: `${user.email} is now an admin` });
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } })).role).toBe('ADMIN');
    const [ev] = await operatorEvents('ADMIN_USER_UPDATED');
    expect(ev?.metadata).toMatchObject({
      operator: true,
      targetUserId: user.id,
      role: { from: 'USER', to: 'ADMIN' },
    });

    expect((await cli('admin:demote', user.email)).code).toBe(0);
    expect((await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } })).role).toBe('USER');
  });

  it('suspends (signing out every session) and unsuspends', async () => {
    const u = await registerViaApi(t.app);
    const s = await newSession(t.app, u);
    expect((await cli('user:suspend', u.email)).code).toBe(2); // --reason is required
    expect((await cli('user:suspend', u.email, '--reason', 'Spam wave')).code).toBe(0);
    expect(
      (await request(t.app).get('/api/me').set('Authorization', bearer(s.accessToken))).status,
    ).toBe(401);
    expect((await loginViaApi(t.app, u.email, u.password)).status).toBe(403);
    expect((await operatorEvents('ADMIN_USER_SUSPENDED'))[0]?.metadata).toMatchObject({
      operator: true,
      reason: 'Spam wave',
    });
    expect((await cli('user:unsuspend', u.email)).code).toBe(0);
    expect((await loginViaApi(t.app, u.email, u.password)).status).toBe(200);
  });

  it('takes a drop down by id with a reason', async () => {
    const drop = await createReadyDrop(t.app);
    expect((await cli('drop:disable', drop.dropId, '--reason', 'Notice 9')).code).toBe(0);
    expect((await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } })).status).toBe(
      'DISABLED',
    );
    expect((await operatorEvents('ADMIN_DROP_DISABLED'))[0]?.metadata).toMatchObject({
      operator: true,
      reason: 'Notice 9',
    });
    expect((await cli('drop:disable', drop.dropId, '--reason', 'again')).code).toBe(1);
  });

  it('revokes every session of one account, or of all accounts', async () => {
    const a = await registerViaApi(t.app);
    const b = await registerViaApi(t.app);
    const sa = await newSession(t.app, a);
    const sb = await newSession(t.app, b);
    const me = (token: string) => request(t.app).get('/api/me').set('Authorization', bearer(token));

    expect((await cli('sessions:revoke')).code).toBe(2);
    expect((await cli('sessions:revoke', a.email)).out).toBe('Signed out 2 sessions');
    expect((await me(sa.accessToken)).status).toBe(401);
    expect((await me(sb.accessToken)).status).toBe(200);
    expect((await cli('sessions:revoke', '--all')).out).toBe('Signed out 2 sessions');
    expect((await me(sb.accessToken)).status).toBe(401);
    expect((await operatorEvents('ADMIN_SESSIONS_REVOKED')).map((e) => e.metadata)).toEqual(
      expect.arrayContaining([expect.objectContaining({ allUsers: true, revokedSessions: 2 })]),
    );
  });

  it('prints the audit tail, oldest first, with admins and the operator named', async () => {
    const admin = await createAdminRecord(t.prisma);
    const user = await createUserRecord(t.prisma);
    await t.prisma.auditEvent.create({
      data: {
        action: 'ADMIN_USER_UPDATED',
        actorId: admin.id,
        metadata: { targetUserId: user.id },
        createdAt: new Date('2026-01-02T09:00:00Z'),
      },
    });
    await cli('user:suspend', user.email, '--reason', 'r1');
    const res = await cli('audit:tail', '--limit', '5');
    expect(res.code).toBe(0);
    const lines = res.out.split('\n');
    expect(lines[0]).toBe(
      `2026-01-02T09:00:00.000Z ADMIN_USER_UPDATED by=${admin.email} account=${user.email} drop=-`,
    );
    expect(lines[1]).toMatch(/ADMIN_USER_SUSPENDED by=operator .* reason="r1"$/);
    expect(lines[2]).toBe('(2 of 2 events)');
    expect((await cli('audit:tail', '--limit', '0')).code).toBe(2);
  });
});
