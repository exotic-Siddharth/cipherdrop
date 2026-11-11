import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { createUserRecord } from '../../../test/factories';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp();
});

afterAll(async () => {
  await t.close();
});

describe('audit service', () => {
  it('record() stores the IP prefix and a UA summary, never the raw address or UA', async () => {
    const user = await createUserRecord(t.prisma);
    await t.ctx.audit.record({
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      req: {
        ip: '203.0.113.77',
        headers: {
          'user-agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
        },
      },
      metadata: { mfa: false },
    });
    const [event] = await t.prisma.auditEvent.findMany({ where: { userId: user.id } });
    expect(event?.ipPrefix).toBe('203.0.113.0/24');
    expect(event?.userAgent).not.toContain('Mozilla');
    expect(event?.metadata).toEqual({ mfa: false });
  });

  it('list() pages newest first, counts the total and filters by action, per user only', async () => {
    const user = await createUserRecord(t.prisma);
    const other = await createUserRecord(t.prisma);
    const base = Date.UTC(2026, 10, 1, 12, 0, 0);
    const actions = [
      'LOGIN_SUCCESS',
      'LOGIN_FAILURE',
      'LOGIN_SUCCESS',
      'PASSWORD_CHANGED',
    ] as const;
    for (const [i, action] of actions.entries()) {
      await t.prisma.auditEvent.create({
        data: { userId: user.id, action, createdAt: new Date(base + i * 1000) },
      });
    }
    await t.prisma.auditEvent.create({ data: { userId: other.id, action: 'LOGIN_SUCCESS' } });

    const first = await t.ctx.audit.list(user.id, { page: 1, pageSize: 3 });
    expect(first.total).toBe(4);
    expect(first.page).toBe(1);
    expect(first.pageSize).toBe(3);
    expect(first.items.map((e) => e.action)).toEqual([
      'PASSWORD_CHANGED',
      'LOGIN_SUCCESS',
      'LOGIN_FAILURE',
    ]);
    const second = await t.ctx.audit.list(user.id, { page: 2, pageSize: 3 });
    expect(second.items.map((e) => e.action)).toEqual(['LOGIN_SUCCESS']);
    expect(second.total).toBe(4);

    const filtered = await t.ctx.audit.list(user.id, {
      action: 'LOGIN_SUCCESS',
      page: 1,
      pageSize: 20,
    });
    expect(filtered.total).toBe(2);
    expect(filtered.items.every((e) => e.action === 'LOGIN_SUCCESS' && e.userId === user.id)).toBe(
      true,
    );

    const none = await t.ctx.audit.list(user.id, { action: 'MFA_ENABLED', page: 1, pageSize: 20 });
    expect(none).toEqual({ items: [], total: 0, page: 1, pageSize: 20 });
  });
});
