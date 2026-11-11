import { ErrorBodySchema, EmailSchema } from '@cipherdrop/shared';
import express from 'express';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { createTestApp, type TestApp } from '../test/app';
import { ipPrefix } from './lib/ip';
import { signAccessToken } from './lib/jwt';
import { denylistSid } from './lib/redis';
import { createRouter, routeManifest } from './lib/router';
import { requireAuth } from './middleware/auth';
import { errorHandler } from './middleware/error';

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp();
});

afterAll(async () => {
  await t.close();
});

/** A tiny app that shares the test context, for exercising S4 middleware in isolation. */
function miniApp(mount: (app: express.Express) => void): express.Express {
  const app = express();
  app.locals.ctx = t.ctx;
  app.use(express.json());
  mount(app);
  app.use(errorHandler);
  return app;
}

/* Minimal views of Express 5's router internals (router@2): enough to walk the real route table. */
interface StackLayer {
  route?: { path: string; methods: Record<string, boolean> };
  handle?: { stack?: StackLayer[] };
  matchers?: ((path: string) => unknown)[];
}

/** Every "METHOD /full/path" actually mounted on `app` (walks app.router.stack, not routeManifest). */
function mountedRoutes(app: express.Express): string[] {
  const root = (app as unknown as { router: { stack: StackLayer[] } }).router.stack;
  // Mount paths are not stored on a Layer: find the shortest segment prefix of a known path that it matches.
  const prefixes = new Set<string>(['']);
  for (const entry of routeManifest) {
    const parts = entry.path.split('/').filter(Boolean);
    for (let i = 1; i <= parts.length; i++) prefixes.add(`/${parts.slice(0, i).join('/')}`);
  }
  const candidates = [...prefixes].sort((a, b) => a.length - b.length);
  const out: string[] = [];
  const walk = (stack: StackLayer[], base: string): void => {
    for (const layer of stack) {
      if (layer.route) {
        const full = layer.route.path === '/' ? base || '/' : `${base}${layer.route.path}`;
        for (const m of Object.keys(layer.route.methods)) out.push(`${m.toUpperCase()} ${full}`);
      } else if (layer.handle?.stack) {
        const mount = candidates.find((c) => layer.matchers?.some((m) => m(c || '/')));
        walk(layer.handle.stack, mount ?? base);
      }
    }
  };
  walk(root, '');
  return out;
}

/** Mounted routes that are missing from routeManifest or from the OpenAPI document. */
function undocumentedRoutes(
  app: express.Express,
  paths: Record<string, Record<string, unknown>>,
): string[] {
  const manifest = new Map(
    routeManifest.map((e) => [`${e.method.toUpperCase()} ${e.path}`, e.openApiPath]),
  );
  return mountedRoutes(app).filter((key) => {
    const openApiPath = manifest.get(key);
    const method = key.split(' ')[0]?.toLowerCase() ?? '';
    return openApiPath === undefined || paths[openApiPath]?.[method] === undefined;
  });
}

describe('S4 app skeleton', () => {
  it('GET /healthz 200', async () => {
    const res = await request(t.app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('404 shape', async () => {
    const res = await request(t.app).get('/api/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: { code: 'NOT_FOUND', message: expect.any(String) } });
    expect(ErrorBodySchema.safeParse(res.body).success).toBe(true);
  });

  it('VALIDATION_ERROR shape', async () => {
    const { router, route } = createRouter('/api/__s4test');
    route(
      {
        method: 'post',
        path: '/echo/:n',
        summary: 'S4 test route',
        tags: ['test'],
        request: {
          params: z.object({ n: z.string().regex(/^\d+$/).transform(Number) }),
          body: z.object({ email: EmailSchema }),
        },
        responses: { 200: { description: 'echo' } },
      },
      (req, res) => {
        res.json({ n: req.validatedParams.n, email: req.body.email });
      },
    );
    const app = miniApp((a) => a.use('/api/__s4test', router));

    const ok = await request(app)
      .post('/api/__s4test/echo/7')
      .send({ email: ' Demo@Example.COM ' });
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ n: 7, email: 'demo@example.com' });

    const bad = await request(app).post('/api/__s4test/echo/x').send({ email: 'not-an-email' });
    expect(bad.status).toBe(400);
    expect(ErrorBodySchema.safeParse(bad.body).success).toBe(true);
    expect(bad.body.error.code).toBe('VALIDATION_ERROR');
    const paths = bad.body.error.details.issues.map((i: { path: string }) => i.path).sort();
    expect(paths).toEqual(['body.email', 'params.n']);

    // Malformed JSON on the real app is a VALIDATION_ERROR too (not a 500).
    const malformed = await request(t.app)
      .post('/api/auth/prelogin')
      .set('Content-Type', 'application/json')
      .send('{"email":');
    expect(malformed.status).toBe(400);
    expect(malformed.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('/api/openapi.json 200', async () => {
    const res = await request(t.app).get('/api/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toMatch(/^3\./);
    const paths = res.body.paths as Record<string, Record<string, unknown>>;
    for (const entry of routeManifest) {
      expect(
        paths[entry.openApiPath]?.[entry.method],
        `${entry.method} ${entry.openApiPath}`,
      ).toBeDefined();
    }
    // routeManifest and the registry are filled by the same route() call, so also walk the REAL router stack:
    // a route mounted any other way (bare router.get, app.get) would be missing from both.
    expect(mountedRoutes(t.app).length).toBeGreaterThanOrEqual(routeManifest.length);
    // /api/openapi.json is the one deliberate non-route() route (it serves the document itself).
    expect(undocumentedRoutes(t.app, paths)).toEqual(['GET /api/openapi.json']);
    // A sample of spec section 10 routes, including R9 and both chunk routes.
    expect(paths['/api/auth/prelogin']?.post).toBeDefined();
    expect(paths['/api/auth/recovery/rotate']?.post).toBeDefined();
    expect(paths['/api/me/drops']?.get).toBeDefined();
    expect(paths['/api/drops/{id}/files/{fileId}/chunks/{index}']?.put).toBeDefined();
    expect(paths['/api/drops/{id}/files/{fileId}/chunks/{index}']?.get).toBeDefined();
    expect(paths['/api/admin/drops/{id}/grant']?.post).toBeDefined();

    const docs = await request(t.app).get('/api/docs/');
    expect(docs.status).toBe(200);
    expect(docs.text).toContain('swagger');
  });

  it('the route-table walk flags a route mounted outside route()', async () => {
    const bare = express.Router();
    bare.get('/ping', (_req, res) => {
      res.json({ ok: true });
    });
    const app = miniApp((a) => a.use('/api/__bare', bare));
    const paths = (await request(t.app).get('/api/openapi.json')).body.paths;
    // (Its mount path is unknown to routeManifest, so only the tail is asserted.)
    expect(undocumentedRoutes(app, paths)).toEqual([expect.stringMatching(/^GET .*\/ping$/)]);
  });

  it('no-store header on /api routes', async () => {
    const paths = [
      '/api/openapi.json', // 200
      '/api/does-not-exist', // 404
      '/api/auth/vault', // 401 without a token
      '/api/docs/', // static Swagger UI (HTML)
      '/api/docs/swagger-ui.css', // static Swagger UI asset
    ];
    for (const path of paths) {
      const res = await request(t.app).get(path);
      expect(res.headers['cache-control'], path).toBe('no-store');
    }
    const auth = await request(t.app).get('/api/auth/vault');
    expect(auth.status).toBe(401);
  });

  it('denylisted sid -> 401', async () => {
    const app = miniApp((a) =>
      a.get('/api/__s4test/whoami', requireAuth, (req, res) => {
        res.json({ user: req.user });
      }),
    );
    const sid = `sid-${Date.now()}`;
    const token = signAccessToken({ id: 'user-s4', role: 'USER' }, sid);

    const before = await request(app)
      .get('/api/__s4test/whoami')
      .set('Authorization', `Bearer ${token}`);
    expect(before.status).toBe(200);
    expect(before.body.user).toEqual({ id: 'user-s4', role: 'USER', sid });

    await denylistSid(t.redis, sid);

    const after = await request(app)
      .get('/api/__s4test/whoami')
      .set('Authorization', `Bearer ${token}`);
    expect(after.status).toBe(401);
    expect(after.body.error.code).toBe('UNAUTHORIZED');

    // The real app rejects the denylisted token on a user route too, whatever the handler does.
    const real = await request(t.app).get('/api/me').set('Authorization', `Bearer ${token}`);
    expect(real.status).toBe(401);
    expect(real.body.error.code).toBe('UNAUTHORIZED');

    const missing = await request(app).get('/api/__s4test/whoami');
    expect(missing.status).toBe(401);
  });

  it('ipPrefix masks IPv4 /24 and IPv6 /48', () => {
    expect(ipPrefix('203.0.113.77')).toBe('203.0.113.0/24');
    expect(ipPrefix('::ffff:203.0.113.77')).toBe('203.0.113.0/24');
    expect(ipPrefix('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::/48');
    expect(ipPrefix('2001:0db8:0000:0042:0000:8a2e:0370:7334')).toBe('2001:db8::/48');
    expect(ipPrefix('::1')).toBe('::/48');
    expect(ipPrefix('fe80::1%eth0')).toBe('fe80::/48');
    expect(ipPrefix('not-an-ip')).toBeNull();
    expect(ipPrefix(undefined)).toBeNull();
  });
});
