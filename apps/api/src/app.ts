/**
 * createApp(deps?) builds the Express 5 app (S4). Lanes never edit this file; they own their routes.ts.
 *
 * Order: requestId -> pino-http -> helmet -> CORS(WEB_ORIGIN) -> no-store on /api -> metrics ->
 * /healthz /readyz /metrics -> global limiter on /api (600/min per IP; chunk PUT/GET exempt) ->
 * cookies -> JSON (1 MB) -> /api/openapi.json + /api/docs -> /api/auth, /api/me (B1), /api/drops,
 * /api/admin (B2) -> 404 -> error handler.
 */
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { type Express } from 'express';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';
import { createContext, type AppDeps } from './context';
import { ipKey } from './lib/ip';
import { createHttpLogger } from './lib/logger';
import { metricsMiddleware } from './lib/metrics';
import type { AppRouter } from './lib/router';
import { errorHandler, notFoundHandler } from './middleware/error';
import { noStore } from './middleware/noStore';
import { requestId } from './middleware/requestId';
import { adminRoutes } from './modules/admin/routes';
import { authRoutes } from './modules/auth/routes';
import { dropsRoutes } from './modules/drops/routes';
import { healthRoutes } from './modules/health/routes';
import { meRoutes } from './modules/me/routes';
import { getOpenApiDocument } from './openapi/document';

/** Chunk transfer routes (relative to /api): limited per token instead of per IP (R10). */
const CHUNK_PATH_RE = /^\/drops\/[^/]+\/files\/[^/]+\/chunks\/[^/]+\/?$/;

function mount(app: Express, r: AppRouter): void {
  if (r.basePath) app.use(r.basePath, r.router);
  else app.use(r.router);
}

export function createApp(deps: AppDeps = {}): Express {
  const ctx = createContext(deps);
  const app = express();
  app.locals.ctx = ctx;

  app.disable('x-powered-by');
  app.set('trust proxy', ctx.env.TRUST_PROXY);
  // BigInt columns are serialised as JSON numbers (all values stay below 2^53).
  app.set('json replacer', (_key: string, value: unknown) =>
    typeof value === 'bigint' ? Number(value) : value,
  );

  app.use(requestId);
  app.use(createHttpLogger(ctx.logger));
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          // Swagger UI over plain-http localhost must not be upgraded to https in development.
          upgradeInsecureRequests: ctx.env.NODE_ENV === 'production' ? [] : null,
        },
      },
    }),
  );
  app.use(
    cors({
      origin: ctx.env.WEB_ORIGIN,
      credentials: true,
      exposedHeaders: ['Retry-After', 'X-Request-Id', 'RateLimit', 'RateLimit-Policy'],
      maxAge: 600,
    }),
  );
  app.use('/api', noStore);
  app.use(metricsMiddleware);

  mount(app, healthRoutes(ctx));

  app.use(
    '/api',
    ctx.rateLimit({
      name: 'global',
      key: (req) => ipKey(req.ip),
      skip: (req) => (req.method === 'PUT' || req.method === 'GET') && CHUNK_PATH_RE.test(req.path),
    }),
  );
  app.use(cookieParser());
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/openapi.json', (_req, res) => {
    res.json(getOpenApiDocument());
  });
  app.use(
    '/api/docs',
    swaggerUi.serve,
    swaggerUi.setup(undefined, {
      swaggerUrl: '/api/openapi.json',
      customSiteTitle: 'CipherDrop API',
    }),
  );

  for (const r of [authRoutes(ctx), meRoutes(ctx), dropsRoutes(ctx), adminRoutes(ctx)]) {
    mount(app, r);
  }

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
