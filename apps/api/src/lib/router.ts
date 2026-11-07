/**
 * Route + OpenAPI helper (CipherDrop counterpart of the sibling plan's R12). ALL routes are registered through
 * `route()`, which in one call:
 *   1. registers the Express route: [auth middleware from def.auth] -> validate(def.request) -> ...handlers;
 *   2. registers the OpenAPI path (full path, `:param` -> `{param}`, security, common error responses);
 *   3. appends {method, path, openApiPath, auth, ...} to the exported `routeManifest`.
 * OpenAPI/manifest entries are de-duplicated by "METHOD /full/path", so calling a route factory once per
 * createApp() (tests create many apps) does not duplicate them.
 *
 *   const r = createRouter('/api/drops');
 *   r.route({ method: 'get', path: '/:id', summary: 'Drop metadata', tags: ['drops'],
 *             request: { params: DropIdParamsSchema }, responses: { 200: { description: 'ok', schema: DropMetaSchema } } },
 *           async (req, res) => { res.json(await getMeta(req.validatedParams.id)); });
 *   createApp() mounts r.router at r.basePath.
 *
 * def.auth: 'user' -> requireAuth; 'admin' -> requireAuth + requireRole('ADMIN'); 'optional' and 'owner' ->
 * optionalAuth; 'refreshCookie' | 'uploadToken' | 'downloadToken' | 'public' -> no middleware (the handler
 * checks the cookie/token itself; the value only documents the OpenAPI security scheme).
 */
import type { ResponseConfig, RouteConfig, ZodRequestBody } from '@asteasolutions/zod-to-openapi';
import {
  Router,
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
} from 'express';
import { z, type AnyZodObject, type ZodTypeAny } from 'zod';
import { optionalAuth, requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/requireRole';
import { validate } from '../middleware/validate';
import { ErrorBodyRef, markRegistryChanged, registry } from '../openapi/registry';

export type HttpMethod = 'get' | 'post' | 'put' | 'patch' | 'delete';

export type RouteAuth =
  | 'public'
  | 'optional'
  | 'user'
  | 'admin'
  | 'owner'
  | 'refreshCookie'
  | 'uploadToken'
  | 'downloadToken';

export interface RouteResponseDef {
  description: string;
  /** JSON body schema. Omit for empty responses (204) or binary bodies. */
  schema?: ZodTypeAny;
  /** Defaults to application/json when `schema` is set; e.g. 'application/octet-stream' for chunk GETs. */
  contentType?: string;
}

export interface RouteRequestDef<P, Q, B> {
  params?: P;
  query?: Q;
  /** JSON body (express.json is mounted globally, limit 1 MB). */
  body?: B;
  /** Non-JSON body, documentation only: the handler parses it itself (e.g. express.raw AFTER checking the token). */
  rawBody?: { contentType: string; description?: string };
  /** Documented request headers (not validated). */
  headers?: AnyZodObject;
}

export interface RouteDef<
  P extends AnyZodObject | undefined = undefined,
  Q extends AnyZodObject | undefined = undefined,
  B extends ZodTypeAny | undefined = undefined,
> {
  method: HttpMethod;
  /** Express path relative to the router's basePath, e.g. '/', '/:id', '/:id/files/:fileId/chunks/:index'. */
  path: string;
  summary: string;
  description?: string;
  tags: string[];
  auth?: RouteAuth;
  request?: RouteRequestDef<P, Q, B>;
  responses: Record<number, RouteResponseDef>;
}

type Infer<T, Fallback> = T extends ZodTypeAny ? z.output<T> : Fallback;

/** The Express request as seen by route handlers: body/validatedParams/validatedQuery are the parsed values. */
export type RouteRequest<P, Q, B> = Request<Record<string, string>, unknown, B> & {
  validatedParams: P;
  validatedQuery: Q;
};

export type RouteHandler<P = Record<string, string>, Q = Record<string, unknown>, B = unknown> = (
  req: RouteRequest<P, Q, B>,
  res: Response,
  next: NextFunction,
) => unknown;

export interface RouteManifestEntry {
  method: HttpMethod;
  /** Full Express path, e.g. /api/drops/:id */
  path: string;
  /** OpenAPI path, e.g. /api/drops/{id} */
  openApiPath: string;
  auth: RouteAuth;
  tags: string[];
  summary: string;
}

/** Every route registered in this process (de-duplicated). I1 checks it against the OpenAPI document and spec section 10. */
export const routeManifest: RouteManifestEntry[] = [];
const registeredKeys = new Set<string>();

export interface AppRouter {
  basePath: string;
  router: Router;
  route: <
    P extends AnyZodObject | undefined = undefined,
    Q extends AnyZodObject | undefined = undefined,
    B extends ZodTypeAny | undefined = undefined,
  >(
    def: RouteDef<P, Q, B>,
    ...handlers: RouteHandler<
      Infer<P, Record<string, string>>,
      Infer<Q, Record<string, unknown>>,
      Infer<B, unknown>
    >[]
  ) => void;
}

const PARAM_RE = /:([A-Za-z_][A-Za-z0-9_]*)/g;

const AUTH_MIDDLEWARE: Record<RouteAuth, RequestHandler[]> = {
  public: [],
  optional: [optionalAuth],
  owner: [optionalAuth],
  user: [requireAuth],
  admin: [requireAuth, requireRole('ADMIN')],
  refreshCookie: [],
  uploadToken: [],
  downloadToken: [],
};

const SECURITY: Record<RouteAuth, RouteConfig['security']> = {
  public: undefined,
  optional: [{}, { bearerAuth: [] }],
  owner: [{ ownerToken: [] }, { bearerAuth: [] }],
  user: [{ bearerAuth: [] }],
  admin: [{ bearerAuth: [] }],
  refreshCookie: [{ refreshCookie: [] }],
  uploadToken: [{ uploadToken: [] }],
  downloadToken: [{ downloadToken: [] }],
};

const errorResponse = (description: string): ResponseConfig => ({
  description,
  content: { 'application/json': { schema: ErrorBodyRef } },
});

const binary = { type: 'string', format: 'binary' } as const;

function toOpenApiPath(fullPath: string): string {
  return fullPath.replace(PARAM_RE, '{$1}');
}

function buildRouteConfig(
  def: RouteDef<AnyZodObject | undefined, AnyZodObject | undefined, ZodTypeAny | undefined>,
  fullPath: string,
  openApiPath: string,
): RouteConfig {
  const auth = def.auth ?? 'public';
  const paramNames = [...fullPath.matchAll(PARAM_RE)].map((m) => m[1] as string);
  const params =
    def.request?.params ??
    (paramNames.length > 0
      ? z.object(Object.fromEntries(paramNames.map((name) => [name, z.string()])))
      : undefined);

  let body: ZodRequestBody | undefined;
  if (def.request?.body) {
    body = { content: { 'application/json': { schema: def.request.body } }, required: true };
  } else if (def.request?.rawBody) {
    body = {
      description: def.request.rawBody.description,
      content: { [def.request.rawBody.contentType]: { schema: binary } },
      required: true,
    };
  }

  const responses: Record<string, ResponseConfig> = {};
  for (const [status, r] of Object.entries(def.responses)) {
    if (r.schema) {
      responses[status] = {
        description: r.description,
        content: { [r.contentType ?? 'application/json']: { schema: r.schema } },
      };
    } else if (r.contentType) {
      responses[status] = {
        description: r.description,
        content: { [r.contentType]: { schema: binary } },
      };
    } else {
      responses[status] = { description: r.description };
    }
  }
  const hasInput = Boolean(def.request?.params || def.request?.query || def.request?.body);
  if (hasInput && !responses['400'])
    responses['400'] = errorResponse('Validation error (VALIDATION_ERROR)');
  if (auth !== 'public' && auth !== 'optional' && !responses['401']) {
    responses['401'] = errorResponse('Missing, invalid or revoked credentials (UNAUTHORIZED)');
  }
  if (auth === 'admin' && !responses['403'])
    responses['403'] = errorResponse('Not an admin (FORBIDDEN)');
  if (fullPath.startsWith('/api/') && !responses['429']) {
    responses['429'] = errorResponse('Rate limited (RATE_LIMITED, Retry-After)');
  }

  return {
    method: def.method,
    path: openApiPath,
    summary: def.summary,
    description: def.description,
    tags: def.tags,
    security: SECURITY[auth],
    request: {
      ...(params ? { params } : {}),
      ...(def.request?.query ? { query: def.request.query } : {}),
      ...(def.request?.headers ? { headers: def.request.headers } : {}),
      ...(body ? { body } : {}),
    },
    responses,
  };
}

/** Create a module router mounted (by createApp) at `basePath` ('' for root-level routes such as /healthz). */
export function createRouter(basePath: string): AppRouter {
  const router = Router();

  const route: AppRouter['route'] = (def, ...handlers) => {
    const fullPath = `${basePath}${def.path === '/' ? '' : def.path}` || '/';
    const openApiPath = toOpenApiPath(fullPath);
    const auth = def.auth ?? 'public';

    const chain: RequestHandler[] = [
      ...AUTH_MIDDLEWARE[auth],
      validate({ params: def.request?.params, query: def.request?.query, body: def.request?.body }),
      ...(handlers as unknown as RequestHandler[]),
    ];
    router[def.method](def.path, ...chain);

    const key = `${def.method.toUpperCase()} ${fullPath}`;
    if (!registeredKeys.has(key)) {
      registeredKeys.add(key);
      registry.registerPath(
        buildRouteConfig(
          def as RouteDef<
            AnyZodObject | undefined,
            AnyZodObject | undefined,
            ZodTypeAny | undefined
          >,
          fullPath,
          openApiPath,
        ),
      );
      markRegistryChanged();
      routeManifest.push({
        method: def.method,
        path: fullPath,
        openApiPath,
        auth,
        tags: def.tags,
        summary: def.summary,
      });
    }
  };

  return { basePath, router, route };
}
