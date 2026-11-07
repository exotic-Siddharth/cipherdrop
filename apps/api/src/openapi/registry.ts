/**
 * The single OpenAPI registry. Paths are registered ONLY through lib/router.ts `route()`. Lanes may register
 * extra named component schemas here via `registry.register(name, schema)` from their own modules.
 */
import { OpenAPIRegistry, extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi';
import { ErrorBodySchema } from '@cipherdrop/shared';
import { z } from 'zod';

extendZodWithOpenApi(z);

export const registry = new OpenAPIRegistry();

let version = 0;
/** Bumped on every new path, so the cached document is regenerated. */
export const registryVersion = () => version;
export const markRegistryChanged = () => {
  version += 1;
};

registry.registerComponent('securitySchemes', 'bearerAuth', {
  type: 'http',
  scheme: 'bearer',
  bearerFormat: 'JWT',
  description:
    'Access token (JWT HS256, 15 min, claims {sub, role, sid}); kept in memory by the SPA.',
});
registry.registerComponent('securitySchemes', 'uploadToken', {
  type: 'http',
  scheme: 'bearer',
  description: 'uploadToken returned by POST /api/drops (useless once the drop is READY).',
});
registry.registerComponent('securitySchemes', 'downloadToken', {
  type: 'http',
  scheme: 'bearer',
  description: 'downloadToken returned by POST /api/drops/{id}/open or the admin review grant.',
});
registry.registerComponent('securitySchemes', 'ownerToken', {
  type: 'apiKey',
  in: 'header',
  name: 'X-Owner-Token',
  description: 'ownerToken returned by POST /api/drops (anonymous owners).',
});
registry.registerComponent('securitySchemes', 'refreshCookie', {
  type: 'apiKey',
  in: 'cookie',
  name: 'cd_rt',
  description: 'Opaque refresh token cookie (httpOnly, SameSite=Strict, Path=/api/auth).',
});

/** Registered copy of ErrorBodySchema (renders as #/components/schemas/ErrorBody). */
export const ErrorBodyRef = registry.register('ErrorBody', ErrorBodySchema);
