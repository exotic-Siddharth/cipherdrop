import { OpenApiGeneratorV3 } from '@asteasolutions/zod-to-openapi';
import { registry, registryVersion } from './registry';

type OpenApiDocument = ReturnType<OpenApiGeneratorV3['generateDocument']>;

let cache: { version: number; doc: OpenApiDocument } | undefined;

/** The OpenAPI 3.0 document served at /api/openapi.json (regenerated when new paths register). */
export function getOpenApiDocument(): OpenApiDocument {
  if (!cache || cache.version !== registryVersion()) {
    const doc = new OpenApiGeneratorV3(registry.definitions).generateDocument({
      openapi: '3.0.3',
      info: {
        title: 'CipherDrop API',
        version: '1.0.0',
        description:
          'Zero-knowledge, end-to-end encrypted file sharing. The server stores and returns opaque base64url ' +
          'blobs and ciphertext byte streams only. Errors: {error:{code,message,details?}}. ' +
          'Pages: {items,total,page,pageSize}.',
      },
      servers: [{ url: '/' }],
    });
    cache = { version: registryVersion(), doc };
  }
  return cache.doc;
}
