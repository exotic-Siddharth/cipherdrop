import { defineConfig } from 'tsup';

/**
 * Production bundle: internal workspace packages (TS source) are bundled; npm dependencies stay external.
 * dist/index.js is the server; dist/provision-runtime-role.js the one-shot of deploy/api-entrypoint.sh `migrate`.
 */
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'provision-runtime-role': 'src/db/provision-runtime-role.ts',
  },
  format: ['esm'],
  platform: 'node',
  target: 'node22',
  outDir: 'dist',
  sourcemap: true,
  clean: true,
  splitting: false,
  noExternal: [/^@cipherdrop\//],
});
