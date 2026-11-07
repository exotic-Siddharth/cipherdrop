import { defineConfig } from 'tsup';

/** Production bundle: internal workspace packages (TS source) are bundled; npm dependencies stay external. */
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  platform: 'node',
  target: 'node22',
  outDir: 'dist',
  sourcemap: true,
  clean: true,
  splitting: false,
  noExternal: [/^@cipherdrop\//],
});
