import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

/**
 * Component tests run in jsdom. Pipeline and worker-logic tests opt into Node with
 * `// @vitest-environment node` at the top of the file (R20: jsdom lacks Worker and Blob streams).
 */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}', 'deploy-checks/**/*.test.ts'],
    setupFiles: ['./src/test/setup.ts'],
    restoreMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
    // CSS is not processed, except raw reads of the theme tokens (contrast tests measure them, C-40).
    css: { include: [/styles\/index\.css\?raw$/] },
    // Router tests import every lazy page cold (zxcvbn dictionaries, crypto); allow for a loaded laptop.
    testTimeout: 20_000,
  },
});
