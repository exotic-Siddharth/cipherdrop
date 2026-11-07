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
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts'],
    restoreMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
    css: false,
  },
});
