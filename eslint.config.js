// @ts-check
import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import { defineConfig } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const NODE_BUILTINS = [
  'assert',
  'async_hooks',
  'buffer',
  'child_process',
  'cluster',
  'crypto',
  'dgram',
  'dns',
  'events',
  'fs',
  'fs/promises',
  'http',
  'http2',
  'https',
  'module',
  'net',
  'os',
  'path',
  'perf_hooks',
  'process',
  'querystring',
  'readline',
  'stream',
  'string_decoder',
  'timers',
  'tls',
  'tty',
  'url',
  'util',
  'v8',
  'vm',
  'worker_threads',
  'zlib',
];
const ISOMORPHIC_MESSAGE =
  'packages/crypto and packages/shared run in browsers and Web Workers: use WebCrypto / standard APIs, not Node-only ones.';

export default defineConfig(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/playwright-report/**',
      '**/test-results/**',
      'apps/api/data/**',
      'apps/api/prisma/migrations/**',
    ],
  },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],
    },
  },
  // Server code logs only through pino (zero-knowledge logging rules, spec section 12).
  {
    files: ['apps/api/src/**/*.ts'],
    ignores: ['**/*.test.ts'],
    rules: { 'no-console': 'error' },
  },
  // Isomorphic packages: no Node-only modules or globals outside tests and the bench.
  {
    files: ['packages/crypto/src/**/*.ts', 'packages/shared/src/**/*.ts'],
    ignores: ['**/*.test.ts', 'packages/crypto/src/bench.ts'],
    languageOptions: { globals: { ...globals.browser, ...globals.worker } },
    rules: {
      'no-console': 'error',
      'no-restricted-imports': [
        'error',
        {
          paths: NODE_BUILTINS.map((name) => ({ name, message: ISOMORPHIC_MESSAGE })),
          patterns: [{ group: ['node:*'], message: ISOMORPHIC_MESSAGE }],
        },
      ],
      'no-restricted-globals': [
        'error',
        ...[
          'Buffer',
          'process',
          'require',
          '__dirname',
          '__filename',
          'global',
          'setImmediate',
        ].map((name) => ({ name, message: ISOMORPHIC_MESSAGE })),
      ],
    },
  },
  // Web app (browser + workers).
  {
    files: ['apps/web/**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.worker } },
    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },
  // Web tooling that runs in Node.
  {
    files: ['apps/web/*.config.ts', 'apps/web/e2e/**/*.ts', 'apps/web/bench/**/*.ts'],
    languageOptions: { globals: { ...globals.node } },
  },
);
