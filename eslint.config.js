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

/*
 * Security bans (docs/SECURITY.md): invariants the code keeps today, enforced so a change cannot drop them silently.
 * eslint.config.test.mjs (npm run test:lint) proves each one fires. Flat config replaces a rule's options when two
 * blocks match the same file, so a block that adds a ban to a narrower set of files repeats the wider block's bans.
 */
const MATH_RANDOM_BAN = [
  {
    object: 'Math',
    property: 'random',
    message:
      'Math.random is not a CSPRNG. Key material, nonces, ids and salts come from crypto.getRandomValues (randomBytes in @cipherdrop/crypto).',
  },
];
const HTML_SINK_MESSAGE =
  'Writing HTML from a string is an XSS sink (the CSP is the second line, not the first). Build DOM nodes or JSX; React escapes text.';
const HTML_SINK_BAN = [
  { property: 'innerHTML', message: HTML_SINK_MESSAGE },
  { property: 'outerHTML', message: HTML_SINK_MESSAGE },
  { property: 'insertAdjacentHTML', message: HTML_SINK_MESSAGE },
  { object: 'document', property: 'write', message: HTML_SINK_MESSAGE },
  { object: 'document', property: 'writeln', message: HTML_SINK_MESSAGE },
];
const RAW_SQL_MESSAGE =
  'Unsafe raw SQL concatenates strings into the query. Use the tagged templates $queryRaw`...` / $executeRaw`...`, which send every value as a bind parameter.';
const RAW_SQL_BAN = [
  { property: '$queryRawUnsafe', message: RAW_SQL_MESSAGE },
  { property: '$executeRawUnsafe', message: RAW_SQL_MESSAGE },
  { object: 'Prisma', property: 'raw', message: RAW_SQL_MESSAGE },
];
// An absolute (scheme:) or protocol-relative (//) URL as the first argument of a network call. \x2F is '/':
// esquery's regex literal cannot contain a slash.
const ABSOLUTE_URL = '/^(?:[a-z][a-z0-9+.-]*:|\\x2F\\x2F)/i';
const ABSOLUTE_URL_MESSAGE =
  "The SPA talks only to its own origin (spec section 6, CSP connect-src 'self'): use a relative /api path (lib/api, apiUrl).";
const NETWORK_CALLS = [
  'CallExpression[callee.name="fetch"]',
  'CallExpression[callee.type="MemberExpression"][callee.property.name="fetch"]',
  'CallExpression[callee.type="MemberExpression"][callee.property.name="sendBeacon"]',
  'NewExpression[callee.name=/^(?:Request|EventSource|WebSocket)$/]',
];
const WEB_SYNTAX_BAN = [
  ...NETWORK_CALLS.flatMap((call) => [
    {
      selector: `${call}[arguments.0.type="Literal"][arguments.0.value=${ABSOLUTE_URL}]`,
      message: ABSOLUTE_URL_MESSAGE,
    },
    {
      selector: `${call}[arguments.0.type="TemplateLiteral"][arguments.0.quasis.0.value.raw=${ABSOLUTE_URL}]`,
      message: ABSOLUTE_URL_MESSAGE,
    },
  ]),
  { selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]', message: HTML_SINK_MESSAGE },
  { selector: 'Property[key.name="dangerouslySetInnerHTML"]', message: HTML_SINK_MESSAGE },
];
const TEST_FILES = ['**/*.test.ts', '**/*.test.tsx', 'apps/web/src/test/**'];

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
  // Server code logs only through pino (zero-knowledge logging rules, spec section 12), and its SQL binds every value.
  {
    files: ['apps/api/src/**/*.ts'],
    ignores: ['**/*.test.ts'],
    rules: { 'no-console': 'error', 'no-restricted-properties': ['error', ...RAW_SQL_BAN] },
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
  // Key material and nonces: the crypto package. (Its tests may use Math.random for test data.)
  {
    files: ['packages/crypto/src/**/*.ts'],
    ignores: TEST_FILES,
    rules: { 'no-restricted-properties': ['error', ...MATH_RANDOM_BAN] },
  },
  // SPA source: no HTML from strings, no requests to another origin.
  {
    files: ['apps/web/src/**/*.{ts,tsx}'],
    ignores: TEST_FILES,
    rules: {
      'no-restricted-properties': ['error', ...HTML_SINK_BAN],
      'no-restricted-syntax': ['error', ...WEB_SYNTAX_BAN],
    },
  },
  // The SPA's crypto pipeline and its workers also handle key material (repeats the SPA bans: see above).
  {
    files: ['apps/web/src/crypto/**/*.ts', 'apps/web/src/workers/**/*.ts'],
    ignores: TEST_FILES,
    rules: { 'no-restricted-properties': ['error', ...HTML_SINK_BAN, ...MATH_RANDOM_BAN] },
  },
  // Web tooling that runs in Node.
  {
    files: ['apps/web/*.config.ts', 'apps/web/e2e/**/*.ts', 'apps/web/bench/**/*.ts'],
    languageOptions: { globals: { ...globals.node } },
  },
);
