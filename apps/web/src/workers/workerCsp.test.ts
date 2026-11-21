// @vitest-environment node
/**
 * worker-src is 'self' only (crypto-7). Both workers are same-origin module files: Vite recognises
 * `new Worker(new URL('./x.worker.ts', import.meta.url), ...)` and emits the worker as its own /assets/ chunk. A
 * worker built any other way (a `?worker&inline` import, a Blob of script text turned into an object URL) would
 * run from a blob: URL and need blob: back in worker-src, so these checks fail before the CSP has to be widened.
 * The e2e suite proves the emitted workers load under the production CSP (uploads and the KDF run in them).
 */
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CONTENT_SECURITY_POLICY } from '../../securityHeaders';

const srcDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sources = readdirSync(srcDir, { recursive: true, encoding: 'utf8' })
  .filter((file) => /\.tsx?$/.test(file) && !/\.test\.tsx?$/.test(file))
  .map((file) => ({ file, text: readFileSync(path.join(srcDir, file), 'utf8') }));

function sourcesOf(name: string): string[] {
  const found = CONTENT_SECURITY_POLICY.split(';')
    .map((d) => d.trim().split(/\s+/))
    .find(([directive]) => directive === name);
  return found ? found.slice(1) : [];
}

describe('workers and the CSP (crypto-7)', () => {
  it("worker-src allows this origin's files only, not blob:", () => {
    expect(sourcesOf('worker-src')).toEqual(["'self'"]);
  });

  it('every worker is built from a same-origin module file', () => {
    const constructions = sources.flatMap(({ file, text }) =>
      [...text.matchAll(/new\s+(?:Shared)?Worker\s*\(\s*([^\n]*)/g)].map((m) => ({
        file,
        arg: m[1]!,
      })),
    );
    expect(constructions.map((c) => c.file).sort()).toEqual([
      path.join('crypto', 'kdfClient.ts'),
      path.join('features', 'send', 'uploadClient.ts'),
    ]);
    for (const { file, arg } of constructions) {
      expect(arg, file).toMatch(/^new URL\('(\.\.?\/)+[\w/]+\.worker\.ts', import\.meta\.url\)/);
    }
  });

  it('no source imports an inline (blob:) worker', () => {
    for (const { file, text } of sources) {
      expect(text, file).not.toMatch(/['"][^'"\n]*\?(?:worker|sharedworker)(?:&[^'"\n]*)?['"]/);
      expect(text, file).not.toMatch(/['"][^'"\n]*[?&]inline\b[^'"\n]*['"]/);
    }
  });
});
