// Tests for the Prisma CLI lockfile of the API image (node:test, no dependencies): npm run test:scripts.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { cliLockfile, PROJECT_NAME, resolveKey } from './prisma-cli-lockfile.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');
const script = path.join(scriptDir, 'prisma-cli-lockfile.mjs');
const rootLock = JSON.parse(readFileSync(path.join(repoRoot, 'package-lock.json'), 'utf8'));

const tmp = mkdtempSync(path.join(tmpdir(), 'prisma-cli-lock-'));
after(() => rmSync(tmp, { recursive: true, force: true }));

/** A registry entry as npm writes it into a lockfile. */
function entry(version, extra = {}) {
  return {
    version,
    resolved: `https://registry.npmjs.org/x/-/x-${version}.tgz`,
    integrity: `sha512-${Buffer.from(version).toString('base64')}`,
    ...extra,
  };
}

function lockOf(packages) {
  return { name: 'repo', lockfileVersion: 3, requires: true, packages: { '': {}, ...packages } };
}

/** Every dependency of every locked entry resolves inside the lock (what npm ci needs to build the tree). */
function assertClosed(lock) {
  for (const [key, e] of Object.entries(lock.packages)) {
    if (key === '') continue;
    for (const dep of Object.keys(e.dependencies ?? {})) {
      assert.ok(resolveKey(lock.packages, key, dep), `${key} -> ${dep} resolves`);
    }
  }
}

describe('resolveKey', () => {
  const packages = lockOf({
    'node_modules/a': entry('1.0.0'),
    'node_modules/b': entry('1.0.0'),
    'node_modules/a/node_modules/b': entry('2.0.0'),
    'node_modules/a/node_modules/c': entry('1.0.0'),
  }).packages;

  test('prefers the nested copy, then walks up to the root, like Node', () => {
    assert.equal(resolveKey(packages, 'node_modules/a', 'b'), 'node_modules/a/node_modules/b');
    assert.equal(
      resolveKey(packages, 'node_modules/a/node_modules/b', 'c'),
      'node_modules/a/node_modules/c',
    );
    assert.equal(resolveKey(packages, 'node_modules/a/node_modules/c', 'a'), 'node_modules/a');
    assert.equal(resolveKey(packages, '', 'b'), 'node_modules/b');
    assert.equal(resolveKey(packages, 'node_modules/b', 'c'), undefined);
  });
});

describe('cliLockfile against the repository lockfile', () => {
  const { manifest, lock } = cliLockfile(rootLock);
  const keys = Object.keys(lock.packages).filter((k) => k !== '');

  test('depends on exactly the prisma version the repository locks', () => {
    const version = rootLock.packages['node_modules/prisma'].version;
    assert.deepEqual(manifest.dependencies, { prisma: version });
    assert.equal(manifest.private, true);
    assert.deepEqual(lock.packages[''], {
      name: PROJECT_NAME,
      version: '0.0.0',
      dependencies: { prisma: version },
    });
    assert.equal(lock.lockfileVersion, 3);
    assert.equal(lock.packages['node_modules/prisma'].version, version);
  });

  test('locks the whole transitive tree, nested copies included, and nothing else', () => {
    for (const name of ['@prisma/config', '@prisma/engines', 'c12', 'chokidar', 'jiti', 'effect']) {
      assert.ok(lock.packages[`node_modules/${name}`], `${name} is locked`);
    }
    // nypm needs citty 0.2 while c12's giget takes the hoisted 0.1: both copies keep their paths.
    assert.ok(lock.packages['node_modules/nypm/node_modules/citty']);
    assert.ok(lock.packages['node_modules/citty']);
    // Nothing of the API or the SPA comes along.
    for (const name of ['express', '@prisma/client', 'react', 'typescript', '@cipherdrop/shared']) {
      assert.equal(lock.packages[`node_modules/${name}`], undefined, `${name} is not locked`);
    }
    assertClosed(lock);
  });

  test('copies version, resolved URL and integrity hash from the repository lockfile', () => {
    for (const key of keys) {
      const source = rootLock.packages[key];
      assert.ok(source, `${key} exists in package-lock.json`);
      for (const field of ['version', 'resolved', 'integrity', 'dependencies']) {
        assert.deepEqual(lock.packages[key][field], source[field], `${key} ${field}`);
      }
      assert.match(lock.packages[key].integrity, /^sha512-/, `${key} integrity`);
    }
  });

  test('drops the flags that describe the package in the repository (dev, devOptional, peer)', () => {
    assert.equal(rootLock.packages['node_modules/prisma'].devOptional, true, 'precondition');
    for (const key of keys) {
      for (const flag of ['dev', 'devOptional', 'peer', 'extraneous']) {
        assert.equal(lock.packages[key][flag], undefined, `${key} ${flag}`);
      }
    }
  });
});

describe('cliLockfile edge cases', () => {
  test('marks a package reached only through optionalDependencies as optional', () => {
    const { lock } = cliLockfile(
      lockOf({
        'node_modules/prisma': entry('1.0.0', {
          dependencies: { req: '1' },
          optionalDependencies: { native: '1', absent: '1' },
        }),
        'node_modules/req': entry('1.0.0', { dependencies: { native: '1' }, dev: true }),
        'node_modules/native': entry('1.0.0', { optional: true }),
      }),
    );
    // `native` is also a REQUIRED dependency of `req`, so it is not optional; `absent` (another platform) is skipped.
    assert.equal(lock.packages['node_modules/native'].optional, undefined);
    assert.equal(lock.packages['node_modules/absent'], undefined);
    assert.equal(lock.packages['node_modules/req'].dev, undefined);

    const only = cliLockfile(
      lockOf({
        'node_modules/prisma': entry('1.0.0', { optionalDependencies: { native: '1' } }),
        'node_modules/native': entry('1.0.0'),
      }),
    ).lock;
    assert.equal(only.packages['node_modules/native'].optional, true);
  });

  test('follows required peers and skips optional ones', () => {
    const { lock } = cliLockfile(
      lockOf({
        'node_modules/prisma': entry('1.0.0', {
          peerDependencies: { typescript: '>=5', needed: '1' },
          peerDependenciesMeta: { typescript: { optional: true } },
        }),
        'node_modules/typescript': entry('5.9.3'),
        'node_modules/needed': entry('1.0.0'),
      }),
    );
    assert.ok(lock.packages['node_modules/needed']);
    assert.equal(lock.packages['node_modules/typescript'], undefined);
  });

  test('refuses what npm ci could not verify or install', () => {
    assert.throws(() => cliLockfile(lockOf({})), /prisma is not in the root lockfile/);
    assert.throws(
      () =>
        cliLockfile(
          lockOf({ 'node_modules/prisma': entry('1.0.0', { dependencies: { gone: '1' } }) }),
        ),
      /dependency gone is not in the root lockfile/,
    );
    const { integrity: _integrity, ...unhashed } = entry('1.0.0');
    assert.throws(
      () => cliLockfile(lockOf({ 'node_modules/prisma': unhashed })),
      /no resolved URL or integrity hash/,
    );
    assert.throws(
      () =>
        cliLockfile(
          lockOf({
            'node_modules/prisma': entry('1.0.0', { dependencies: { ws: '*' } }),
            'node_modules/ws': { resolved: 'packages/ws', link: true },
          }),
        ),
      /workspace link/,
    );
    assert.throws(() => cliLockfile({ lockfileVersion: 2, packages: {} }), /lockfileVersion 3/);
  });
});

describe('command line', () => {
  test('writes package.json and package-lock.json into the output directory', () => {
    const out = path.join(tmp, 'out');
    const res = spawnSync(
      process.execPath,
      [script, path.join(repoRoot, 'package-lock.json'), out],
      {
        encoding: 'utf8',
      },
    );
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /^prisma@\d+\.\d+\.\d+: \d+ packages locked in /);
    const expected = cliLockfile(rootLock);
    assert.deepEqual(
      JSON.parse(readFileSync(path.join(out, 'package.json'), 'utf8')),
      expected.manifest,
    );
    assert.deepEqual(
      JSON.parse(readFileSync(path.join(out, 'package-lock.json'), 'utf8')),
      expected.lock,
    );
  });

  test('exits 1 with a message on a bad lockfile and 2 on bad arguments', () => {
    const bad = path.join(tmp, 'bad-lock.json');
    writeFileSync(bad, JSON.stringify(lockOf({})));
    const failed = spawnSync(process.execPath, [script, bad, path.join(tmp, 'never')], {
      encoding: 'utf8',
    });
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /prisma-cli-lockfile: prisma is not in the root lockfile/);
    const usage = spawnSync(process.execPath, [script], { encoding: 'utf8' });
    assert.equal(usage.status, 2);
    assert.match(usage.stderr, /^usage:/);
  });
});
