#!/usr/bin/env node
/**
 * A lockfile for the API image's standalone Prisma CLI (apps/api/Dockerfile, stage prisma-cli), cut out of the
 * repository's package-lock.json.
 *
 * The CLI is a devDependency of the API, so the image's production install leaves it out, yet the container runs
 * `prisma migrate deploy` when it starts. Installing it on its own with `npm install prisma@<version>` pins only the
 * top-level version: the transitive tree (@prisma/config -> c12 -> chokidar, jiti, ... with ranged versions) would
 * resolve afresh on every build, outside the lockfile's integrity hashes and outside the npm audit gate.
 *
 * This script writes a package.json and a package-lock.json holding exactly the lockfile entries of `prisma` and of
 * everything it depends on, at the paths the repository's install puts them, with the same version, resolved URL and
 * integrity hash. `npm ci` from that directory then installs byte-for-byte what the repository's lockfile describes,
 * or fails. It is generated during the image build rather than committed, so it can never drift from the root
 * lockfile, and a Dependabot bump of prisma reaches the image with nothing else to update.
 *
 * Fails (exit 1) when an entry has no resolved URL or integrity hash (npm ci could not verify it), when a required
 * dependency or non-optional peer cannot be resolved inside the root lockfile, or when an entry is a workspace link.
 *
 * Usage: node scripts/prisma-cli-lockfile.mjs <root package-lock.json> <output directory>
 * Plain ESM with no dependencies, like scripts/audit-gate.mjs: it runs in the bare node image before any install.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const CLI_PACKAGE = 'prisma';
export const PROJECT_NAME = 'cipherdrop-prisma-cli';
/** Lockfile flags that describe the entry's place in the ROOT project; in the standalone install all are prod. */
const ROOT_ONLY_FLAGS = ['dev', 'devOptional', 'peer', 'optional', 'extraneous', 'inBundle'];

/**
 * The lockfile key a dependency `name` resolves to from the package at `fromKey`, the way Node's resolver walks up
 * nested node_modules directories ('' is the project root). Undefined when the lockfile has no such package.
 */
export function resolveKey(packages, fromKey, name) {
  let dir = fromKey;
  for (;;) {
    const key = dir === '' ? `node_modules/${name}` : `${dir}/node_modules/${name}`;
    if (packages[key]) return key;
    if (dir === '') return undefined;
    // From 'node_modules/a/node_modules/b' up to 'node_modules/a', then to the root.
    const up = dir.lastIndexOf('/node_modules/');
    dir = up === -1 ? '' : dir.slice(0, up);
  }
}

/**
 * The package.json and package-lock.json (lockfileVersion 3) of a project whose only dependency is `name` at the
 * version the root lockfile holds, with the entries of its whole dependency tree copied from that lockfile.
 */
export function cliLockfile(rootLock, name = CLI_PACKAGE) {
  const packages = rootLock?.packages;
  if (rootLock?.lockfileVersion !== 3 || !packages || typeof packages !== 'object') {
    throw new Error('expected a package-lock.json with lockfileVersion 3 and a "packages" map');
  }
  const top = resolveKey(packages, '', name);
  if (!top) throw new Error(`${name} is not in the root lockfile`);
  // key -> true when at least one REQUIRED edge reaches it (false: only optional dependencies do).
  const reached = new Map();
  const queue = [[top, true]];
  while (queue.length > 0) {
    const [key, required] = queue.shift();
    if (reached.get(key) === true || (reached.has(key) && !required)) continue;
    reached.set(key, required);
    const entry = packages[key];
    if (entry.link) throw new Error(`${key} is a workspace link, not a registry package`);
    if (typeof entry.resolved !== 'string' || typeof entry.integrity !== 'string') {
      throw new Error(`${key} has no resolved URL or integrity hash: npm ci could not verify it`);
    }
    const optionalPeers = new Set(
      Object.entries(entry.peerDependenciesMeta ?? {})
        .filter(([, meta]) => meta?.optional === true)
        .map(([dep]) => dep),
    );
    const edges = [
      ...Object.keys(entry.dependencies ?? {}).map((dep) => [dep, required]),
      ...Object.keys(entry.optionalDependencies ?? {}).map((dep) => [dep, false]),
      // npm installs non-optional peers itself; optional ones are only used when something else installs them.
      ...Object.keys(entry.peerDependencies ?? {})
        .filter((dep) => !optionalPeers.has(dep))
        .map((dep) => [dep, required]),
    ];
    for (const [dep, depRequired] of edges) {
      const depKey = resolveKey(packages, key, dep);
      if (depKey) queue.push([depKey, depRequired]);
      else if (depRequired)
        throw new Error(`${key}: dependency ${dep} is not in the root lockfile`);
      // An optional dependency for another platform is simply absent from the lockfile: nothing to install.
    }
  }

  const version = packages[top].version;
  const manifest = {
    name: PROJECT_NAME,
    version: '0.0.0',
    private: true,
    description: `Standalone ${name} CLI for the API image, generated by scripts/prisma-cli-lockfile.mjs`,
    dependencies: { [name]: version },
  };
  const lockPackages = {
    '': {
      name: manifest.name,
      version: manifest.version,
      dependencies: { ...manifest.dependencies },
    },
  };
  for (const key of [...reached.keys()].sort()) {
    const copy = { ...packages[key] };
    for (const flag of ROOT_ONLY_FLAGS) delete copy[flag];
    // Reached only through optionalDependencies (a platform-specific binary): npm ci may skip it.
    if (reached.get(key) === false) copy.optional = true;
    lockPackages[key] = copy;
  }
  const lock = {
    name: manifest.name,
    version: manifest.version,
    lockfileVersion: 3,
    requires: true,
    packages: lockPackages,
  };
  return { manifest, lock };
}

/** Writes package.json and package-lock.json into `outDir` (created when missing). */
export function writeCliLockfile(rootLockFile, outDir, name = CLI_PACKAGE) {
  const { manifest, lock } = cliLockfile(JSON.parse(readFileSync(rootLockFile, 'utf8')), name);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(path.join(outDir, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`);
  return { manifest, lock };
}

function main(argv) {
  const [rootLockFile, outDir] = argv;
  if (!rootLockFile || !outDir || argv.length !== 2) {
    console.error(
      'usage: node scripts/prisma-cli-lockfile.mjs <root package-lock.json> <output directory>',
    );
    return 2;
  }
  try {
    const { manifest, lock } = writeCliLockfile(rootLockFile, outDir);
    const count = Object.keys(lock.packages).length - 1;
    console.log(
      `${CLI_PACKAGE}@${manifest.dependencies[CLI_PACKAGE]}: ${count} packages locked in ${outDir}`,
    );
    return 0;
  } catch (err) {
    console.error(`prisma-cli-lockfile: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
