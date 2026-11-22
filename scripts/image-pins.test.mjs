// Image references that must stay identical across the repository (node:test, no dependencies): npm run test:scripts.
import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  checkPins,
  composeImages,
  dockerfileImages,
  readRepository,
  repositoryOf,
  workflowReferences,
} from './image-pins.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const PG = `postgres:16-alpine@sha256:${'1'.repeat(64)}`;
const PG_BUMPED = `postgres:16-alpine@sha256:${'2'.repeat(64)}`;
const REDIS = `redis:7-alpine@sha256:${'3'.repeat(64)}`;
const MINIO = 'cgr.dev/chainguard/minio:latest';
const NODE = `node:22-alpine@sha256:${'4'.repeat(64)}`;

const compose = (pg = PG) => ({
  file: 'compose.yml',
  text: [
    'x-logging: &logging',
    '  driver: json-file',
    'services:',
    '  postgres:',
    `    image: ${pg}`,
    '  redis:',
    `    image: ${REDIS} # pinned`,
    '  api:',
    // Built locally: not a third-party image.
    '    image: cipherdrop-api:${IMAGE_TAG:-latest}',
    '  minio:',
    `    image: ${MINIO}`,
    '',
  ].join('\n'),
});

const workflow = ({ pg = PG, redis = REDIS, minio = MINIO } = {}) => ({
  file: 'ci.yml',
  text: [
    'jobs:',
    '  integration:',
    '    name: integration (postgres, redis, minio)',
    '    services:',
    '      postgres:',
    `        image: ${pg}`,
    '        env:',
    '          POSTGRES_USER: cipherdrop',
    '      redis:',
    `        image: '${redis}'`,
    '        options: >-',
    '          --health-cmd "redis-cli ping"',
    '    steps:',
    '      - name: db:check',
    '        env:',
    '          SHADOW_DATABASE_URL: postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop_shadow',
    '          REDIS_URL: redis://localhost:56380/0',
    '        run: npm run db:check -w @cipherdrop/api',
    '      - run: |',
    `          docker run -d --name minio ${minio} server /data`,
    '',
  ].join('\n'),
});

const dockerfile = (file, node = NODE) => ({
  file,
  text: [`FROM ${node} AS base`, 'RUN true', 'FROM base AS runtime', ''].join('\n'),
});

const pins = (overrides = {}) =>
  checkPins({
    compose: compose(),
    workflows: [workflow()],
    dockerfiles: [dockerfile('api.Dockerfile'), dockerfile('web.Dockerfile')],
    ...overrides,
  });

describe('repositoryOf', () => {
  test('drops the tag, the digest and the implicit Docker Hub prefixes', () => {
    assert.equal(repositoryOf(PG), 'postgres');
    assert.equal(repositoryOf('docker.io/library/postgres:16'), 'postgres');
    assert.equal(repositoryOf('postgres'), 'postgres');
    assert.equal(repositoryOf(MINIO), 'cgr.dev/chainguard/minio');
    assert.equal(
      repositoryOf('registry.local:5000/team/app:1.2@sha256:abc'),
      'registry.local:5000/team/app',
    );
  });
});

describe('composeImages', () => {
  test('lists the third-party images by repository, not the stack’s own images', () => {
    const { images, problems } = composeImages('compose.yml', compose().text);
    assert.deepEqual(problems, []);
    assert.deepEqual(
      [...images].map(([repo, { ref, at }]) => [repo, ref, at]),
      [
        ['postgres', PG, 'compose.yml:5'],
        ['redis', REDIS, 'compose.yml:7'],
        ['cgr.dev/chainguard/minio', MINIO, 'compose.yml:11'],
      ],
    );
  });

  test('a repository named twice with two references is a problem', () => {
    const text = `${compose().text}  postgres-replica:\n    image: ${PG_BUMPED}\n`;
    const { problems } = composeImages('compose.yml', text);
    assert.equal(problems.length, 1);
    assert.match(
      problems[0],
      /^compose\.yml:13: postgres:16-alpine@sha256:2+ differs from .+ at compose\.yml:5$/,
    );
  });
});

describe('workflowReferences', () => {
  const repos = new Set(['postgres', 'redis', 'cgr.dev/chainguard/minio']);

  test('finds service images and docker run arguments, not keys, names, URLs or commands', () => {
    assert.deepEqual(workflowReferences('ci.yml', workflow().text, repos), [
      { ref: PG, repo: 'postgres', at: 'ci.yml:6' },
      { ref: REDIS, repo: 'redis', at: 'ci.yml:10' },
      { ref: MINIO, repo: 'cgr.dev/chainguard/minio', at: 'ci.yml:20' },
    ]);
  });

  test('also finds a fully qualified reference and an image with neither tag nor digest', () => {
    const text = [
      'services:',
      '  postgres:',
      '    image: docker.io/library/postgres:16-alpine',
      '  redis:',
      '    image: redis',
      '',
    ].join('\n');
    assert.deepEqual(
      workflowReferences('ci.yml', text, repos).map(({ ref, at }) => [ref, at]),
      [
        ['docker.io/library/postgres:16-alpine', 'ci.yml:3'],
        ['redis', 'ci.yml:5'],
      ],
    );
  });

  test('skips comment lines', () => {
    const text = `# The services mirror ${PG_BUMPED}.\n      # image: postgres:15\n`;
    assert.deepEqual(workflowReferences('ci.yml', text, repos), []);
  });
});

describe('dockerfileImages', () => {
  test('reads FROM images, not stage names', () => {
    assert.deepEqual(dockerfileImages('Dockerfile', dockerfile('Dockerfile').text), [
      { ref: NODE, repo: 'node', at: 'Dockerfile:1' },
    ]);
  });
});

describe('checkPins', () => {
  test('identical references pass', () => {
    assert.deepEqual(pins().problems, []);
  });

  test('a compose digest bump without the CI services fails (a Dependabot docker-compose pull request)', () => {
    const { problems } = pins({ compose: compose(PG_BUMPED) });
    assert.deepEqual(problems, [
      `ci.yml:6: ${PG} is not compose.yml's ${PG_BUMPED} (compose.yml:5)`,
    ]);
  });

  test('a CI service image on other bytes, or on the tag alone, fails', () => {
    assert.equal(pins({ workflows: [workflow({ pg: PG_BUMPED })] }).problems.length, 1);
    assert.match(
      pins({ workflows: [workflow({ redis: 'redis:7-alpine' })] }).problems[0],
      /^ci\.yml:10: redis:7-alpine is not compose\.yml's redis:7-alpine@sha256:3+ \(compose\.yml:7\)$/,
    );
  });

  test('a docker run image that drifts from the compose file fails', () => {
    const minio = `cgr.dev/chainguard/minio:latest@sha256:${'5'.repeat(64)}`;
    assert.match(
      pins({ workflows: [workflow({ minio })] }).problems[0],
      /^ci\.yml:20: cgr\.dev\/chainguard\/minio/,
    );
  });

  test('two Dockerfiles on different node digests fail', () => {
    const other = `node:22-alpine@sha256:${'6'.repeat(64)}`;
    const { problems } = pins({
      dockerfiles: [dockerfile('api.Dockerfile'), dockerfile('web.Dockerfile', other)],
    });
    assert.deepEqual(problems, [
      `web.Dockerfile:1: ${other} differs from ${NODE} at api.Dockerfile:1`,
    ]);
  });
});

describe('this repository', () => {
  const result = checkPins(readRepository(repoRoot));

  test('CI, docker-compose.prod.yml and the Dockerfiles name each shared image identically', () => {
    assert.deepEqual(result.problems, []);
  });

  // Without these the check above could pass on nothing found.
  test('the reader sees the pins it is meant to compare', () => {
    for (const repo of ['postgres', 'redis']) {
      assert.match(
        result.composeImages.get(repo)?.ref ?? '',
        /:[\w.-]+@sha256:[0-9a-f]{64}$/,
        `${repo} in compose`,
      );
      const inCi = result.workflowRefs.filter(
        (r) => r.repo === repo && r.at.startsWith('.github/workflows/ci.yml:'),
      );
      assert.ok(inCi.length > 0, `ci.yml uses the ${repo} image`);
    }
    for (const file of ['apps/api/Dockerfile', 'apps/web/Dockerfile']) {
      assert.ok(
        result.dockerfileRefs.some((r) => r.repo === 'node' && r.at.startsWith(`${file}:`)),
        `${file} builds on node`,
      );
    }
  });
});
