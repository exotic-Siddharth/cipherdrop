// Tests for the image vulnerability gate (node:test, no dependencies): npm run test:scripts.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  annotations,
  collectVulnerabilities,
  evaluate,
  formatResults,
  imageSlug,
  TRIVY_IMAGE,
  trivyArgs,
} from './image-scan.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(scriptDir, 'image-scan.mjs');
const tmp = mkdtempSync(path.join(tmpdir(), 'image-scan-'));
after(() => rmSync(tmp, { recursive: true, force: true }));

/** One vulnerability as Trivy writes it into a JSON report. */
function vuln(id, severity, extra = {}) {
  return {
    VulnerabilityID: id,
    PkgName: 'pkg',
    InstalledVersion: '1.0.0',
    Severity: severity,
    Status: 'affected',
    ...extra,
  };
}

const fixedIn = (version) => ({ FixedVersion: version, Status: 'fixed' });

/** A Trivy JSON report (schema 2): an Alpine layer and the node packages. */
function report(osVulns = [], nodeVulns = []) {
  return {
    SchemaVersion: 2,
    ArtifactName: '/scan/cipherdrop-api.tar',
    Metadata: { OS: { Family: 'alpine', Name: '3.24.4' } },
    Results: [
      {
        Target: '/scan/cipherdrop-api.tar (alpine 3.24.4)',
        Type: 'alpine',
        Vulnerabilities: osVulns,
      },
      { Target: 'Node.js', Type: 'node-pkg', Vulnerabilities: nodeVulns },
    ],
  };
}

function run(args, env = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_ACTIONS: '', ...env },
  });
}

function saved(name, content) {
  const file = path.join(tmp, name);
  writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));
  return file;
}

describe('image scan policy', () => {
  test('a CRITICAL with a fixed version fails the gate', () => {
    const r = evaluate('api', report([vuln('CVE-2026-1', 'CRITICAL', fixedIn('3.0.1'))]));
    assert.equal(r.ok, false);
    assert.deepEqual(
      r.failing.map((v) => v.id),
      ['CVE-2026-1'],
    );
    assert.deepEqual(r.counts.CRITICAL, { all: 1, fixable: 1 });
  });

  test('a fixed version alone (no Status) counts as fixable, as with --ignore-unfixed', () => {
    const r = evaluate(
      'api',
      report([], [vuln('CVE-2026-2', 'CRITICAL', { FixedVersion: '2.1.0', Status: undefined })]),
    );
    assert.equal(r.ok, false);
  });

  test('a CRITICAL with no fix yet, and HIGH ones fixed or not, are reported and pass', () => {
    const r = evaluate(
      'api',
      report(
        [vuln('CVE-2026-3', 'CRITICAL', { Status: 'will_not_fix' })],
        [
          vuln('CVE-2026-4', 'HIGH', fixedIn('5.0.10')),
          vuln('CVE-2026-5', 'HIGH'),
          vuln('CVE-2026-6', 'MEDIUM', fixedIn('1.1.1')),
          vuln('CVE-2026-7', 'LOW'),
        ],
      ),
    );
    assert.equal(r.ok, true);
    assert.deepEqual(r.failing, []);
    // Listed: CRITICAL first, then HIGH; MEDIUM and LOW only counted.
    assert.deepEqual(
      r.reported.map((v) => v.id),
      ['CVE-2026-3', 'CVE-2026-4', 'CVE-2026-5'],
    );
    assert.deepEqual(r.counts.HIGH, { all: 2, fixable: 1 });
    assert.deepEqual(r.counts.MEDIUM, { all: 1, fixable: 1 });
    assert.deepEqual(r.counts.LOW, { all: 1, fixable: 0 });
  });

  test('an unknown severity is counted as UNKNOWN and never dropped', () => {
    const r = evaluate('api', report([vuln('CVE-2026-8', 'SEVERE')]));
    assert.deepEqual(r.counts.UNKNOWN, { all: 1, fixable: 0 });
  });

  test('a clean image, and an image with no Results at all, pass', () => {
    assert.equal(evaluate('web', report()).ok, true);
    assert.equal(evaluate('web', { SchemaVersion: 2 }).ok, true);
  });

  test('anything that is not a Trivy report throws (the gate fails closed)', () => {
    assert.throws(() => collectVulnerabilities(null), /not a Trivy JSON report/);
    assert.throws(
      () => collectVulnerabilities({ SchemaVersion: 1, Results: [] }),
      /SchemaVersion 2/,
    );
    assert.throws(() => collectVulnerabilities({ SchemaVersion: 2, Results: {} }), /not an array/);
  });
});

describe('image scan output', () => {
  test('lists the reported findings, marks the failing ones and ends with the verdict', () => {
    const results = [
      evaluate(
        'cipherdrop-api:ci',
        report(
          [],
          [
            vuln('CVE-2026-9', 'CRITICAL', {
              ...fixedIn('2.0.0'),
              PkgName: 'effect',
              PkgPath: 'app/node_modules/effect/package.json',
            }),
          ],
        ),
      ),
      evaluate('cipherdrop-web:ci', report()),
    ];
    const text = formatResults(results);
    assert.match(text, /^image scan: cipherdrop-api:ci \(alpine 3\.24\.4\)$/m);
    assert.match(text, /CRITICAL 1 \(1 fixable\), HIGH 0 \(0 fixable\)/);
    assert.match(
      text,
      /CRITICAL CVE-2026-9 effect 1\.0\.0, fixed in 2\.0\.0: app\/node_modules\/effect\/package\.json {2}<- FAILS THE GATE/,
    );
    assert.match(text, /^image scan: FAIL, 1 fixable CRITICAL vulnerability:/m);
    assert.match(
      formatResults([results[1]]),
      /^image scan: PASS, no fixable CRITICAL vulnerability in 1 image\(s\)/m,
    );
  });

  test('text from the report cannot act as a workflow command', () => {
    const r = evaluate(
      'api',
      report([
        vuln('CVE-2026-10', 'HIGH', { PkgName: '::stop-commands::x', PkgPath: '##[error]boom' }),
      ]),
    );
    for (const line of formatResults([r]).split('\n')) {
      assert.doesNotMatch(line.trimStart(), /^::/);
      assert.doesNotMatch(line, /##\[/);
      assert.doesNotMatch(line, /::stop-commands::/);
    }
  });

  test('one annotation per failing vulnerability, none for reported ones', () => {
    const r = evaluate(
      'cipherdrop-api:ci',
      report([
        vuln('CVE-2026-11', 'CRITICAL', fixedIn('1.2.3')),
        vuln('CVE-2026-12', 'HIGH', fixedIn('1.0.1')),
      ]),
    );
    assert.deepEqual(annotations([r]), [
      '::error title=Fixable critical vulnerability::CVE-2026-11 in pkg 1.0.0 (cipherdrop-api:ci), fixed in 1.2.3',
    ]);
  });
});

describe('image scan plumbing', () => {
  test('imageSlug names the files after the repository part of a reference', () => {
    assert.equal(imageSlug('cipherdrop-api:ci'), 'cipherdrop-api');
    assert.equal(imageSlug('ghcr.io/owner/cipherdrop-web:1.2@sha256:abc'), 'cipherdrop-web');
    assert.equal(imageSlug('localhost:5000/cipherdrop-api'), 'cipherdrop-api');
    // Never a path: no directory part, no leading dots.
    assert.equal(imageSlug('../evil'), 'evil');
    assert.equal(imageSlug('..'), '_');
    assert.throws(() => imageSlug(''), /not an image reference/);
  });

  test('Trivy runs from an image pinned by digest, with the ignore file only when there is one', () => {
    assert.match(TRIVY_IMAGE, /^aquasec\/trivy:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/);
    const base = { outDir: '/o', cacheDir: '/c' };
    const plain = trivyArgs(base, ['image', '--input', '/scan/x.tar']);
    assert.deepEqual(plain.slice(0, 6), [
      'run',
      '--rm',
      '-v',
      '/o:/scan',
      '-v',
      '/c:/root/.cache/trivy',
    ]);
    assert.ok(plain.includes(TRIVY_IMAGE));
    assert.ok(!plain.some((a) => a.includes('docker.sock')), 'no Docker socket for Trivy');
    assert.ok(!plain.includes('--ignorefile'));
    const withIgnore = trivyArgs({ ...base, ignoreFile: '/repo/.trivyignore' }, ['image']);
    assert.ok(withIgnore.includes('/repo/.trivyignore:/policy/.trivyignore:ro'));
    assert.deepEqual(withIgnore.slice(-2), ['--ignorefile', '/policy/.trivyignore']);
  });
});

describe('image scan CLI', () => {
  test('--report: exit 0 for a passing report, 1 for a fixable CRITICAL, 2 for a broken report', () => {
    const pass = saved(
      'pass.trivy.json',
      report([], [vuln('CVE-2026-13', 'HIGH', fixedIn('2.0.0'))]),
    );
    const fail = saved(
      'fail.trivy.json',
      report([vuln('CVE-2026-14', 'CRITICAL', fixedIn('2.0.0'))]),
    );
    const broken = saved('broken.trivy.json', '{"SchemaVersion": 2, "Results": ');
    assert.equal(run(['--report', pass]).status, 0);
    const failed = run(['--report', pass, '--report', fail], { GITHUB_ACTIONS: 'true' });
    assert.equal(failed.status, 1);
    assert.match(failed.stdout, /::error title=Fixable critical vulnerability::CVE-2026-14/);
    const unreadable = run(['--report', broken]);
    assert.equal(unreadable.status, 2);
    assert.match(unreadable.stderr, /^image scan: /);
  });

  test('no image and no report is an error, not a pass', () => {
    const res = run([]);
    assert.equal(res.status, 2);
    assert.match(res.stderr, /no image given/);
  });

  test(
    'images: saves each one, writes its SBOM and report, deletes the tarball and judges the report',
    { skip: process.platform === 'win32' && 'the fake docker is a shebang script' },
    () => {
      // A fake `docker` first on the PATH: it records its arguments and writes what save and Trivy would.
      const bin = path.join(tmp, 'bin');
      mkdirSync(bin, { recursive: true });
      const fake = path.join(bin, 'docker');
      writeFileSync(
        fake,
        `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify(args) + '\\n');
if (args[0] === 'save') fs.writeFileSync(args[args.indexOf('-o') + 1], 'tar');
if (args[0] === 'run') {
  const mount = args.find((a) => a.endsWith(':/scan'));
  const out = args[args.indexOf('--output') + 1];
  const file = path.join(mount.slice(0, -':/scan'.length), path.basename(out));
  fs.writeFileSync(file, out.endsWith('.cdx.json') ? '{"bomFormat":"CycloneDX"}' : fs.readFileSync(process.env.FAKE_TRIVY_REPORT));
}
`,
      );
      chmodSync(fake, 0o755);
      const outDir = path.join(tmp, 'out');
      const log = path.join(tmp, 'docker.log');
      const env = (reportFile) => ({
        PATH: `${bin}${path.delimiter}${process.env.PATH}`,
        FAKE_DOCKER_LOG: log,
        FAKE_TRIVY_REPORT: reportFile,
        TRIVY_CACHE_DIR: path.join(tmp, 'cache'),
      });

      const passing = saved(
        'images-pass.json',
        report([], [vuln('CVE-2026-15', 'HIGH', fixedIn('1.0.1'))]),
      );
      const res = run(['--out', outDir, 'cipherdrop-api:ci', 'cipherdrop-web:ci'], env(passing));
      assert.equal(res.status, 0, res.stderr);
      for (const name of ['cipherdrop-api', 'cipherdrop-web']) {
        assert.ok(existsSync(path.join(outDir, `${name}.cdx.json`)));
        assert.ok(existsSync(path.join(outDir, `${name}.trivy.json`)));
        assert.ok(!existsSync(path.join(outDir, `${name}.tar`)), 'the tarball is deleted');
      }
      const calls = readFileSync(log, 'utf8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l));
      assert.deepEqual(calls[0], [
        'save',
        'cipherdrop-api:ci',
        '-o',
        path.join(outDir, 'cipherdrop-api.tar'),
      ]);
      const scans = calls.filter((c) => c[0] === 'run');
      assert.equal(scans.length, 4, 'an SBOM and a vulnerability scan per image');
      for (const c of scans) {
        assert.ok(c.includes(TRIVY_IMAGE));
        assert.ok(c.includes('--input'));
      }
      assert.ok(
        scans.some((c) => c.includes('cyclonedx') && c.includes('/scan/cipherdrop-web.cdx.json')),
      );
      assert.ok(
        scans.some((c) => c.includes('vuln') && c.includes('/scan/cipherdrop-api.trivy.json')),
      );

      const failing = saved(
        'images-fail.json',
        report([vuln('CVE-2026-16', 'CRITICAL', fixedIn('3.0.0'))]),
      );
      assert.equal(run(['--out', outDir, 'cipherdrop-api:ci'], env(failing)).status, 1);
    },
  );
});
