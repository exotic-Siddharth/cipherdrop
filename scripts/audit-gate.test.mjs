// Tests for the dependency audit gate (node:test, no dependencies): npm run test:scripts.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  annotations,
  collectAdvisories,
  evaluate,
  formatResult,
  validateAllowlist,
} from './audit-gate.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const gateScript = path.join(scriptDir, 'audit-gate.mjs');
const TODAY = '2026-11-20';

/** One advisory as npm audit v2 reports it in a package's `via` list. */
function via(name, ghsa, severity, title = `${name} advisory`) {
  return {
    source: 1,
    name,
    dependency: name,
    title,
    url: `https://github.com/advisories/${ghsa}`,
    severity,
    range: '<9',
  };
}

/** A report shaped like `npm audit --omit=dev --json` of this repository on 2026-11-20 (trimmed). */
function baseReport() {
  return {
    auditReportVersion: 2,
    vulnerabilities: {
      zod: {
        name: 'zod',
        severity: 'high',
        isDirect: true,
        via: [via('zod', 'GHSA-mrhx-c7xc-m3w5', 'high')],
        effects: ['@asteasolutions/zod-to-openapi'],
        range: '<4.6.6',
        nodes: ['node_modules/zod'],
        fixAvailable: { name: 'zod', version: '4.6.7', isSemVerMajor: true },
      },
      '@asteasolutions/zod-to-openapi': {
        name: '@asteasolutions/zod-to-openapi',
        severity: 'high',
        isDirect: true,
        via: ['zod'],
        effects: [],
        range: '<=8.0.0-beta.4',
        nodes: ['node_modules/@asteasolutions/zod-to-openapi'],
        fixAvailable: {
          name: '@asteasolutions/zod-to-openapi',
          version: '9.1.0',
          isSemVerMajor: true,
        },
      },
      'deepmerge-ts': {
        name: 'deepmerge-ts',
        severity: 'high',
        isDirect: false,
        via: [via('deepmerge-ts', 'GHSA-ggr8-5vv4-36mx', 'high')],
        effects: ['@prisma/config'],
        range: '<8.0.0',
        nodes: ['node_modules/deepmerge-ts'],
        fixAvailable: { name: 'prisma', version: '7.10.1', isSemVerMajor: true },
      },
      '@prisma/config': {
        name: '@prisma/config',
        severity: 'high',
        isDirect: false,
        via: ['deepmerge-ts'],
        effects: ['prisma'],
        range: '>=6.13.0-dev.1',
        nodes: ['node_modules/@prisma/config'],
        fixAvailable: { name: 'prisma', version: '7.10.1', isSemVerMajor: true },
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 4, critical: 0, total: 4 },
      dependencies: { prod: 310, dev: 358, optional: 115, peer: 0, peerOptional: 0, total: 756 },
    },
  };
}

function entry(id, pkg, reviewBy = '2027-02-20') {
  return { id, package: pkg, reason: 'reviewed: does not reach request data', reviewBy };
}

function baseAllowlist() {
  return {
    advisories: [entry('GHSA-mrhx-c7xc-m3w5', 'zod'), entry('GHSA-ggr8-5vv4-36mx', 'deepmerge-ts')],
  };
}

function addVulnerability(report, name, ghsa, severity) {
  report.vulnerabilities[name] = {
    name,
    severity,
    isDirect: true,
    via: [via(name, ghsa, severity)],
    effects: [],
    range: '<9',
    nodes: [`node_modules/${name}`],
    fixAvailable: true,
  };
  return report;
}

describe('evaluate', () => {
  test('passes when every high advisory is allowlisted and current', () => {
    const result = evaluate(baseReport(), baseAllowlist(), TODAY);
    assert.equal(result.ok, true);
    assert.deepEqual(
      result.allowed.map((a) => a.advisory.id),
      ['GHSA-ggr8-5vv4-36mx', 'GHSA-mrhx-c7xc-m3w5'],
    );
    assert.match(formatResult(result, TODAY), /^PASS: 2 high\/critical advisories/m);
  });

  test('a package vulnerable only through another one is not an advisory of its own', () => {
    // @prisma/config and zod-to-openapi have string `via` entries: covered by deepmerge-ts and zod.
    const advisories = collectAdvisories(baseReport());
    assert.deepEqual(advisories.map((a) => a.package).sort(), ['deepmerge-ts', 'zod']);
  });

  for (const severity of ['high', 'critical']) {
    test(`fails on a new ${severity} advisory that is not on the allowlist`, () => {
      const report = addVulnerability(baseReport(), 'express', 'GHSA-aaaa-bbbb-cccc', severity);
      const result = evaluate(report, baseAllowlist(), TODAY);
      assert.equal(result.ok, false);
      assert.deepEqual(
        result.unlisted.map((a) => [a.id, a.package, a.severity]),
        [['GHSA-aaaa-bbbb-cccc', 'express', severity]],
      );
      const text = formatResult(result, TODAY);
      assert.match(text, new RegExp(`NEW +${severity} +GHSA-aaaa-bbbb-cccc +express`));
      assert.match(text, /^FAIL:/m);
    });
  }

  test('an allowlisted id filed against another package does not cover it', () => {
    const report = addVulnerability(baseReport(), 'express', 'GHSA-mrhx-c7xc-m3w5', 'high');
    const result = evaluate(report, baseAllowlist(), TODAY);
    assert.equal(result.ok, false);
    assert.deepEqual(
      result.unlisted.map((a) => a.package),
      ['express'],
    );
  });

  test('low and moderate advisories are reported but do not fail the gate', () => {
    const report = addVulnerability(baseReport(), 'qs', 'GHSA-dddd-eeee-ffff', 'moderate');
    addVulnerability(report, 'debug', 'GHSA-gggg-hhhh-jjjj', 'low');
    const result = evaluate(report, baseAllowlist(), TODAY);
    assert.equal(result.ok, true);
    assert.deepEqual(result.ungated.map((a) => a.package).sort(), ['debug', 'qs']);
    assert.match(formatResult(result, TODAY), /info +moderate +GHSA-dddd-eeee-ffff +qs/);
  });

  test('an advisory with a severity npm does not normally report fails closed', () => {
    const report = addVulnerability(baseReport(), 'odd', 'GHSA-ssss-tttt-uuuu', 'severe');
    delete report.vulnerabilities.odd.via[0].severity;
    report.vulnerabilities.odd.severity = 'severe';
    const result = evaluate(report, baseAllowlist(), TODAY);
    assert.equal(result.ok, false);
    assert.deepEqual(
      result.unlisted.map((a) => [a.package, a.severity]),
      [['odd', 'severe']],
    );
  });

  test('fails on a stale entry whose advisory is no longer reported', () => {
    const report = baseReport();
    delete report.vulnerabilities['deepmerge-ts'];
    const result = evaluate(report, baseAllowlist(), TODAY);
    assert.equal(result.ok, false);
    assert.deepEqual(
      result.stale.map((e) => e.id),
      ['GHSA-ggr8-5vv4-36mx'],
    );
    assert.match(formatResult(result, TODAY), /STALE +GHSA-ggr8-5vv4-36mx +deepmerge-ts/);
  });

  test('an entry whose advisory dropped below high is stale too', () => {
    const report = baseReport();
    report.vulnerabilities.zod.via[0].severity = 'moderate';
    const result = evaluate(report, baseAllowlist(), TODAY);
    assert.equal(result.ok, false);
    assert.deepEqual(
      result.stale.map((e) => e.package),
      ['zod'],
    );
  });

  test('fails once an entry is past its reviewBy date, and not before', () => {
    const allowlist = baseAllowlist();
    allowlist.advisories[0].reviewBy = '2026-11-19';
    const result = evaluate(baseReport(), allowlist, TODAY);
    assert.equal(result.ok, false);
    assert.deepEqual(
      result.expired.map((e) => e.id),
      ['GHSA-mrhx-c7xc-m3w5'],
    );
    assert.match(formatResult(result, TODAY), /EXPIRED +high +GHSA-mrhx-c7xc-m3w5/);

    allowlist.advisories[0].reviewBy = TODAY;
    assert.equal(evaluate(baseReport(), allowlist, TODAY).ok, true);
  });

  test('fails closed on an npm error report or anything that is not an audit v2 report', () => {
    const allowlist = baseAllowlist();
    const npmError = {
      error: { code: 'ENOLOCK', summary: 'This command requires an existing lockfile.' },
    };
    assert.throws(() => evaluate(npmError, allowlist, TODAY), /npm audit failed: ENOLOCK/);
    assert.throws(
      () => evaluate({ auditReportVersion: 1 }, allowlist, TODAY),
      /not an npm audit v2/,
    );
    assert.throws(() => evaluate(null, allowlist, TODAY), /not an npm audit v2/);
    const nullVulns = { auditReportVersion: 2, vulnerabilities: null };
    assert.throws(() => evaluate(nullVulns, allowlist, TODAY), /not an npm audit v2/);
  });

  test('advisory text cannot inject a workflow command line', () => {
    const report = addVulnerability(baseReport(), 'evil', 'GHSA-kkkk-mmmm-nnnn', 'high');
    report.vulnerabilities.evil.via[0].title = 'bad\n::add-mask::secret\r\n100%';
    const result = evaluate(report, baseAllowlist(), TODAY);
    const lines = [...formatResult(result, TODAY).split('\n'), ...annotations(result)];
    assert.ok(lines.every((line) => !line.startsWith('::') || line.startsWith('::error title=')));
    assert.ok(annotations(result).some((line) => line.endsWith('bad ::add-mask::secret 100%25')));
  });
});

describe('validateAllowlist', () => {
  const cases = [
    ['no advisories array', {}, /"advisories" array/],
    ['an id that is not a GHSA id', { advisories: [entry('CVE-2026-0001', 'zod')] }, /GHSA id/],
    [
      'a missing reason',
      { advisories: [{ ...entry('GHSA-mrhx-c7xc-m3w5', 'zod'), reason: ' ' }] },
      /"reason"/,
    ],
    [
      'a missing package',
      { advisories: [{ ...entry('GHSA-mrhx-c7xc-m3w5', 'zod'), package: undefined }] },
      /"package"/,
    ],
    [
      'an impossible date',
      { advisories: [entry('GHSA-mrhx-c7xc-m3w5', 'zod', '2027-02-30')] },
      /real date/,
    ],
    [
      'a date in another format',
      { advisories: [entry('GHSA-mrhx-c7xc-m3w5', 'zod', '20/02/2027')] },
      /real date/,
    ],
    [
      'a duplicate entry',
      { advisories: [entry('GHSA-mrhx-c7xc-m3w5', 'zod'), entry('GHSA-mrhx-c7xc-m3w5', 'zod')] },
      /duplicate/,
    ],
  ];
  for (const [name, allowlist, message] of cases) {
    test(`rejects ${name}`, () => assert.throws(() => validateAllowlist(allowlist), message));
  }

  test('the committed allowlist is well-formed and every entry has a reason and a review date', () => {
    const committed = JSON.parse(
      readFileSync(path.join(scriptDir, 'audit-allowlist.json'), 'utf8'),
    );
    const entries = validateAllowlist(committed);
    assert.ok(entries.length > 0);
  });
});

describe('command line', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'audit-gate-'));
  after(() => rmSync(dir, { recursive: true, force: true }));

  function run(report, allowlist) {
    const input = path.join(dir, 'audit.json');
    const list = path.join(dir, 'allowlist.json');
    writeFileSync(input, JSON.stringify(report));
    writeFileSync(list, JSON.stringify(allowlist));
    return spawnSync(
      process.execPath,
      [gateScript, '--input', input, '--allowlist', list, '--today', TODAY],
      { encoding: 'utf8', env: { ...process.env, GITHUB_ACTIONS: 'true' } },
    );
  }

  test('exits 0 on a clean result', () => {
    const res = run(baseReport(), baseAllowlist());
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /^PASS/m);
  });

  test('exits 1 on a new high, with a GitHub annotation', () => {
    const res = run(
      addVulnerability(baseReport(), 'express', 'GHSA-aaaa-bbbb-cccc', 'high'),
      baseAllowlist(),
    );
    assert.equal(res.status, 1);
    assert.match(res.stdout, /^::error title=New high advisory::GHSA-aaaa-bbbb-cccc in express/m);
  });

  test('exits 1 on a stale entry, with a GitHub annotation', () => {
    const allowlist = baseAllowlist();
    allowlist.advisories.push(entry('GHSA-pppp-qqqq-rrrr', 'left-pad'));
    const res = run(baseReport(), allowlist);
    assert.equal(res.status, 1);
    assert.match(res.stdout, /^::error title=Stale audit allowlist entry::GHSA-pppp-qqqq-rrrr/m);
  });

  test('exits 1 when the input cannot be judged', () => {
    const res = run(
      { error: { code: 'EAI_AGAIN', summary: 'registry unreachable' } },
      baseAllowlist(),
    );
    assert.equal(res.status, 1);
    assert.match(res.stderr, /audit gate: npm audit failed: EAI_AGAIN/);
  });
});
