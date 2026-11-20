#!/usr/bin/env node
/**
 * Dependency audit gate (docs/SECURITY.md section 7): `npm audit --omit=dev --json`, judged against the reviewed
 * exceptions in scripts/audit-allowlist.json.
 *
 * Fails (exit 1) when:
 *   - a high or critical advisory is not on the allowlist (a NEW advisory must be fixed or reviewed and listed);
 *   - an allowlist entry matches no high or critical advisory any more (STALE: remove it, so an exception never
 *     outlives the problem it covered);
 *   - an entry's reviewBy date has passed (EXPIRED: re-read the reason, then extend the date or fix the dependency);
 *   - the audit itself fails or its output is not an npm audit v2 report (fail closed, never pass on no data);
 *   - the allowlist is malformed.
 * Low and moderate advisories are listed in the summary and never fail the gate.
 *
 * An advisory is identified by its GHSA id and the package it is filed against. A package that is only vulnerable
 * because it depends on a vulnerable one (a string `via` in the report) is not an advisory of its own: the
 * summary lists it under "also affects", and fixing or listing the root advisory covers it. A severity npm does not
 * normally report is treated as gated, so unexpected data fails the gate instead of slipping under it.
 *
 * Usage: npm run audit:gate [-- --input <audit.json>] [--allowlist <file>] [--today YYYY-MM-DD]
 *   --input      judge a saved `npm audit --omit=dev --json` output instead of running npm (tests, offline review)
 *   --allowlist  default: scripts/audit-allowlist.json next to this script
 *   --today      the date reviewBy is compared with (default: the current UTC date)
 * Plain ESM with no dependencies, so it runs before (or without) `npm ci`: npm audit reads package-lock.json.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');

export const GATED_SEVERITIES = new Set(['high', 'critical']);
const SEVERITY_ORDER = ['critical', 'high', 'moderate', 'low', 'info'];
const GHSA_RE = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;
const GHSA_ID_RE = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Throws on anything that is not a well-formed allowlist; returns its entries. */
export function validateAllowlist(allowlist) {
  if (!allowlist || !Array.isArray(allowlist.advisories)) {
    throw new Error('allowlist: expected an object with an "advisories" array');
  }
  const seen = new Set();
  for (const [i, entry] of allowlist.advisories.entries()) {
    const where = `allowlist advisories[${i}]`;
    if (typeof entry?.id !== 'string' || !GHSA_ID_RE.test(entry.id)) {
      throw new Error(`${where}: "id" must be a GHSA id (GHSA-xxxx-xxxx-xxxx)`);
    }
    for (const key of ['package', 'reason', 'reviewBy']) {
      if (typeof entry[key] !== 'string' || entry[key].trim() === '') {
        throw new Error(`${where} (${entry.id}): "${key}" must be a non-empty string`);
      }
    }
    if (!isValidDate(entry.reviewBy)) {
      throw new Error(`${where} (${entry.id}): "reviewBy" must be a real date as YYYY-MM-DD`);
    }
    const key = advisoryKey(entry.id, entry.package);
    if (seen.has(key))
      throw new Error(`${where}: duplicate entry for ${entry.id} in ${entry.package}`);
    seen.add(key);
  }
  return allowlist.advisories;
}

/** Flattens an npm audit v2 report into one record per advisory; throws when the report is unusable. */
export function collectAdvisories(report) {
  if (report && typeof report === 'object' && 'error' in report) {
    const err = report.error ?? {};
    throw new Error(`npm audit failed: ${err.code ?? 'error'} ${err.summary ?? ''}`.trim());
  }
  if (
    report?.auditReportVersion !== 2 ||
    typeof report.vulnerabilities !== 'object' ||
    report.vulnerabilities === null
  ) {
    throw new Error(
      'not an npm audit v2 report (expected auditReportVersion 2 and a vulnerabilities object)',
    );
  }
  const byKey = new Map();
  for (const [pkg, vuln] of Object.entries(report.vulnerabilities)) {
    for (const via of vuln.via ?? []) {
      // A string names another vulnerable package this one depends on; that advisory is reported there.
      if (typeof via !== 'object' || via === null) continue;
      const name = via.name ?? pkg;
      // Without a GHSA id (an npm-only advisory) the numeric source id still identifies it uniquely.
      const id = (GHSA_RE.exec(via.url ?? '')?.[0] ?? `npm-${via.source}`).replace(
        /^ghsa/i,
        'GHSA',
      );
      const key = advisoryKey(id, name);
      if (byKey.has(key)) continue;
      byKey.set(key, {
        id: clean(id),
        package: clean(name),
        severity: clean(via.severity ?? vuln.severity ?? 'unknown'),
        title: clean(via.title),
        url: clean(via.url),
        range: clean(via.range ?? vuln.range),
        fix: describeFix(vuln.fixAvailable),
        dependents: dependentsOf(report.vulnerabilities, pkg),
      });
    }
  }
  return [...byKey.values()].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      a.package.localeCompare(b.package) ||
      a.id.localeCompare(b.id),
  );
}

/** The gate's decision. `today` is a YYYY-MM-DD string (UTC). */
export function evaluate(report, allowlist, today) {
  const entries = validateAllowlist(allowlist);
  const advisories = collectAdvisories(report);
  const gated = advisories.filter((a) => isGated(a.severity));
  const entryByKey = new Map(entries.map((e) => [advisoryKey(e.id, e.package), e]));
  const gatedKeys = new Set(gated.map((a) => advisoryKey(a.id, a.package)));

  const allowed = [];
  const unlisted = [];
  for (const advisory of gated) {
    const entry = entryByKey.get(advisoryKey(advisory.id, advisory.package));
    if (entry) allowed.push({ advisory, entry });
    else unlisted.push(advisory);
  }
  const stale = entries.filter((e) => !gatedKeys.has(advisoryKey(e.id, e.package)));
  // A stale entry is reported as stale only: its date no longer matters.
  const expired = allowed.filter(({ entry }) => entry.reviewBy < today).map(({ entry }) => entry);
  const ungated = advisories.filter((a) => !isGated(a.severity));

  return {
    ok: unlisted.length === 0 && stale.length === 0 && expired.length === 0,
    advisories,
    allowed,
    unlisted,
    stale,
    expired,
    ungated,
    metadata: report.metadata ?? {},
  };
}

/** Human-readable summary, one line per finding (the CI log is the report). */
export function formatResult(result, today) {
  const lines = [];
  const counts = result.metadata.vulnerabilities ?? {};
  const deps = result.metadata.dependencies ?? {};
  const countText = SEVERITY_ORDER.filter((s) => counts[s])
    .map((s) => `${s} ${counts[s]}`)
    .join(', ');
  lines.push(
    `npm audit --omit=dev: ${result.advisories.length} advisories in ${counts.total ?? '?'} vulnerable ` +
      `packages${countText ? ` (${countText})` : ''}; ${deps.prod ?? '?'} production dependencies checked`,
  );
  lines.push(`gate: high and critical advisories must be on the allowlist (today ${today})`);
  lines.push('');

  const describe = (a) => {
    const via = a.dependents.length ? `; also affects ${a.dependents.join(', ')}` : '';
    return [
      `    ${a.title || '(no title)'}`,
      `    ${a.url || '(no url)'}; affected ${a.range || '?'}; fix: ${a.fix}${via}`,
    ];
  };
  for (const a of result.unlisted) {
    lines.push(`  NEW      ${a.severity.padEnd(8)} ${a.id}  ${a.package}`, ...describe(a));
  }
  for (const { advisory: a, entry } of result.allowed) {
    const state = result.expired.includes(entry) ? 'EXPIRED ' : 'allowed ';
    lines.push(
      `  ${state} ${a.severity.padEnd(8)} ${a.id}  ${a.package}  (review by ${entry.reviewBy})`,
      ...describe(a),
    );
  }
  for (const entry of result.stale) {
    lines.push(
      `  STALE             ${entry.id}  ${entry.package}  (allowlisted, but no longer reported as high or critical)`,
    );
  }
  for (const a of result.ungated) {
    lines.push(`  info     ${a.severity.padEnd(8)} ${a.id}  ${a.package}  (below the gate)`);
  }
  if (result.advisories.length === 0 && result.stale.length === 0) lines.push('  no advisories');
  lines.push('');

  if (result.ok) {
    lines.push(
      `PASS: ${count(result.allowed.length, 'high/critical advisory', 'high/critical advisories')}, all on the ` +
        'allowlist with a current review date.',
    );
  } else {
    lines.push('FAIL:');
    if (result.unlisted.length) {
      lines.push(
        `  ${count(result.unlisted.length, 'high/critical advisory is', 'high/critical advisories are')} not on ` +
          'the allowlist: upgrade the dependency, or ' +
          'review the advisory and add it to scripts/audit-allowlist.json with a reason and a reviewBy date.',
      );
    }
    if (result.stale.length) {
      lines.push(
        `  ${count(result.stale.length, 'allowlist entry matches', 'allowlist entries match')} nothing: remove ` +
          'it from scripts/audit-allowlist.json ' +
          '(and update docs/SECURITY.md section 7).',
      );
    }
    if (result.expired.length) {
      lines.push(
        `  ${count(result.expired.length, 'allowlist entry is', 'allowlist entries are')} past the reviewBy ` +
          'date: re-review, then fix the dependency or move the date.',
      );
    }
  }
  return lines.join('\n');
}

/** GitHub Actions annotations, so a failure is visible on the checks page without opening the log. */
export function annotations(result) {
  const out = [];
  for (const a of result.unlisted) {
    out.push(annotation(`New ${a.severity} advisory`, `${a.id} in ${a.package}: ${a.title}`));
  }
  for (const e of result.stale) {
    out.push(
      annotation('Stale audit allowlist entry', `${e.id} in ${e.package} no longer matches`),
    );
  }
  for (const e of result.expired) {
    out.push(
      annotation(
        'Expired audit allowlist entry',
        `${e.id} in ${e.package} (review by ${e.reviewBy})`,
      ),
    );
  }
  return out;
}

/** One `::error::` workflow command; `%` and line breaks are escaped as the runner expects. */
function annotation(title, message) {
  const escape = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  return `::error title=${escape(title).replace(/[,:]/g, ' ')}::${escape(message)}`;
}

/** Runs npm audit and returns its parsed JSON report (npm exits 1 when it finds anything: that is not an error). */
export function runNpmAudit(cwd = repoRoot) {
  const args = ['audit', '--omit=dev', '--json'];
  // Under `npm run`, npm_execpath is npm's own CLI script: running it with this Node needs no shell (npm.cmd on
  // Windows cannot be spawned without one). Run directly (or from another package manager), use `npm` on the PATH.
  const npmCli = process.env.npm_execpath;
  const [cmd, cmdArgs, shell] =
    npmCli && /^npm-cli\.[cm]?js$/.test(path.basename(npmCli))
      ? [process.execPath, [npmCli, ...args], false]
      : ['npm', args, process.platform === 'win32'];
  const res = spawnSync(cmd, cmdArgs, {
    cwd,
    encoding: 'utf8',
    shell,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.error) throw new Error(`could not run npm audit: ${res.error.message}`);
  try {
    return JSON.parse(res.stdout);
  } catch {
    throw new Error(
      `npm audit exited ${res.status} without a JSON report:\n${res.stderr || res.stdout}`.trim(),
    );
  }
}

/**
 * Report text comes from the advisory database: control characters are dropped so that no title can start a new
 * log line (a line beginning with `::` is a workflow command on GitHub Actions).
 */
function clean(value) {
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  const controlChars = /[\u0000-\u001f\u007f]+/g;
  return String(value ?? '')
    .replace(controlChars, ' ')
    .trim();
}

function isGated(severity) {
  return GATED_SEVERITIES.has(severity) || !SEVERITY_ORDER.includes(severity);
}

function count(n, singular, plural) {
  return `${n} ${n === 1 ? singular : plural}`;
}

function advisoryKey(id, pkg) {
  return `${id.toUpperCase()}|${pkg}`;
}

function severityRank(severity) {
  const i = SEVERITY_ORDER.indexOf(severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

function isValidDate(value) {
  if (!DATE_RE.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

function describeFix(fixAvailable) {
  if (fixAvailable === true) return 'npm audit fix';
  if (!fixAvailable) return 'none available';
  const major = fixAvailable.isSemVerMajor ? ', semver-major' : '';
  return `${fixAvailable.name} ${fixAvailable.version}${major}`;
}

/** The vulnerable packages that are only vulnerable through `pkg` (the report's `effects`), for context. */
function dependentsOf(vulnerabilities, pkg) {
  return [...(vulnerabilities[pkg]?.effects ?? [])].sort();
}

function main() {
  const { values } = parseArgs({
    options: {
      input: { type: 'string' },
      allowlist: { type: 'string', default: path.join(scriptDir, 'audit-allowlist.json') },
      today: { type: 'string', default: new Date().toISOString().slice(0, 10) },
    },
  });
  if (!isValidDate(values.today)) throw new Error('--today must be a date as YYYY-MM-DD');
  const allowlist = JSON.parse(readFileSync(values.allowlist, 'utf8'));
  const report = values.input ? JSON.parse(readFileSync(values.input, 'utf8')) : runNpmAudit();
  const result = evaluate(report, allowlist, values.today);
  console.log(formatResult(result, values.today));
  if (process.env.GITHUB_ACTIONS === 'true')
    for (const line of annotations(result)) console.log(line);
  return result.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    process.exitCode = main();
  } catch (err) {
    // Fail closed: an audit that could not be judged is a failed gate, not a pass.
    const message = err instanceof Error ? err.message : String(err);
    console.error(`audit gate: ${message}`);
    if (process.env.GITHUB_ACTIONS === 'true') console.log(annotation('Audit gate error', message));
    process.exitCode = 1;
  }
}
