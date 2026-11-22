#!/usr/bin/env node
/**
 * Image vulnerability gate and SBOM for the production images (CI job prod-stack): each image is scanned by Trivy,
 * run from its official image pinned by digest, and the report is judged here.
 *
 * Policy:
 *   - a CRITICAL vulnerability that has a fixed version FAILS (exit 1): a fix exists, so the base image digest (its
 *     Dependabot pull request) or the dependency is bumped before merging;
 *   - HIGH vulnerabilities, and CRITICAL ones with no fix yet, are REPORTED (the list below and the saved report)
 *     and never fail: nothing can be done about an unfixed one but wait, and HIGH findings are mostly in tooling the
 *     running server never calls (the npm CLI bundled with the node image). The npm dependencies themselves are
 *     gated at HIGH by the dependency audit (scripts/audit-gate.mjs).
 * An exception, while a fix is prepared, goes into .trivyignore at the repository root (one ID per line, a comment
 * with the reason, and `exp:YYYY-MM-DD` so it lapses); Trivy drops the IDs listed there from the report.
 *
 * For each image it writes, into --out:
 *   <name>.cdx.json    CycloneDX SBOM: every OS and npm package in the image (inventory only, no vulnerability data)
 *   <name>.trivy.json  Trivy's vulnerability report, every severity
 * Fails closed (exit 2) when docker or Trivy fails, or a report is not a Trivy JSON report: never a pass on no data.
 *
 * Usage: node scripts/image-scan.mjs [--out image-scan] <image>...
 *        node scripts/image-scan.mjs --report <file.trivy.json>...   judge saved reports (tests, offline review)
 * Needs Docker. The Trivy cache (vulnerability database) lives in $TRIVY_CACHE_DIR, default
 * $RUNNER_TEMP/trivy-cache or the OS temp directory.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { annotation, inertLine } from './audit-gate.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..');

/**
 * Trivy 0.76.2, pinned by its multi-platform index digest (resolved with `docker buildx imagetools inspect`). An
 * image, not aquasecurity/trivy-action: a digest cannot be moved, where an action's tags can. Dependabot does not
 * read this file: bump the tag and digest together, by hand.
 */
export const TRIVY_IMAGE =
  'aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const REPORTED = new Set(['CRITICAL', 'HIGH']);

/** The file name for an image reference: `ghcr.io/x/cipherdrop-api:ci@sha256:...` -> `cipherdrop-api`. */
export function imageSlug(ref) {
  const noDigest = ref.split('@')[0];
  const lastSlash = noDigest.lastIndexOf('/');
  const lastColon = noDigest.lastIndexOf(':');
  const repo = lastColon > lastSlash ? noDigest.slice(0, lastColon) : noDigest;
  const slug = repo
    .slice(repo.lastIndexOf('/') + 1)
    .replace(/[^a-z0-9._-]/gi, '_')
    .replace(/^\.+/, '_');
  if (!slug) throw new Error(`not an image reference: ${JSON.stringify(ref)}`);
  return slug;
}

/** Whether a vulnerability has a fixed version (Trivy's `--ignore-unfixed` keeps exactly these). */
export function isFixable(v) {
  return v.Status === 'fixed' || Boolean(v.FixedVersion);
}

/**
 * Every vulnerability of a Trivy JSON report (schema version 2) with what the policy needs. Throws on anything
 * else, so an unreadable report fails the gate.
 */
export function collectVulnerabilities(report) {
  if (!report || typeof report !== 'object' || report.SchemaVersion !== 2) {
    throw new Error('not a Trivy JSON report (SchemaVersion 2)');
  }
  if (report.Results !== undefined && !Array.isArray(report.Results)) {
    throw new Error('Trivy report: Results is not an array');
  }
  const out = [];
  for (const result of report.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      const severity = SEVERITIES.includes(v.Severity) ? v.Severity : 'UNKNOWN';
      out.push({
        id: String(v.VulnerabilityID ?? ''),
        pkg: String(v.PkgName ?? ''),
        installed: String(v.InstalledVersion ?? ''),
        fixed: String(v.FixedVersion ?? ''),
        severity,
        fixable: isFixable(v),
        where: String(v.PkgPath || result.Target || ''),
      });
    }
  }
  return out;
}

/** The verdict for one image's report. */
export function evaluate(image, report) {
  const vulns = collectVulnerabilities(report);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, { all: 0, fixable: 0 }]));
  for (const v of vulns) {
    counts[v.severity].all += 1;
    if (v.fixable) counts[v.severity].fixable += 1;
  }
  const rank = (v) => SEVERITIES.indexOf(v.severity);
  const reported = vulns
    .filter((v) => REPORTED.has(v.severity))
    .sort(
      (a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id) || a.where.localeCompare(b.where),
    );
  const failing = reported.filter((v) => v.severity === 'CRITICAL' && v.fixable);
  const os = report.Metadata?.OS ? `${report.Metadata.OS.Family} ${report.Metadata.OS.Name}` : '';
  return { image, os, counts, reported, failing, ok: failing.length === 0 };
}

/** The plain-text report of every image, each line made inert for the Actions log. */
export function formatResults(results) {
  const lines = [];
  for (const r of results) {
    lines.push(`image scan: ${r.image}${r.os ? ` (${r.os})` : ''}`);
    lines.push(
      '  ' +
        SEVERITIES.map((s) => `${s} ${r.counts[s].all} (${r.counts[s].fixable} fixable)`).join(
          ', ',
        ),
    );
    for (const v of r.reported) {
      const fix = v.fixed ? `fixed in ${v.fixed}` : 'no fix yet';
      const gate = v.severity === 'CRITICAL' && v.fixable ? '  <- FAILS THE GATE' : '';
      lines.push(
        `  ${v.severity.padEnd(8)} ${v.id} ${v.pkg} ${v.installed}, ${fix}: ${v.where}${gate}`,
      );
    }
  }
  const failing = results.reduce((n, r) => n + r.failing.length, 0);
  lines.push(
    failing === 0
      ? `image scan: PASS, no fixable CRITICAL vulnerability in ${results.length} image(s); HIGH and unfixed ones are listed above for review`
      : `image scan: FAIL, ${failing} fixable CRITICAL vulnerabilit${failing === 1 ? 'y' : 'ies'}: bump the base image digest or the dependency (or add a dated .trivyignore entry with the reason)`,
  );
  return lines.map(inertLine).join('\n');
}

/** GitHub Actions annotations for the failing vulnerabilities. */
export function annotations(results) {
  return results.flatMap((r) =>
    r.failing.map((v) =>
      annotation(
        'Fixable critical vulnerability',
        `${v.id} in ${v.pkg} ${v.installed} (${r.image}), fixed in ${v.fixed || 'a newer release'}`,
      ),
    ),
  );
}

/** The docker arguments of one Trivy run: the output directory at /scan, the cache, the ignore file if any. */
export function trivyArgs({ outDir, cacheDir, ignoreFile }, trivyCommand) {
  const args = ['run', '--rm', '-v', `${outDir}:/scan`, '-v', `${cacheDir}:/root/.cache/trivy`];
  args.push('-e', 'TRIVY_NO_PROGRESS=true', '-e', 'TRIVY_DISABLE_VEX_NOTICE=true');
  if (ignoreFile) args.push('-v', `${ignoreFile}:/policy/.trivyignore:ro`);
  args.push(TRIVY_IMAGE, ...trivyCommand);
  if (ignoreFile) args.push('--ignorefile', '/policy/.trivyignore');
  return args;
}

function docker(args) {
  const res = spawnSync('docker', args, { stdio: ['ignore', 'inherit', 'inherit'] });
  if (res.error) throw new Error(`could not run docker: ${res.error.message}`);
  if (res.status !== 0)
    throw new Error(`docker ${args.slice(0, 2).join(' ')} ... exited ${res.status}`);
}

/** Saves the image, writes its SBOM and its vulnerability report, and returns the parsed report. */
export function scanImage(image, { outDir, cacheDir, ignoreFile }) {
  const name = imageSlug(image);
  const tar = path.join(outDir, `${name}.tar`);
  const opts = { outDir, cacheDir, ignoreFile };
  docker(['save', image, '-o', tar]);
  try {
    // --input reads the saved image: Trivy needs no access to the Docker socket.
    docker(
      trivyArgs({ ...opts, ignoreFile: undefined }, [
        'image',
        '--input',
        `/scan/${name}.tar`,
        '--format',
        'cyclonedx',
        '--output',
        `/scan/${name}.cdx.json`,
      ]),
    );
    docker(
      trivyArgs(opts, [
        'image',
        '--input',
        `/scan/${name}.tar`,
        '--scanners',
        'vuln',
        '--format',
        'json',
        '--output',
        `/scan/${name}.trivy.json`,
      ]),
    );
  } finally {
    rmSync(tar, { force: true });
  }
  return JSON.parse(readFileSync(path.join(outDir, `${name}.trivy.json`), 'utf8'));
}

function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      out: { type: 'string', default: 'image-scan' },
      report: { type: 'string', multiple: true },
    },
  });
  let results;
  if (values.report?.length) {
    if (positionals.length) throw new Error('give either images or --report files, not both');
    results = values.report.map((file) => evaluate(file, JSON.parse(readFileSync(file, 'utf8'))));
  } else {
    if (positionals.length === 0)
      throw new Error('no image given (usage: image-scan.mjs <image>...)');
    const outDir = path.resolve(values.out);
    mkdirSync(outDir, { recursive: true });
    const cacheDir = path.resolve(
      process.env.TRIVY_CACHE_DIR ?? path.join(process.env.RUNNER_TEMP ?? tmpdir(), 'trivy-cache'),
    );
    mkdirSync(cacheDir, { recursive: true });
    const ignore = path.join(repoRoot, '.trivyignore');
    const ignoreFile = existsSync(ignore) ? ignore : undefined;
    results = positionals.map((image) =>
      evaluate(image, scanImage(image, { outDir, cacheDir, ignoreFile })),
    );
  }
  console.log(formatResults(results));
  if (process.env.GITHUB_ACTIONS === 'true')
    for (const line of annotations(results)) console.log(line);
  return results.every((r) => r.ok) ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    process.exitCode = main();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(
      `image scan: ${message}`
        .split(/\r\n|\r|\n/)
        .map(inertLine)
        .join('\n'),
    );
    if (process.env.GITHUB_ACTIONS === 'true') console.log(annotation('Image scan error', message));
    process.exitCode = 2;
  }
}
