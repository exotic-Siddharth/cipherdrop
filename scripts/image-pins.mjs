/**
 * Image references that must stay identical, and that no tool keeps identical. Checked by scripts/image-pins.test.mjs
 * (`npm run test:scripts`, which audit.yml runs on every push and pull request):
 *
 *   - CI tests against the bytes production runs. Every reference in .github/workflows to an image that
 *     docker-compose.prod.yml uses (the Postgres and Redis service containers, the MinIO `docker run`) must be the
 *     compose file's exact reference, tag and digest. Dependabot's docker-compose entry rewrites only the compose
 *     file (neither its github-actions nor its docker entry reads jobs.*.services.*.image), so its pull request fails
 *     here until the workflows are moved with it.
 *   - An image that more than one Dockerfile builds on (node:22-alpine in both) has the same reference in each. The
 *     Dependabot group moves them together; a hand edit of one would not.
 *
 * A line reader, not a YAML parser: the audit job installs nothing, so this uses Node built-ins only. It finds image
 * references wherever they are written (an `image:` value, an argument of `docker run`) and skips comment lines.
 */
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

/** The repository of an image reference: `docker.io/library/postgres:16@sha256:...` -> `postgres`. */
export function repositoryOf(ref) {
  const at = ref.indexOf('@');
  const nameAndTag = at === -1 ? ref : ref.slice(0, at);
  // A registry port (`host:5000/name`) is before the last slash; the tag's colon is after it.
  const colon = nameAndTag.indexOf(':', nameAndTag.lastIndexOf('/') + 1);
  const name = colon === -1 ? nameAndTag : nameAndTag.slice(0, colon);
  return name.replace(/^docker\.io\//, '').replace(/^library\//, '');
}

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** `- image: x`, `image: 'x'`, `image: x # comment` -> x. */
const IMAGE_KEY = /^\s*(?:-\s+)?image:\s*['"]?([^'"\s#]+)/;

const isComment = (line) => line.trimStart().startsWith('#');

/**
 * The third-party images of a compose file, by repository: every `image:` value except the stack's own images, which
 * are built locally (their reference holds a ${...} variable). A repository named twice must be named identically.
 */
export function composeImages(file, text) {
  const images = new Map();
  const problems = [];
  text.split('\n').forEach((line, i) => {
    if (isComment(line)) return;
    const ref = IMAGE_KEY.exec(line)?.[1];
    if (!ref || ref.includes('${')) return;
    const repo = repositoryOf(ref);
    const seen = images.get(repo);
    if (!seen) images.set(repo, { ref, at: `${file}:${i + 1}` });
    else if (seen.ref !== ref)
      problems.push(`${file}:${i + 1}: ${ref} differs from ${seen.ref} at ${seen.at}`);
  });
  return { images, problems };
}

/**
 * Every reference to one of `repos` in a workflow, with its line: written with a tag or digest anywhere on a
 * non-comment line (`docker run cgr.dev/chainguard/minio:latest`), or as an `image:` value even without either.
 * `postgres:` as a mapping key, `postgresql://` and `redis://` URLs and `redis-cli` are not references.
 */
export function workflowReferences(file, text, repos) {
  const patterns = [...repos].map(
    (repo) =>
      new RegExp(
        `(?<![\\w./-])(?:docker\\.io/)?(?:library/)?${escapeRegExp(repo)}(?=[:@]\\w)[^\\s'"\`,;|&()[\\]{}]*`,
        'g',
      ),
  );
  const refs = [];
  text.split('\n').forEach((line, i) => {
    if (isComment(line)) return;
    const found = new Set(patterns.flatMap((re) => line.match(re) ?? []));
    const keyed = IMAGE_KEY.exec(line)?.[1];
    if (keyed && repos.has(repositoryOf(keyed))) found.add(keyed);
    for (const ref of found) refs.push({ ref, repo: repositoryOf(ref), at: `${file}:${i + 1}` });
  });
  return refs;
}

/** The images a Dockerfile's FROM lines name (`FROM base AS runtime` names a stage, not an image). */
export function dockerfileImages(file, text) {
  const stages = new Set();
  const refs = [];
  text.split('\n').forEach((line, i) => {
    const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (!m) return;
    if (!stages.has(m[1]))
      refs.push({ ref: m[1], repo: repositoryOf(m[1]), at: `${file}:${i + 1}` });
    if (m[2]) stages.add(m[2]);
  });
  return refs;
}

/**
 * The checks above over already-read files. Returns every problem (an empty list passes) and what was found, so a
 * caller can also assert that the references it expects were seen at all.
 */
export function checkPins({ compose, workflows, dockerfiles }) {
  const { images, problems } = composeImages(compose.file, compose.text);
  const repos = new Set(images.keys());

  const workflowRefs = workflows.flatMap(({ file, text }) => workflowReferences(file, text, repos));
  for (const { ref, repo, at } of workflowRefs) {
    const pinned = images.get(repo);
    if (ref !== pinned.ref) {
      problems.push(`${at}: ${ref} is not ${compose.file}'s ${pinned.ref} (${pinned.at})`);
    }
  }

  const dockerfileRefs = dockerfiles.flatMap(({ file, text }) => dockerfileImages(file, text));
  const firstByRepo = new Map();
  for (const entry of dockerfileRefs) {
    const first = firstByRepo.get(entry.repo);
    if (!first) firstByRepo.set(entry.repo, entry);
    else if (first.ref !== entry.ref) {
      problems.push(`${entry.at}: ${entry.ref} differs from ${first.ref} at ${first.at}`);
    }
  }

  return { problems, composeImages: images, workflowRefs, dockerfileRefs };
}

/** Reads the files the checks cover from a checkout: paths in the results are relative to `root`. */
export function readRepository(root) {
  const read = (file) => ({ file, text: readFileSync(path.join(root, file), 'utf8') });
  const workflowDir = '.github/workflows';
  return {
    compose: read('docker-compose.prod.yml'),
    workflows: readdirSync(path.join(root, workflowDir))
      .filter((name) => /\.ya?ml$/.test(name))
      .sort()
      .map((name) => read(`${workflowDir}/${name}`)),
    dockerfiles: [read('apps/api/Dockerfile'), read('apps/web/Dockerfile')],
  };
}
