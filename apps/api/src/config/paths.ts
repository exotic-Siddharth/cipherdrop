import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Absolute path of apps/api, found by walking up to the package.json named @cipherdrop/api. This works from
 * src/ (tsx, vitest) and from the dist/ bundle, whatever the current working directory is.
 */
function findApiRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 8; depth++) {
    const pkg = path.join(dir, 'package.json');
    if (existsSync(pkg)) {
      try {
        if (
          (JSON.parse(readFileSync(pkg, 'utf8')) as { name?: string }).name === '@cipherdrop/api'
        ) {
          return dir;
        }
      } catch {
        // not a readable package.json: keep walking
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}

export const apiRoot = findApiRoot();
