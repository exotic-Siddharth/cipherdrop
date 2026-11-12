/**
 * Control measurement for docs/BENCHMARKS.md: how fast can Playwright's headless Chromium PUT 4 MiB bodies to a
 * bare Node http server on localhost that just counts the bytes? No CipherDrop code, no crypto, no proxy. It
 * shows the ceiling the browser's own fetch upload path puts on "encrypt + upload" on this machine.
 *
 *   npm run bench:ceiling -w @cipherdrop/web
 * Env: BENCH_CEILING_PORT (default 5176), BENCH_RUNS (3). Rates are MiB/s (1 MiB = 1,048,576 bytes).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { chromium } from '@playwright/test';

const RUNS = Number(process.env.BENCH_RUNS ?? 3);
const PORT = Number(process.env.BENCH_CEILING_PORT ?? 5176);
const CHUNKS = 24;
const CHUNK_BYTES = 4 * 1024 * 1024 + 16;

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

async function main(): Promise<void> {
  const server = http.createServer((req, res) => {
    if (req.method !== 'PUT') {
      res.setHeader('content-type', 'text/html').end('<!doctype html><title>ceiling</title>');
      return;
    }
    req.resume(); // discard the body
    req.on('end', () => res.writeHead(204).end());
  });
  await new Promise<void>((resolve) => server.listen(PORT, resolve));
  const port = (server.address() as AddressInfo).port;
  const browser = await chromium.launch();
  try {
    const page = await (await browser.newContext()).newPage();
    await page.goto(`http://localhost:${port}/`);
    const rows: string[] = [];
    for (const inFlight of [1, 3]) {
      const rates: number[] = [];
      for (let run = 0; run < RUNS + 1; run++) {
        const rate = await page.evaluate(
          async ({ inFlight, chunks, bytes }) => {
            const body = new Uint8Array(bytes);
            let next = 0;
            const started = performance.now();
            await Promise.all(
              Array.from({ length: inFlight }, async () => {
                while (next < chunks) {
                  next++;
                  const res = await fetch('/chunk', { method: 'PUT', body });
                  if (!res.ok) throw new Error(`PUT ${res.status}`);
                }
              }),
            );
            return (chunks * bytes) / (1024 * 1024) / ((performance.now() - started) / 1000);
          },
          { inFlight, chunks: CHUNKS, bytes: CHUNK_BYTES },
        );
        if (run > 0) rates.push(rate); // the first pass is the warm-up
      }
      rows.push(
        `| ${inFlight} | ${median(rates).toFixed(1)} | ${Math.min(...rates).toFixed(1)} | ${Math.max(...rates).toFixed(1)} |`,
      );
    }
    console.log(
      [
        `Chromium ${browser.version()} headless -> bare Node http server (${CHUNKS} PUTs of 4 MiB, ${RUNS} runs after one warm-up)`,
        '',
        '| PUTs in flight | Median MiB/s | Min | Max |',
        '|---:|---:|---:|---:|',
        ...rows,
      ].join('\n'),
    );
  } finally {
    await browser.close();
    server.close();
  }
}

main().catch((err: unknown) => {
  console.error('BENCH FAILED:', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
