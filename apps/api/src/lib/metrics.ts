/**
 * Prometheus metrics (spec section 15) on ONE per-process registry. Every metric is created here, once, at
 * module load; lanes import `metrics` and call inc()/set(). Never construct metrics inside createApp() or a
 * route factory (prom-client throws on duplicate registration).
 */
import type { RequestHandler } from 'express';
import client from 'prom-client';

export const metricsRegistry = new client.Registry();
client.collectDefaultMetrics({ register: metricsRegistry });

export const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status_code'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [metricsRegistry],
});

export const metrics = {
  /** labels: anon = "true" | "false" */
  dropsCreated: new client.Counter({
    name: 'drops_created_total',
    help: 'Drops created',
    labelNames: ['anon'] as const,
    registers: [metricsRegistry],
  }),
  dropOpens: new client.Counter({
    name: 'drop_opens_total',
    help: 'Successful drop opens (downloads consumed)',
    registers: [metricsRegistry],
  }),
  chunkBytesUploaded: new client.Counter({
    name: 'chunk_bytes_uploaded_total',
    help: 'Ciphertext bytes received in chunk uploads',
    registers: [metricsRegistry],
  }),
  chunkBytesDownloaded: new client.Counter({
    name: 'chunk_bytes_downloaded_total',
    help: 'Ciphertext bytes streamed in chunk downloads',
    registers: [metricsRegistry],
  }),
  cleanupRuns: new client.Counter({
    name: 'cleanup_runs_total',
    help: 'Cleanup job runs',
    registers: [metricsRegistry],
  }),
  cleanupDeletedDrops: new client.Counter({
    name: 'cleanup_deleted_drops_total',
    help: 'Drops whose blobs were deleted by the cleanup job',
    registers: [metricsRegistry],
  }),
  storageFreeBytes: new client.Gauge({
    name: 'storage_free_bytes',
    help: 'Free bytes on the volume holding the blobs (local storage driver; set by /readyz)',
    registers: [metricsRegistry],
  }),
  storageBytes: new client.Gauge({
    name: 'storage_bytes',
    help: 'Ciphertext bytes currently stored',
    registers: [metricsRegistry],
  }),
};

/** Low-cardinality route label: the matched route pattern, never the concrete URL. */
function routeLabel(req: Parameters<RequestHandler>[0]): string {
  const route = req.route as { path?: unknown } | undefined;
  if (route && typeof route.path === 'string') return `${req.baseUrl}${route.path}`;
  return 'unmatched';
}

export const metricsMiddleware: RequestHandler = (req, res, next) => {
  const end = httpRequestDuration.startTimer();
  res.on('finish', () => {
    end({ method: req.method, route: routeLabel(req), status_code: String(res.statusCode) });
  });
  next();
};
