import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';

const SAFE_ID = /^[A-Za-z0-9._-]{8,64}$/;

/** Accept a well-formed incoming X-Request-Id (e.g. from nginx), otherwise mint one. Echoed in the response. */
export const requestId: RequestHandler = (req, res, next) => {
  const incoming = req.get('x-request-id');
  const id = incoming && SAFE_ID.test(incoming) ? incoming : randomUUID();
  (req as typeof req & { id: string }).id = id;
  res.setHeader('X-Request-Id', id);
  next();
};
