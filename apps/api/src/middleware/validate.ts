/**
 * zod request validation. On success:
 * - req.body           = parsed body (Express 5: undefined bodies are validated as {})
 * - req.validatedQuery = parsed query (Express 5 `req.query` is a read-only getter)
 * - req.validatedParams = parsed params (Express 5 params stay raw strings)
 * Without a schema the raw value is copied, so validatedQuery/validatedParams are always defined.
 * On failure: 400 VALIDATION_ERROR with details.issues = [{path: "body.email", message, code}].
 */
import type { RequestHandler } from 'express';
import type { ZodIssue, ZodTypeAny } from 'zod';
import { validationError } from '../lib/errors';

export interface ValidationSchemas {
  params?: ZodTypeAny;
  query?: ZodTypeAny;
  body?: ZodTypeAny;
}

export interface ValidationIssue {
  path: string;
  message: string;
  code: string;
}

const toIssues = (where: string, issues: ZodIssue[]): ValidationIssue[] =>
  issues.map((i) => ({ path: [where, ...i.path].join('.'), message: i.message, code: i.code }));

export function validate(schemas: ValidationSchemas): RequestHandler {
  return (req, _res, next) => {
    const issues: ValidationIssue[] = [];

    if (schemas.params) {
      const r = schemas.params.safeParse(req.params);
      if (r.success) req.validatedParams = r.data;
      else issues.push(...toIssues('params', r.error.issues));
    } else {
      req.validatedParams = req.params;
    }

    if (schemas.query) {
      const r = schemas.query.safeParse(req.query);
      if (r.success) req.validatedQuery = r.data;
      else issues.push(...toIssues('query', r.error.issues));
    } else {
      req.validatedQuery = req.query;
    }

    if (schemas.body) {
      const r = schemas.body.safeParse(req.body ?? {});
      if (r.success) req.body = r.data;
      else issues.push(...toIssues('body', r.error.issues));
    }

    if (issues.length > 0) throw validationError('Invalid request', { issues });
    next();
  };
}
