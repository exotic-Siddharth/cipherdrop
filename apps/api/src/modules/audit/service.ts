/**
 * Audit service. `record()` is REAL (S4, R4): one Prisma insert with the caller's IP prefix and a UA summary.
 * `list()` (B1) pages a user's events newest first for GET /me/audit.
 *
 * NEVER put plaintext names, notes, keys, tokens or manifests in `metadata`.
 */
import type { AuditAction, Page } from '@cipherdrop/shared';
import type { AuditEvent, Prisma, PrismaClient } from '@prisma/client';
import type { Request } from 'express';
import { ipPrefix } from '../../lib/ip';
import { summarizeUserAgent } from '../../lib/userAgent';

export interface AuditRecordInput {
  userId?: string | null;
  dropId?: string | null;
  action: AuditAction;
  /** Source of ipPrefix (req.ip, trust-proxy aware) and the UA summary. Omit for background jobs. */
  req?: Pick<Request, 'ip' | 'headers'>;
  metadata?: Prisma.InputJsonObject | null;
}

export interface AuditListOptions {
  action?: AuditAction;
  page: number;
  pageSize: number;
}

export interface AuditService {
  record(input: AuditRecordInput): Promise<void>;
  /** Newest first (createdAt, then id). */
  list(userId: string, options: AuditListOptions): Promise<Page<AuditEvent>>;
}

export function createAuditService(prisma: PrismaClient): AuditService {
  return {
    async record(input) {
      const ua = input.req?.headers['user-agent'];
      await prisma.auditEvent.create({
        data: {
          userId: input.userId ?? null,
          dropId: input.dropId ?? null,
          action: input.action,
          ipPrefix: input.req ? ipPrefix(input.req.ip) : null,
          userAgent: input.req ? summarizeUserAgent(Array.isArray(ua) ? ua[0] : ua) : null,
          ...(input.metadata ? { metadata: input.metadata } : {}),
        },
      });
    },

    async list(userId, options) {
      const where: Prisma.AuditEventWhereInput = {
        userId,
        ...(options.action ? { action: options.action } : {}),
      };
      const skip = (options.page - 1) * options.pageSize;
      const [total, items] = await prisma.$transaction([
        prisma.auditEvent.count({ where }),
        prisma.auditEvent.findMany({
          where,
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
          skip,
          take: options.pageSize,
        }),
      ]);
      return { items, total, page: options.page, pageSize: options.pageSize };
    },
  };
}
