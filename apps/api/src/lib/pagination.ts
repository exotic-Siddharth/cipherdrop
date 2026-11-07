import type { Page } from '@cipherdrop/shared';

export interface Pagination {
  page: number;
  pageSize: number;
  skip: number;
  take: number;
}

/** From a validated PageQuerySchema value (`?page&pageSize`) to Prisma skip/take. */
export function paginate(query: { page?: number; pageSize?: number }): Pagination {
  const page = Math.max(1, Math.trunc(query.page ?? 1));
  const pageSize = Math.min(100, Math.max(1, Math.trunc(query.pageSize ?? 20)));
  return { page, pageSize, skip: (page - 1) * pageSize, take: pageSize };
}

/** `{items,total,page,pageSize}` */
export function toPage<T>(
  items: T[],
  total: number,
  p: { page: number; pageSize: number },
): Page<T> {
  return { items, total, page: p.page, pageSize: p.pageSize };
}
