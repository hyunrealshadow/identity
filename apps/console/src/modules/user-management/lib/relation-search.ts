import { parsePageSize } from '#/lib/page-size'

/** Paging of a relation list kept in the URL. */
export interface RelationPagingSearch {
  size?: number
  after?: string
  before?: string
}

export function normalizeRelationPaging(
  input: Record<string, unknown>,
): RelationPagingSearch {
  const result: RelationPagingSearch = {}
  const size = parsePageSize(input.size)
  if (size !== undefined) result.size = size
  if (typeof input.after === 'string' && input.after) result.after = input.after
  else if (typeof input.before === 'string' && input.before) {
    result.before = input.before
  }
  return result
}

/** A value from a fixed set; anything else, including the default, is dropped. */
export function searchOption<T extends string>(
  value: unknown,
  options: ReadonlyArray<T>,
  fallback: T,
): T | undefined {
  return typeof value === 'string' &&
    value !== fallback &&
    (options as ReadonlyArray<string>).includes(value)
    ? (value as T)
    : undefined
}

/** Free text as typed: the URL keeps the form exactly, spaces included. */
export function searchText(value: unknown, maxLength = 256): string | undefined {
  return typeof value === 'string' && value ? value.slice(0, maxLength) : undefined
}

/** Relation tabs move to their first page whenever a filter changes. */
export const FIRST_PAGE = { after: undefined, before: undefined } as const
