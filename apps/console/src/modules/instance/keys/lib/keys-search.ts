import type { KeyStatus, KeyUse } from '#/generated/graphql'
import { parsePageSize } from '#/lib/page-size'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

export interface KeysSearch {
  /** `all` also lists expired and revoked keys. */
  show?: 'all'
  size?: number
  after?: string
  before?: string
}

export const KEYS_PAGE_SIZE = 10

/** Keys that still sign, verify, encrypt or decrypt. */
export const VALID_KEY_STATUSES: readonly KeyStatus[] = ['ACTIVE', 'RETIRED']

export function normalizeKeysSearch(input: Record<string, unknown>): KeysSearch {
  return {
    show: input.show === 'all' ? 'all' : undefined,
    size: parsePageSize(input.size),
    after: typeof input.after === 'string' ? input.after : undefined,
    before: typeof input.before === 'string' ? input.before : undefined,
  }
}

export function keysQueryVariables(use: KeyUse, search: KeysSearch) {
  return {
    filter: {
      use,
      statuses: search.show === 'all' ? undefined : [...VALID_KEY_STATUSES],
    },
    ...cursorPage(search.size ?? KEYS_PAGE_SIZE, search.after, search.before),
  }
}
