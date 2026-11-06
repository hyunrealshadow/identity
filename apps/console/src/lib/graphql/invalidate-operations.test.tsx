// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'

import { ConsoleUserDocument, ConsoleUsersDocument } from '#/generated/graphql'
import { createQueryClient } from '#/lib/graphql/query-client'
import { useInvalidateOperations } from '#/lib/graphql/invalidate-operations'
import { consoleQueryKeys } from '#/lib/graphql/query-keys'
import { LocaleTestProvider } from '#/test/render'

function setup() {
  const client = createQueryClient()
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <LocaleTestProvider>{children}</LocaleTestProvider>
    </QueryClientProvider>
  )
  const { result } = renderHook(() => useInvalidateOperations(), { wrapper })
  const stale = (key: readonly unknown[]) =>
    client.getQueryState(key)?.isInvalidated ?? false
  return { client, invalidate: result, stale }
}

describe('document-based invalidation', () => {
  it('marks every variable combination of the given read stale, and nothing else', async () => {
    const { client, invalidate, stale } = setup()
    const firstPage = consoleQueryKeys.read(0, 'en-US', ConsoleUsersDocument, { first: 10 })
    const filtered = consoleQueryKeys.read(0, 'en-US', ConsoleUsersDocument, {
      first: 10,
      filter: { query: 'ada' },
    })
    const detail = consoleQueryKeys.read(0, 'en-US', ConsoleUserDocument, { id: 'u1' })
    const otherLocale = consoleQueryKeys.read(0, 'zh-CN', ConsoleUsersDocument, { first: 10 })
    const otherSession = consoleQueryKeys.read(1, 'en-US', ConsoleUsersDocument, { first: 10 })
    for (const key of [firstPage, filtered, detail, otherLocale, otherSession]) {
      client.setQueryData(key, { data: null })
    }

    await act(() => invalidate.current([ConsoleUsersDocument]))

    expect(stale(firstPage)).toBe(true)
    expect(stale(filtered)).toBe(true)
    expect(stale(detail)).toBe(false)
    expect(stale(otherLocale)).toBe(false)
    expect(stale(otherSession)).toBe(false)
  })
})
