// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'

import {
  ConsoleCreateUserDocument,
  ConsoleDisableUserDocument,
  ConsoleUpdateUserDocument,
  type ConsoleUserQuery,
} from '#/generated/graphql'
import { createQueryClient } from '#/lib/graphql/query-client'
import { usePatchVersionedEntities } from '#/lib/graphql/patch-versioned-entities'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { LocaleTestProvider } from '#/test/render'

function userResult(version: string): GraphQLResult<ConsoleUserQuery> {
  return {
    data: {
      user: {
        id: 'u1',
        username: 'ada',
        email: 'ada@example.test',
        emailVerified: true,
        enabled: true,
        locked: false,
        lockedUntil: null,
        failedAttempts: 0,
        version,
        givenName: null,
        familyName: null,
        middleName: null,
        nickname: null,
        profile: null,
        picture: null,
        website: null,
        birthdate: null,
        locale: null,
        theme: null,
        createdAt: '2026-01-01T00:00:00Z',
        updatedAt: null,
      },
    },
    errors: [],
    partial: false,
    unauthorized: false,
    forbidden: false,
  }
}

function cachedUser(
  client: ReturnType<typeof createQueryClient>,
  key: readonly unknown[],
) {
  return client.getQueryData<GraphQLResult<ConsoleUserQuery>>(key)?.data?.user ?? null
}

function setup() {
  const client = createQueryClient()
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <LocaleTestProvider>{children}</LocaleTestProvider>
    </QueryClientProvider>
  )
  const { result } = renderHook(() => usePatchVersionedEntities(), { wrapper })
  return { client, patch: result }
}

describe('version patches from mutation payloads', () => {
  it('updates the cached detail version and keeps the rest of the result', () => {
    const { client, patch } = setup()
    const key = ['console', 0, 'en-US', 'ConsoleUser', { id: 'u1' }]
    client.setQueryData(key, userResult('before'))

    act(() =>
      patch.current(ConsoleUpdateUserDocument, {
        updateUser: { userId: 'u1', version: 'after' },
      }),
    )

    const cached = client.getQueryData<GraphQLResult<ConsoleUserQuery>>(key)
    expect(cachedUser(client, key)?.version).toBe('after')
    expect(cachedUser(client, key)?.username).toBe('ada')
    expect(cached?.partial).toBe(false)
  })

  it('applies the state change carried by an enable or disable payload', () => {
    const { client, patch } = setup()
    const key = ['console', 0, 'en-US', 'ConsoleUser', { id: 'u1' }]
    client.setQueryData(key, userResult('before'))

    act(() =>
      patch.current(ConsoleDisableUserDocument, {
        disableUser: { userId: 'u1', version: 'after' },
      }),
    )

    expect(cachedUser(client, key)?.enabled).toBe(false)
    expect(cachedUser(client, key)?.version).toBe('after')
  })

  it('leaves other readers and other entities untouched', () => {
    const { client, patch } = setup()
    const zhKey = ['console', 0, 'zh-CN', 'ConsoleUser', { id: 'u1' }]
    const otherKey = ['console', 0, 'en-US', 'ConsoleUser', { id: 'u2' }]
    client.setQueryData(zhKey, userResult('before'))
    client.setQueryData(otherKey, { ...userResult('before'), data: { user: { ...userResult('before').data!.user, id: 'u2' } } })

    act(() =>
      patch.current(ConsoleUpdateUserDocument, {
        updateUser: { userId: 'u1', version: 'after' },
      }),
    )

    expect(cachedUser(client, zhKey)?.version).toBe('before')
    expect(cachedUser(client, otherKey)?.version).toBe('before')
  })

  it('ignores operations without a declared payload target', () => {
    const { client, patch } = setup()
    const key = ['console', 0, 'en-US', 'ConsoleUser', { id: 'u1' }]
    client.setQueryData(key, userResult('before'))

    act(() => patch.current(ConsoleCreateUserDocument, { createUser: { userId: 'u9', version: 'after' } }))

    expect(cachedUser(client, key)?.version).toBe('before')
  })
})
