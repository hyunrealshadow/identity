import { act, renderHook, waitFor } from '@testing-library/react'
import { useQueryClient } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'

import type { GraphQLResult } from '#/lib/graphql/transport'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { LocaleTestProvider, QueryTestProvider } from '#/test/render'
import { SessionVersionContext, useSessionVersionCounter } from './session-version'

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  replace: null as null | (() => void),
}))
vi.mock('#/lib/graphql/use-graphql', () => ({ useGraphQL: () => mocks.request }))

function result(subject: string): GraphQLResult<{ subject: string }> {
  return {
    data: { subject },
    errors: [],
    partial: false,
    unauthorized: false,
    forbidden: false,
  }
}

function SessionScope({ children }: { children: ReactNode }) {
  const [version, replace] = useSessionVersionCounter(useQueryClient())
  mocks.replace = replace
  return (
    <SessionVersionContext.Provider value={version}>{children}</SessionVersionContext.Provider>
  )
}

describe('session replacement', () => {
  it('reloads mounted reads for the new session instead of leaving them pending', async () => {
    mocks.request.mockReset()
    mocks.request
      .mockResolvedValueOnce(result('previous'))
      .mockResolvedValueOnce(result('next'))
    const { result: hook } = renderHook(
      () => useConsoleQuery<{ subject: string }, object>('query ConsoleSubject { subject }', {}, true, 'missing_subject'),
      {
        wrapper: ({ children }) => (
          <QueryTestProvider>
            <LocaleTestProvider>
              <SessionScope>{children}</SessionScope>
            </LocaleTestProvider>
          </QueryTestProvider>
        ),
      },
    )
    await waitFor(() => expect(hook.current.data).toEqual({ subject: 'previous' }))

    act(() => mocks.replace!())

    // The previous session's value is never shown for the next one, and the
    // read settles instead of staying in its loading state.
    expect(hook.current.data).not.toEqual({ subject: 'previous' })
    await waitFor(() => expect(hook.current.status).toBe('ready'))
    expect(hook.current.data).toEqual({ subject: 'next' })
  })
})
