// @vitest-environment jsdom
import { act, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { GraphQLResult } from '#/lib/graphql/transport'
import { renderHookWithLocale } from '#/test/render'
import {
  sameVariable,
  useConsoleQuery,
  type KeepPreviousData,
} from './use-console-query'

const mocks = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('#/lib/graphql/use-graphql', () => ({
  useGraphQL: () => mocks.request,
}))

interface Page {
  rows: string[]
}

interface Variables {
  ownerId: string
  after?: string
}

function page(rows: string[]): GraphQLResult<Page> {
  return {
    data: { rows },
    errors: [],
    partial: false,
    unauthorized: false,
    forbidden: false,
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

function setup(keepPreviousData: KeepPreviousData<Variables>) {
  return renderHookWithLocale(
    ({ variables }: { variables: Variables }) =>
      useConsoleQuery<Page, Variables>(
        'query ConsolePage { rows }',
        variables,
        true,
        'missing_page',
        { keepPreviousData },
      ),
    { initialProps: { variables: { ownerId: 'a' } as Variables } },
  )
}

describe('useConsoleQuery placeholders', () => {
  it('keeps the previous rows while the next page of the same owner loads', async () => {
    mocks.request.mockReset()
    mocks.request.mockResolvedValueOnce(page(['first']))
    const next = deferred<GraphQLResult<Page>>()
    mocks.request.mockReturnValueOnce(next.promise)

    const { result, rerender } = setup(sameVariable('ownerId'))
    await waitFor(() => expect(result.current.status).toBe('ready'))

    rerender({ variables: { ownerId: 'a', after: 'cursor' } })
    await waitFor(() => expect(result.current.refreshing).toBe(true))
    expect(result.current.status).toBe('ready')
    expect(result.current.data).toEqual({ rows: ['first'] })

    await act(async () => next.resolve(page(['second'])))
    await waitFor(() => expect(result.current.refreshing).toBe(false))
    expect(result.current.data).toEqual({ rows: ['second'] })
  })

  it('never shows another owner\'s rows as a placeholder', async () => {
    mocks.request.mockReset()
    mocks.request.mockResolvedValueOnce(page(['owner a']))
    mocks.request.mockReturnValueOnce(deferred<GraphQLResult<Page>>().promise)

    const { result, rerender } = setup(sameVariable('ownerId'))
    await waitFor(() => expect(result.current.status).toBe('ready'))

    rerender({ variables: { ownerId: 'b' } })
    await waitFor(() => expect(result.current.status).toBe('loading'))
    expect(result.current.data).toBeNull()
  })

  it('does not keep a failed read as a placeholder', async () => {
    mocks.request.mockReset()
    mocks.request.mockResolvedValueOnce({
      ...page([]),
      data: null,
      failure: { kind: 'graphql', code: 'insufficient_scope' },
      forbidden: true,
    } satisfies GraphQLResult<Page>)
    mocks.request.mockReturnValueOnce(deferred<GraphQLResult<Page>>().promise)

    const { result, rerender } = setup(true)
    await waitFor(() => expect(result.current.forbidden).toBe(true))

    rerender({ variables: { ownerId: 'a', after: 'cursor' } })
    await waitFor(() => expect(result.current.status).toBe('loading'))
    expect(result.current.forbidden).toBe(false)
  })
})
