// @vitest-environment jsdom
import { act, renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuthorizationLabels } from './use-authorization-labels'
const { request } = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('#/lib/graphql/use-graphql', () => ({ useGraphQL: () => request }))
const node = (id: string) => ({ id, __typename: 'Group', name: id, names: [] })
beforeEach(() => {
  request.mockReset()
})
describe('authorization label loading', () => {
  it('loads all labels across bounded batches and preserves partial successes', async () => {
    request.mockImplementation(
      async (_document, { ids }: { ids: string[] }) => ({
        data: { nodes: ids.map(node) },
        errors: ids.length < 100 ? [{ message: 'Unavailable label' }] : [],
      }),
    )
    const ids = Array.from({ length: 102 }, (_, index) => `label-${index}`)
    const { result } = renderHook(() => useAuthorizationLabels(ids))
    await waitFor(() => expect(result.current.nodes).toHaveLength(102))
    expect(request.mock.calls.map((call) => call[1].ids.length)).toEqual([
      100, 2,
    ])
    expect(result.current.failed).toBe(true)
  })
  it('ignores labels from a previous resource after selection changes', async () => {
    let finish: (value: unknown) => void = () => {}
    request.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve
        }),
    )
    request.mockResolvedValue({ data: { nodes: [node('new')] }, errors: [] })
    const { result, rerender } = renderHook(
      ({ ids }) => useAuthorizationLabels(ids),
      { initialProps: { ids: ['old'] } },
    )
    rerender({ ids: ['new'] })
    await waitFor(() =>
      expect(result.current.nodes.map((entry) => entry.id)).toEqual(['new']),
    )
    await act(async () =>
      finish({ data: { nodes: [node('old')] }, errors: [] }),
    )
    expect(result.current.nodes.map((entry) => entry.id)).toEqual(['new'])
  })
})
