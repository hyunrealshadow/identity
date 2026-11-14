import { act, renderHook } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { useUrlFilters } from '#/lib/use-url-filters'

interface Search {
  q?: string
  after?: string
}

const keyOf = (search: Search) => JSON.stringify(search)
const appliedOf = (search: Search) => ({ q: search.q?.trim() || undefined })

function setup(initial: Search) {
  const navigate = vi.fn()
  const hook = renderHook(
    ({ search }: { search: Search }) =>
      useUrlFilters({ search, keyOf, appliedOf, navigate }),
    { initialProps: { search: initial } },
  )
  return { ...hook, navigate }
}

describe('URL-mirrored list filters', () => {
  it('applies what the URL holds when the page loads', () => {
    const { result } = setup({ q: ' ada ' })
    expect(result.current.applied).toEqual({ q: 'ada' })
  })

  it('keeps the applied filters while the form or page changes the URL', () => {
    const { result, rerender, navigate } = setup({})

    act(() => result.current.go({ q: 'ada' }, { replace: true }))
    expect(navigate).toHaveBeenLastCalledWith({ q: 'ada' }, { replace: true })
    rerender({ search: { q: 'ada' } })
    expect(result.current.applied).toEqual({ q: undefined })

    act(() => result.current.go({ q: 'ada', after: 'cursor' }))
    expect(navigate).toHaveBeenLastCalledWith(
      { q: 'ada', after: 'cursor' },
      { replace: false },
    )
    rerender({ search: { q: 'ada', after: 'cursor' } })
    expect(result.current.applied).toEqual({ q: undefined })
  })

  it('changes the applied filters only when asked to', () => {
    const { result, rerender, navigate } = setup({ q: 'ada' })
    act(() => result.current.go({ q: 'grace' }, { replace: true }))
    rerender({ search: { q: 'grace' } })

    act(() => result.current.go({ q: 'grace' }, { apply: { q: 'grace' } }))
    expect(result.current.applied).toEqual({ q: 'grace' })
    // The URL already holds the form, so applying does not navigate again.
    expect(navigate).toHaveBeenCalledTimes(1)
  })

  it('re-applies the URL after a history navigation', () => {
    const { result, rerender } = setup({ q: 'ada' })
    act(() => result.current.go({ q: 'grace' }, { replace: true }))
    rerender({ search: { q: 'grace' } })
    expect(result.current.applied).toEqual({ q: 'ada' })

    // Back/forward changes the search without this page navigating.
    rerender({ search: { q: 'linus' } })
    expect(result.current.applied).toEqual({ q: 'linus' })
  })
})
