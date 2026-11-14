import { useEffect, useRef, useState } from 'react'

interface UrlFiltersOptions<S, F> {
  /** The route search, which always mirrors the filter form. */
  search: S
  /** Stable identity of a search, used to notice URL changes. */
  keyOf: (search: S) => string
  /** The filters a query is sent with when `search` is applied. */
  appliedOf: (search: S) => F
  navigate: (next: S, options: { replace: boolean }) => void
}

interface GoOptions<F> {
  /** Rewrite the current history entry; used while the form is edited. */
  replace?: boolean
  /** New applied filters; omitted, the applied filters stay as they are. */
  apply?: F
}

/**
 * List filters whose form lives in the URL while queries use only the filters
 * last applied. Loading the page or moving through history applies whatever
 * the URL holds; this page's own navigations (editing, paging, ordering) keep
 * the applied filters unless they say otherwise.
 */
export function useUrlFilters<S, F>({
  search,
  keyOf,
  appliedOf,
  navigate,
}: UrlFiltersOptions<S, F>) {
  const searchKey = keyOf(search)
  const [applied, setApplied] = useState<F>(() => appliedOf(search))
  const ownNavigationRef = useRef(false)

  useEffect(() => {
    if (ownNavigationRef.current) {
      ownNavigationRef.current = false
      return
    }
    setApplied(appliedOf(search))
    // Only a change of the search itself re-applies it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchKey])

  function go(next: S, { replace = false, apply }: GoOptions<F> = {}) {
    if (apply !== undefined) setApplied(apply)
    if (keyOf(next) === searchKey) return
    ownNavigationRef.current = true
    navigate(next, { replace })
  }

  return { applied, go }
}
