import { useEffect, useState } from 'react'

import { getAuthSession } from '#/lib/auth/session'

export interface PageCursor {
  after?: string
  before?: string
}

interface History {
  context: string
  pages: Array<{ number: number; cursor: PageCursor }>
  aliases: Record<string, number>
}

function cursorKey(cursor: PageCursor): string {
  return JSON.stringify([cursor.after ?? null, cursor.before ?? null])
}

function initialHistory(context: string): History {
  return {
    context,
    pages: [{ number: 1, cursor: {} }],
    aliases: { [cursorKey({})]: 1 },
  }
}

/** Page numbers describe known cursor positions, never an inferred total count. */
export function useCursorPagination({
  search,
  variables,
  onNavigate,
}: {
  search: PageCursor
  variables: object | null
  onNavigate: (cursor: PageCursor) => void
}) {
  const session = getAuthSession()
  const entries = Object.entries(variables ?? {})
  const size = entries.find(([key]) => key === 'first' || key === 'last')?.[1]
  const context = JSON.stringify([
    session?.claims.iss,
    session?.claims.sub,
    size,
    entries.filter(
      ([key]) => !['after', 'before', 'first', 'last'].includes(key),
    ),
  ])
  const [history, setHistory] = useState(() => initialHistory(context))
  // Do not expose cursor positions from another filter, order, or principal while resetting.
  const active = history.context === context ? history : initialHistory(context)
  const currentPage = active.aliases[cursorKey(search)]

  useEffect(() => {
    setHistory((previous) =>
      previous.context === context ? previous : initialHistory(context),
    )
  }, [context])

  function navigateRelative(cursor: PageCursor, direction: 1 | -1) {
    if (currentPage !== undefined && currentPage + direction >= 1) {
      const number = currentPage + direction
      const existing = active.pages.find((page) => page.number === number)
      const changed =
        direction === 1 &&
        existing &&
        cursorKey(existing.cursor) !== cursorKey(cursor)
      const pages = changed
        ? active.pages.filter((page) => page.number <= number)
        : active.pages
      const aliases = Object.fromEntries(
        Object.entries(active.aliases).filter(
          ([, page]) => !changed || page <= number,
        ),
      )
      setHistory({
        context,
        pages: pages.some((page) => page.number === number)
          ? pages.map((page) =>
              direction === 1 && page.number === number
                ? { number, cursor }
                : page,
            )
          : [...pages, { number, cursor }],
        aliases: { ...aliases, [cursorKey(cursor)]: number },
      })
    }
    onNavigate(cursor)
  }

  return {
    currentPage,
    pages: active.pages.map((page) => page.number).sort((a, b) => a - b),
    next: (after: string) => navigateRelative({ after }, 1),
    previous: (before: string) => navigateRelative({ before }, -1),
    goTo: (number: number) => {
      const target = active.pages.find((page) => page.number === number)
      if (target && number !== currentPage) onNavigate(target.cursor)
    },
  }
}

export type CursorPaginationController = ReturnType<typeof useCursorPagination>
