import { Button } from '@identity/ui/components/button'
import { ChevronLeft, ChevronRight, MoreHorizontal } from 'lucide-react'
import { Fragment } from 'react'

export interface NumberedPaginationPage {
  number: number
  active?: boolean
}

/**
 * Page-numbered control for client-side paged lists. Cursor-backed relations use
 * `CursorPagination` instead.
 */
export function NumberedPagination({
  label,
  summary,
  page,
  pages,
  onPageChange,
  disabled = false,
  previousLabel,
  nextLabel,
  pageLabel,
}: {
  label: string
  summary?: string
  page: number
  pages: readonly number[]
  onPageChange: (page: number) => void
  disabled?: boolean
  previousLabel: string
  nextLabel: string
  pageLabel: (page: number) => string
}) {
  const last = pages.at(-1)
  return (
    <nav
      data-slot="pagination"
      aria-label={label}
      className="flex w-full flex-wrap items-center justify-between gap-2 text-sm"
    >
      {summary ? <span className="text-muted-foreground">{summary}</span> : null}
      <div data-slot="pagination-content" className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          disabled={disabled || page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          <ChevronLeft aria-hidden="true" />
          {previousLabel}
        </Button>
        {pages.map((number, index) => (
          <Fragment key={number}>
            {index > 0 && number - pages[index - 1] > 1 ? (
              <span className="px-1 text-muted-foreground" aria-hidden="true">
                <MoreHorizontal className="size-4" />
              </span>
            ) : null}
            <Button
              variant={number === page ? 'outline' : 'ghost'}
              size="icon-sm"
              disabled={disabled}
              aria-label={pageLabel(number)}
              aria-current={number === page ? 'page' : undefined}
              onClick={() => onPageChange(number)}
            >
              {number}
            </Button>
          </Fragment>
        ))}
        <Button
          variant="ghost"
          size="sm"
          disabled={disabled || (last !== undefined && page >= last)}
          onClick={() => onPageChange(page + 1)}
        >
          {nextLabel}
          <ChevronRight aria-hidden="true" />
        </Button>
      </div>
    </nav>
  )
}
