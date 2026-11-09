import { Button } from '@identity/ui/components/button'
import { ChevronLeft, ChevronRight, MoreHorizontal } from 'lucide-react'
import { Fragment } from 'react'

import { PageSizeSelect } from '#/components/page-size-select'
import { useTranslator } from '#/lib/i18n'
import type { CursorPaginationController } from '#/lib/use-cursor-pagination'

interface PageInfo {
  hasPreviousPage: boolean
  hasNextPage: boolean
  startCursor?: string | null
  endCursor?: string | null
}

export function CursorPagination({
  label,
  pageCount,
  totalCount,
  pageInfo,
  controller,
  isDisabled = false,
  pageSize,
  onPageSizeChange,
}: {
  label: string
  pageCount: number
  totalCount?: number
  pageInfo: PageInfo
  controller: CursorPaginationController
  isDisabled?: boolean
  /** Shows the rows-per-page select when both are provided. */
  pageSize?: number
  onPageSizeChange?: (size: number) => void
}) {
  const t = useTranslator()
  const { pages, currentPage } = controller
  const lastKnown = pages.at(-1)
  const visible = pages.filter(
    (page) =>
      page === 1 ||
      page === lastKnown ||
      Math.abs(page - (currentPage ?? 1)) <= 1,
  )

  function summary() {
    const known = pageSize !== undefined && currentPage !== undefined
    if (known && pageCount === 0 && currentPage === 1)
      return t('tablePageSummary', { total: totalCount ?? 0 })
    if (known && pageCount > 0) {
      const from = (currentPage - 1) * pageSize + 1
      const to = from + pageCount - 1
      return totalCount === undefined
        ? t('tableRangeOnlySummary', { from, to })
        : t('tableRangeSummary', { from, to, total: totalCount })
    }
    return totalCount === undefined
      ? t('rbacPageCount', { count: pageCount })
      : t('tablePageSummary', { total: totalCount })
  }

  return (
    <nav
      data-slot="pagination"
      aria-label={label}
      className="flex w-full flex-wrap items-center justify-between gap-2 text-sm"
    >
      <span className="text-muted-foreground">{summary()}</span>
      <div className="flex flex-wrap items-center gap-3">
        <div data-slot="pagination-content" className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={t('previousPage')}
            disabled={isDisabled || !pageInfo.hasPreviousPage || !pageInfo.startCursor}
            onClick={() => {
              if (pageInfo.startCursor) controller.previous(pageInfo.startCursor)
            }}
          >
            <ChevronLeft aria-hidden="true" />
          </Button>
          {visible.map((number, index) => (
            <Fragment key={number}>
              {index > 0 && number - visible[index - 1] > 1 ? (
                <span className="px-1 text-muted-foreground" aria-hidden="true">
                  <MoreHorizontal className="size-4" />
                </span>
              ) : null}
              <Button
                variant={number === currentPage ? 'outline' : 'ghost'}
                size="icon-sm"
                disabled={isDisabled}
                aria-label={t('tableGoToPage', { page: number })}
                aria-current={number === currentPage ? 'page' : undefined}
                onClick={() => controller.goTo(number)}
              >
                {number}
              </Button>
            </Fragment>
          ))}
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={t('nextPage')}
            disabled={isDisabled || !pageInfo.hasNextPage || !pageInfo.endCursor}
            onClick={() => {
              if (pageInfo.endCursor) controller.next(pageInfo.endCursor)
            }}
          >
            <ChevronRight aria-hidden="true" />
          </Button>
        </div>
        {pageSize !== undefined && onPageSizeChange ? (
          <PageSizeSelect
            value={pageSize}
            onChange={onPageSizeChange}
            disabled={isDisabled}
          />
        ) : null}
      </div>
    </nav>
  )
}
