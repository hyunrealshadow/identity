import { Button } from '@identity/ui/components/button'
import { ChevronLeft, ChevronRight, MoreHorizontal } from 'lucide-react'
import { Fragment } from 'react'

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
}: {
  label: string
  pageCount: number
  totalCount?: number
  pageInfo: PageInfo
  controller: CursorPaginationController
  isDisabled?: boolean
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

  return (
    <nav
      data-slot="pagination"
      aria-label={label}
      className="mx-auto flex w-full flex-wrap items-center justify-center gap-2 text-sm"
    >
      <span className="text-muted-foreground">
        {totalCount === undefined
          ? t('rbacPageCount', { count: pageCount })
          : t('tablePageSummary', { count: pageCount, total: totalCount })}
      </span>
      <div data-slot="pagination-content" className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          disabled={isDisabled || !pageInfo.hasPreviousPage || !pageInfo.startCursor}
          onClick={() => {
            if (pageInfo.startCursor) controller.previous(pageInfo.startCursor)
          }}
        >
          <ChevronLeft aria-hidden="true" />
          {t('previousPage')}
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
          size="sm"
          disabled={isDisabled || !pageInfo.hasNextPage || !pageInfo.endCursor}
          onClick={() => {
            if (pageInfo.endCursor) controller.next(pageInfo.endCursor)
          }}
        >
          {t('nextPage')}
          <ChevronRight aria-hidden="true" />
        </Button>
      </div>
    </nav>
  )
}
