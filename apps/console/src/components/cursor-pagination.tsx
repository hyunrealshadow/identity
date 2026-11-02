import { Pagination } from '@heroui/react'
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
    <Pagination aria-label={label}>
      <Pagination.Summary>
        {totalCount === undefined
          ? t('rbacPageCount', { count: pageCount })
          : t('tablePageSummary', { count: pageCount, total: totalCount })}
      </Pagination.Summary>
      <Pagination.Content>
        <Pagination.Item>
          <Pagination.Previous
            isDisabled={
              isDisabled || !pageInfo.hasPreviousPage || !pageInfo.startCursor
            }
            onPress={() => {
              if (pageInfo.startCursor)
                controller.previous(pageInfo.startCursor)
            }}
          >
            <Pagination.PreviousIcon />
            {t('previousPage')}
          </Pagination.Previous>
        </Pagination.Item>
        {visible.map((number, index) => (
          <Fragment key={number}>
            {index > 0 && number - visible[index - 1] > 1 ? (
              <Pagination.Item>
                <Pagination.Ellipsis />
              </Pagination.Item>
            ) : null}
            <Pagination.Item>
              <Pagination.Link
                isActive={number === currentPage}
                isDisabled={isDisabled}
                aria-label={t('tableGoToPage', { page: number })}
                onPress={() => controller.goTo(number)}
              >
                {number}
              </Pagination.Link>
            </Pagination.Item>
          </Fragment>
        ))}
        <Pagination.Item>
          <Pagination.Next
            isDisabled={
              isDisabled || !pageInfo.hasNextPage || !pageInfo.endCursor
            }
            onPress={() => {
              if (pageInfo.endCursor) controller.next(pageInfo.endCursor)
            }}
          >
            {t('nextPage')}
            <Pagination.NextIcon />
          </Pagination.Next>
        </Pagination.Item>
      </Pagination.Content>
    </Pagination>
  )
}
