import { Button, Skeleton } from '@heroui/react'
import { Search } from 'lucide-react'
import type { ReactNode } from 'react'

import { AsyncState } from '#/components/async-state'
import { CursorPagination } from '#/components/cursor-pagination'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator } from '#/lib/i18n'
import {
  useCursorPagination,
  type PageCursor,
} from '#/lib/use-cursor-pagination'
import type { ConsoleQueryState } from '#/lib/graphql/use-console-query'
import { UserTextField } from '../users/components/user-form-fields'

interface Connection {
  edges: readonly unknown[]
  totalCount?: number
  pageInfo: {
    hasNextPage: boolean
    hasPreviousPage: boolean
    startCursor?: string | null
    endCursor?: string | null
  }
}

export function RelationPagination({
  connection,
  variables,
  after,
  before,
  onNavigate,
  label,
  isDisabled = false,
}: {
  connection: Connection | null | undefined
  variables: object | null
  after?: string
  before?: string
  onNavigate: (cursor: PageCursor) => void
  label: string
  isDisabled?: boolean
}) {
  const controller = useCursorPagination({
    search: { after, before },
    variables,
    onNavigate,
  })
  if (!connection) return null
  return (
    <CursorPagination
      label={label}
      pageCount={connection.edges.length}
      totalCount={connection.totalCount}
      pageInfo={connection.pageInfo}
      controller={controller}
      isDisabled={isDisabled}
    />
  )
}

export function CandidateSearch({
  label,
  value,
  onChange,
  onSearch,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  onSearch: () => void
}) {
  const t = useTranslator()
  return (
    <form
      className="collection-filter-controls mt-4 flex items-end gap-2"
      onSubmit={(event) => {
        event.preventDefault()
        onSearch()
      }}
    >
      <div className="min-w-0 flex-1">
        <UserTextField
          name="candidate-search"
          label={label}
          value={value}
          onChange={onChange}
          maxLength={256}
        />
      </div>
      <Button type="submit">
        <Search className="size-4" aria-hidden="true" />
        {t('roleUsersSearchAction')}
      </Button>
    </form>
  )
}

export function CandidateResults({
  query,
  count,
  label,
  empty,
  children,
}: {
  query: Pick<
    ConsoleQueryState<unknown>,
    | 'status'
    | 'failure'
    | 'forbidden'
    | 'requestId'
    | 'traceId'
    | 'errors'
    | 'refresh'
  >
  count: number
  label: string
  empty: string
  children: ReactNode
}) {
  const t = useTranslator()
  return (
    <div
      className="mt-4 max-h-72 overflow-y-auto rounded-field border border-border"
      role="region"
      aria-label={label}
    >
      {query.status === 'error' ? (
        <div className="p-3">
          <AsyncState
            compact
            kind={query.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(query.failure, query.forbidden))}
            description={t(
              failureDescriptionKey(query.failure, query.forbidden),
            )}
            requestId={query.requestId}
            traceId={query.traceId}
            issues={query.errors}
            onRetry={() => void query.refresh()}
          />
        </div>
      ) : query.status !== 'ready' ? (
        <div className="space-y-2 p-3" role="status" aria-label={t('loading')}>
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      ) : count === 0 ? (
        <p className="p-4 text-sm text-muted">{empty}</p>
      ) : (
        children
      )}
    </div>
  )
}
