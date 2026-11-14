import { DataTable } from '@identity/ui/data-table'
import { Button } from '@identity/ui/components/button'
import { Checkbox } from '@identity/ui/components/checkbox'
import { Popover, PopoverContent, PopoverTrigger } from '@identity/ui/components/popover'
import { RefreshCw, Settings2 } from 'lucide-react'
import { useState, type CSSProperties, type ReactNode } from 'react'

import { useTranslator } from '#/lib/i18n'

export interface ResourceColumn<T> {
  id: string
  label: string
  primary?: boolean
  sort?: string
  render: (item: T) => ReactNode
}

interface TablePreferences {
  hidden: string[]
  compact: boolean
  wrap: boolean
}

const defaults: TablePreferences = { hidden: [], compact: false, wrap: false }

function readPreferences(key: string): TablePreferences {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(key) ?? 'null')
    if (!value || typeof value !== 'object') return defaults
    const stored = value as Record<string, unknown>
    return {
      hidden: Array.isArray(stored.hidden)
        ? stored.hidden.filter((id): id is string => typeof id === 'string')
        : [],
      compact: stored.compact === true,
      wrap: stored.wrap === true,
    }
  } catch {
    return defaults
  }
}

export interface ResourceTableProps<T> {
  id: string
  label: string
  items: readonly T[]
  columns: readonly ResourceColumn<T>[]
  order?: string
  onOrderChange: (order: string | undefined) => void
  onRefresh: () => void
  pagination: ReactNode
  emptyState?: ReactNode
  refreshing?: boolean
  density?: 'compact' | 'comfortable'
  maxHeight?: CSSProperties['maxHeight']
  /** Filter controls shown at the start of the table toolbar. */
  filters?: ReactNode
  /** Full-width content under the toolbar row, such as expanded advanced filters. */
  filtersPanel?: ReactNode
}

/**
 * One toolbar row above a collection: filters at the start, table tools at the
 * end. Pages render it on its own while the table is loading or unavailable so
 * the filters keep their place.
 */
export function CollectionToolbar({
  filters,
  tools,
  panel,
}: {
  filters?: ReactNode
  tools?: ReactNode
  panel?: ReactNode
}) {
  return (
    <div className="resource-collection-toolbar">
      <div className="min-w-0 flex-1">{filters}</div>
      {tools ? (
        <div className="flex shrink-0 items-center gap-2">{tools}</div>
      ) : null}
      {panel ? <div className="min-w-0 basis-full">{panel}</div> : null}
    </div>
  )
}

export type ResourceTableControls = Pick<
  ResourceTableProps<{ id: string }>,
  | 'order'
  | 'onOrderChange'
  | 'onRefresh'
  | 'pagination'
  | 'emptyState'
  | 'refreshing'
  | 'filters'
  | 'filtersPanel'
>

export function ResourceTable<T extends { id: string }>({
  id,
  label,
  items,
  columns,
  order,
  onOrderChange,
  onRefresh,
  pagination,
  emptyState,
  refreshing = false,
  density,
  maxHeight,
  filters,
  filtersPanel,
}: ResourceTableProps<T>) {
  const t = useTranslator()
  const storageKey = `identity.console.table.${id}.v1`
  const [preferences, setPreferences] = useState(() =>
    readPreferences(storageKey),
  )
  const [draft, setDraft] = useState(preferences)
  const [open, setOpen] = useState(false)
  const visible = columns.filter(
    (column) => column.primary || !preferences.hidden.includes(column.id),
  )
  const sorted = columns.find(
    (column) => column.sort && order?.startsWith(`${column.sort}_`),
  )
  const sortDescriptor = sorted
    ? {
        column: sorted.id,
        direction: order?.endsWith('_ASC')
          ? ('ascending' as const)
          : ('descending' as const),
      }
    : undefined

  function save(next: TablePreferences) {
    setPreferences(next)
    try {
      localStorage.setItem(storageKey, JSON.stringify(next))
    } catch {
      // Display preferences remain usable when browser storage is unavailable.
    }
    setOpen(false)
  }

  return (
    <section className="resource-collection" aria-label={label}>
      <CollectionToolbar
        filters={filters}
        panel={filtersPanel}
        tools={
        <>
          <Button
            variant="outline"
            size="icon"
            aria-label={t('tableRefresh')}
            disabled={refreshing}
            onClick={onRefresh}
          >
            <RefreshCw className="size-4" aria-hidden="true" />
          </Button>
          <Popover
            open={open}
            onOpenChange={(next) => {
              if (next) setDraft(preferences)
              setOpen(next)
            }}
          >
            <PopoverTrigger
              render={
                <Button
                  variant="outline"
                  size="icon"
                  aria-label={t('tablePreferences')}
                />
              }
            >
              <Settings2 className="size-4" aria-hidden="true" />
            </PopoverTrigger>
            <PopoverContent
              align="end"
              role="dialog"
              aria-label={t('tablePreferences')}
              className="w-72 max-w-[calc(100vw-2rem)]"
            >
              <h2 className="text-sm font-semibold">{t('tablePreferences')}</h2>
              <div className="mt-4 space-y-3">
                {density === undefined ? (
                  <label className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={draft.compact}
                      onCheckedChange={(compact) => setDraft({ ...draft, compact })}
                    />
                    {t('tableCompact')}
                  </label>
                ) : null}
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={draft.wrap}
                    onCheckedChange={(wrap) => setDraft({ ...draft, wrap })}
                  />
                  {t('tableWrap')}
                </label>
              </div>
              <fieldset className="mt-4 space-y-3 border-t border-border pt-3">
                <legend className="text-sm font-medium">
                  {t('tableVisibleColumns')}
                </legend>
                {columns.map((column) => (
                  <label key={column.id} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={Boolean(
                        column.primary || !draft.hidden.includes(column.id),
                      )}
                      disabled={column.primary}
                      onCheckedChange={(selected) =>
                        setDraft({
                          ...draft,
                          hidden: selected
                            ? draft.hidden.filter((key) => key !== column.id)
                            : [...draft.hidden, column.id],
                        })
                      }
                    />
                    {column.label}
                  </label>
                ))}
              </fieldset>
              <div className="mt-5 flex flex-wrap justify-end gap-2">
                <Button variant="ghost" size="sm" onClick={() => setDraft(defaults)}>
                  {t('tableResetPreferences')}
                </Button>
                <Button variant="outline" size="sm" onClick={() => setOpen(false)}>
                  {t('tableCancel')}
                </Button>
                <Button size="sm" onClick={() => save(draft)}>
                  {t('tableApplyPreferences')}
                </Button>
              </div>
            </PopoverContent>
          </Popover>
        </>
        }
      />
      <DataTable
        label={label}
        loading={refreshing}
        loadingLabel={t('tableLoading')}
        loadingRows={items.length}
        columns={visible.map((column) => ({
          ...column,
          allowsSorting: Boolean(column.sort),
        }))}
        density={density ?? (preferences.compact ? 'compact' : 'comfortable')}
        maxHeight={maxHeight}
        wrap={preferences.wrap}
        sortDescriptor={sortDescriptor}
        onSortChange={(descriptor) => {
          const column = columns.find(
            (candidate) => candidate.id === descriptor.column,
          )
          if (column?.sort)
            onOrderChange(
              sorted?.id === column.id &&
                sortDescriptor?.direction === 'descending'
                ? undefined
                : `${column.sort}_${descriptor.direction === 'ascending' ? 'ASC' : 'DESC'}`,
            )
        }}
      >
        <DataTable.Body
          items={items}
          dependencies={[visible]}
          renderEmptyState={() => (
            <div className="resource-table-empty">{emptyState}</div>
          )}
        >
          {(item: T) => (
            <DataTable.Row key={item.id} id={item.id} columns={visible}>
              {(column: ResourceColumn<T>) => (
                <DataTable.Cell key={column.id}>{column.render(item)}</DataTable.Cell>
              )}
            </DataTable.Row>
          )}
        </DataTable.Body>
      </DataTable>
      {pagination ? (
        <div className="resource-collection-pagination">{pagination}</div>
      ) : null}
    </section>
  )
}
