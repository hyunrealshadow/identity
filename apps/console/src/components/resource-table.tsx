import { DataTable } from '@identity/ui/data-table'
import { Button, Checkbox, Label, Popover } from '@heroui/react'
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
}

export type ResourceTableControls = Pick<
  ResourceTableProps<{ id: string }>,
  | 'order'
  | 'onOrderChange'
  | 'onRefresh'
  | 'pagination'
  | 'emptyState'
  | 'refreshing'
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
      <div className="resource-collection-toolbar">
        <div className="flex items-center gap-2">
          <Button
            isIconOnly
            variant="tertiary"
            size="sm"
            aria-label={t('tableRefresh')}
            isDisabled={refreshing}
            onPress={onRefresh}
          >
            <RefreshCw className="size-4" aria-hidden="true" />
          </Button>
          <Popover
            isOpen={open}
            onOpenChange={(next) => {
              if (next) setDraft(preferences)
              setOpen(next)
            }}
          >
            <Button
              isIconOnly
              variant="tertiary"
              size="sm"
              aria-label={t('tablePreferences')}
            >
              <Settings2 className="size-4" aria-hidden="true" />
            </Button>
            <Popover.Content
              placement="bottom end"
              className="w-72 max-w-[calc(100vw-2rem)]"
            >
              <Popover.Dialog>
                <Popover.Heading>{t('tablePreferences')}</Popover.Heading>
                <div className="mt-4 space-y-3">
                  {density === undefined ? (
                    <Checkbox
                      isSelected={draft.compact}
                      onChange={(compact) => setDraft({ ...draft, compact })}
                    >
                      <Checkbox.Content>
                        <Checkbox.Control>
                          <Checkbox.Indicator />
                        </Checkbox.Control>
                        <Label>{t('tableCompact')}</Label>
                      </Checkbox.Content>
                    </Checkbox>
                  ) : null}
                  <Checkbox
                    isSelected={draft.wrap}
                    onChange={(wrap) => setDraft({ ...draft, wrap })}
                  >
                    <Checkbox.Content>
                      <Checkbox.Control>
                        <Checkbox.Indicator />
                      </Checkbox.Control>
                      <Label>{t('tableWrap')}</Label>
                    </Checkbox.Content>
                  </Checkbox>
                </div>
                <fieldset className="mt-4 space-y-3 border-t border-separator pt-3">
                  <legend className="text-sm font-medium">
                    {t('tableVisibleColumns')}
                  </legend>
                  {columns.map((column) => (
                    <Checkbox
                      key={column.id}
                      isSelected={Boolean(
                        column.primary || !draft.hidden.includes(column.id),
                      )}
                      isDisabled={column.primary}
                      onChange={(selected) =>
                        setDraft({
                          ...draft,
                          hidden: selected
                            ? draft.hidden.filter((key) => key !== column.id)
                            : [...draft.hidden, column.id],
                        })
                      }
                    >
                      <Checkbox.Content>
                        <Checkbox.Control>
                          <Checkbox.Indicator />
                        </Checkbox.Control>
                        <Label>{column.label}</Label>
                      </Checkbox.Content>
                    </Checkbox>
                  ))}
                </fieldset>
                <div className="mt-5 flex flex-wrap justify-end gap-2">
                  <Button
                    variant="tertiary"
                    size="sm"
                    onPress={() => setDraft(defaults)}
                  >
                    {t('tableResetPreferences')}
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    onPress={() => setOpen(false)}
                  >
                    {t('tableCancel')}
                  </Button>
                  <Button size="sm" onPress={() => save(draft)}>
                    {t('tableApplyPreferences')}
                  </Button>
                </div>
              </Popover.Dialog>
            </Popover.Content>
          </Popover>
        </div>
      </div>
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
          {(item) => (
            <DataTable.Row id={item.id} columns={visible}>
              {(column) => (
                <DataTable.Cell>{column.render(item)}</DataTable.Cell>
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
