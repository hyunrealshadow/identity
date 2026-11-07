import { Skeleton, Table } from '@heroui/react'
import {
  useEffect,
  useRef,
  type ComponentProps,
  type CSSProperties,
  type ReactNode,
} from 'react'

export interface DataTableColumn {
  id: string
  label: ReactNode
  primary?: boolean
  allowsSorting?: boolean
}

interface DataTableProps {
  label: string
  columns: readonly DataTableColumn[]
  children: ReactNode
  minWidth?: number
  maxHeight?: CSSProperties['maxHeight']
  density?: 'compact' | 'comfortable'
  /** `primary` (the default) sets the rows on a white surface inside the header's frame. */
  variant?: 'primary' | 'secondary'
  wrap?: boolean
  loading?: boolean
  loadingLabel?: string
  loadingRows?: number
  sortDescriptor?: ComponentProps<typeof Table.Content>['sortDescriptor']
  onSortChange?: ComponentProps<typeof Table.Content>['onSortChange']
}

function DataTableRoot({
  label,
  columns,
  children,
  minWidth = 760,
  maxHeight,
  density = 'comfortable',
  variant = 'primary',
  wrap,
  loading = false,
  loadingLabel,
  loadingRows = 5,
  sortDescriptor,
  onSortChange,
}: DataTableProps) {
  const table = useRef<HTMLTableElement>(null)
  const bodyHeight = useRef<number | undefined>(undefined)
  const tableWidth = useRef<number | undefined>(undefined)
  const columnWidths = useRef<Record<string, number>>({})

  useEffect(() => {
    if (loading || !table.current) return
    const element = table.current
    const measure = () => {
      const height = element
        .querySelector('tbody')
        ?.getBoundingClientRect().height
      if (height) bodyHeight.current = height
      const width = element.getBoundingClientRect().width
      if (width) tableWidth.current = width
      const widths: Record<string, number> = {}
      for (const column of element.querySelectorAll<HTMLElement>(
        'thead [data-key]',
      )) {
        const key = column.dataset.key
        if (key) widths[key] = column.getBoundingClientRect().width
      }
      columnWidths.current = widths
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(element)
    return () => observer.disconnect()
  }, [children, loading])

  return (
    <Table variant={variant} className="identity-data-table">
      <Table.ScrollContainer
        className="identity-data-table-scroll"
        style={{ maxHeight }}
        data-bounded={maxHeight !== undefined || undefined}
        role="region"
        aria-label={label}
        aria-busy={loading || undefined}
        tabIndex={0}
      >
        <Table.Content
          ref={table}
          aria-label={label}
          style={{
            minWidth,
            width: loading ? tableWidth.current : undefined,
            tableLayout: loading ? 'fixed' : undefined,
          }}
          data-density={density}
          data-wrap={wrap || undefined}
          sortDescriptor={sortDescriptor}
          onSortChange={loading ? undefined : onSortChange}
        >
          <Table.Header
            columns={columns}
            className={
              maxHeight !== undefined
                ? 'sticky top-0 z-10 bg-surface-secondary'
                : undefined
            }
          >
            {(column) => (
              <Table.Column
                id={column.id}
                isRowHeader={column.primary}
                allowsSorting={column.allowsSorting}
                style={
                  loading
                    ? { width: columnWidths.current[column.id] }
                    : undefined
                }
              >
                {({ sortDirection }) =>
                  column.allowsSorting ? (
                    <Table.SortableColumnHeader sortDirection={sortDirection}>
                      {column.label}
                    </Table.SortableColumnHeader>
                  ) : (
                    column.label
                  )
                }
              </Table.Column>
            )}
          </Table.Header>
          {loading ? (
            <Table.Body key="loading">
              {Array.from({ length: Math.max(1, loadingRows) }, (_, index) => (
                <Table.Row
                  id={`loading-${index}`}
                  key={index}
                  columns={columns}
                  style={{
                    height: bodyHeight.current
                      ? bodyHeight.current / Math.max(1, loadingRows)
                      : undefined,
                  }}
                >
                  {(column) => (
                    <Table.Cell>
                      {index === 0 && column.id === columns[0]?.id ? (
                        <span role="status" className="sr-only">
                          {loadingLabel}
                        </span>
                      ) : null}
                      <Skeleton
                        className="h-8 w-full rounded-field"
                        aria-hidden="true"
                      />
                    </Table.Cell>
                  )}
                </Table.Row>
              ))}
            </Table.Body>
          ) : (
            children
          )}
        </Table.Content>
      </Table.ScrollContainer>
    </Table>
  )
}

export const DataTable = Object.assign(DataTableRoot, {
  Body: Table.Body,
  Row: Table.Row,
  Cell: Table.Cell,
})
