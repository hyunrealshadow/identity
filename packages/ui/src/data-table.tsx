import * as React from 'react'
import { Skeleton } from './components/skeleton'
import { cn } from 'cn'
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import {
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from 'react'

const TableContext = React.createContext<{
  primaryIndex: number
  columnCount: number
}>({
  primaryIndex: -1,
  columnCount: 1,
})

export interface DataTableColumn {
  id: string
  label: ReactNode
  primary?: boolean
  allowsSorting?: boolean
}

export interface DataTableSortDescriptor {
  column: string
  direction: 'ascending' | 'descending'
}

interface DataTableProps {
  label: string
  columns: readonly DataTableColumn[]
  children: ReactNode
  minWidth?: number
  maxHeight?: CSSProperties['maxHeight']
  density?: 'compact' | 'comfortable'
  /** Kept for layout parity; both variants share the same bordered surface. */
  variant?: 'primary' | 'secondary'
  wrap?: boolean
  loading?: boolean
  loadingLabel?: string
  loadingRows?: number
  sortDescriptor?: DataTableSortDescriptor
  onSortChange?: (descriptor: DataTableSortDescriptor) => void
}

interface MeasuredTableWidths {
  tableWidth?: number
  tbodyHeight?: number
  columnWidths: Record<string, number>
}

function sameMeasuredWidths(
  previous: MeasuredTableWidths,
  next: MeasuredTableWidths,
): boolean {
  if (previous.tableWidth !== next.tableWidth) return false
  if (previous.tbodyHeight !== next.tbodyHeight) return false
  const prevKeys = Object.keys(previous.columnWidths)
  const nextKeys = Object.keys(next.columnWidths)
  if (prevKeys.length !== nextKeys.length) return false
  return nextKeys.every(
    (key) => previous.columnWidths[key] === next.columnWidths[key],
  )
}

const headerCell =
  'h-9 text-start align-middle text-xs font-medium whitespace-nowrap text-muted-foreground px-3 py-2 group-data-[density=compact]:px-2 group-data-[density=compact]:py-1.5'

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
  const [measured, setMeasured] = useState<MeasuredTableWidths>({
    columnWidths: {},
  })

  useEffect(() => {
    if (loading || !table.current) return
    const element = table.current
    const measure = () => {
      const width = element.getBoundingClientRect().width
      const tbodyHeight = element.querySelector('tbody')?.getBoundingClientRect().height
      const columnWidths: Record<string, number> = {}
      for (const column of element.querySelectorAll<HTMLElement>(
        'thead th[data-key]',
      )) {
        const key = column.dataset.key
        if (key) columnWidths[key] = column.getBoundingClientRect().width
      }
      setMeasured((previous) => {
        const next: MeasuredTableWidths = {
          tableWidth: width || previous.tableWidth,
          tbodyHeight: tbodyHeight || previous.tbodyHeight,
          columnWidths,
        }
        return sameMeasuredWidths(previous, next) ? previous : next
      })
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(measure)
    observer.observe(element)
    return () => observer.disconnect()
  }, [loading, columns.length])

  function toggleSort(id: string) {
    if (!onSortChange || loading) return
    const direction =
      sortDescriptor?.column === id && sortDescriptor.direction === 'ascending'
        ? 'descending'
        : 'ascending'
    onSortChange({ column: id, direction })
  }

  const primaryIndex = columns.findIndex((column) => Boolean(column.primary))
  return (
    <TableContext.Provider
      value={{ primaryIndex, columnCount: columns.length }}
    >
      <div
        className="relative w-full overflow-auto rounded-lg border border-border bg-card"
        style={{ maxHeight }}
        data-bounded={maxHeight !== undefined || undefined}
        role="region"
        aria-label={label}
        aria-busy={loading || undefined}
        tabIndex={0}
      >
        <table
          ref={table}
          role="grid"
          aria-label={label}
          className="group w-full caption-bottom border-collapse text-sm"
          style={{
            minWidth,
            width: loading ? measured.tableWidth : undefined,
            tableLayout: loading ? 'fixed' : undefined,
          }}
          data-density={density}
          data-wrap={wrap || undefined}
          data-variant={variant}
        >
          <thead
            className={
              maxHeight !== undefined ? 'sticky top-0 z-10 bg-muted' : 'bg-muted/50'
            }
          >
            <tr className="border-b border-border">
              {columns.map((column) => {
                const active = sortDescriptor?.column === column.id
                const ascending =
                  active && sortDescriptor?.direction === 'ascending'
                const Icon = active
                  ? ascending
                    ? ArrowUp
                    : ArrowDown
                  : ArrowUpDown
                return (
                  <th
                    key={column.id}
                    data-key={column.id}
                    scope="col"
                    aria-sort={
                      active
                        ? ascending
                          ? 'ascending'
                          : 'descending'
                        : undefined
                    }
                    className={headerCell}
                    style={
                      loading
                        ? { width: measured.columnWidths[column.id] }
                        : undefined
                    }
                  >
                    {column.allowsSorting && onSortChange ? (
                      <button
                        type="button"
                        disabled={loading}
                        onClick={() => toggleSort(column.id)}
                        className="inline-flex w-full cursor-pointer items-center gap-1 rounded-sm text-start hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50"
                      >
                        {column.label}
                        <Icon className="size-3.5" aria-hidden="true" />
                      </button>
                    ) : (
                      column.label
                    )}
                  </th>
                )
              })}
            </tr>
          </thead>
          {loading ? (
            <tbody style={measured.tbodyHeight ? { height: measured.tbodyHeight } : undefined}>
              {Array.from({ length: Math.max(1, loadingRows) }, (_, index) => (
                <tr key={index} className="border-b border-border last:border-0">
                  {columns.map((column) => (
                    <td
                      key={column.id}
                      className="px-3 py-2 align-middle group-data-[density=compact]:px-2 group-data-[density=compact]:py-1.5"
                    >
                      {index === 0 && column.id === columns[0]?.id ? (
                        <span role="status" className="sr-only">
                          {loadingLabel}
                        </span>
                      ) : null}
                      <Skeleton className="h-8 w-full" aria-hidden="true" />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          ) : (
            children
          )}
        </table>
      </div>
    </TableContext.Provider>
  )
}

function DataTableBody<T = unknown>({
  children,
  items,
  dependencies: _dependencies,
  renderEmptyState,
}: {
  children?: ReactNode | ((item: T, index: number) => ReactNode)
  items?: readonly T[]
  dependencies?: readonly unknown[]
  renderEmptyState?: () => ReactNode
}) {
  const { columnCount } = React.useContext(TableContext)
  const rows = items
    ? items.map((item, index) =>
        typeof children === 'function' ? children(item, index) : null,
      )
    : Array.isArray(children)
      ? children.filter(Boolean)
      : children
        ? [children]
        : []
  if (rows.length === 0 && renderEmptyState) {
    return (
      <tbody>
        <tr>
          <td colSpan={Math.max(1, columnCount)} className="text-center">
            {renderEmptyState()}
          </td>
        </tr>
      </tbody>
    )
  }
  return <tbody>{rows}</tbody>
}

function DataTableRow<C = DataTableColumn>({
  id,
  children,
  className,
  columns,
  ...props
}: Omit<React.ComponentProps<'tr'>, 'children'> & {
  id?: string | number
  onAction?: () => void
  textValue?: string
  columns?: readonly C[]
  children?: ReactNode | ((value: C) => ReactNode)
}) {
  const { primaryIndex: contextPrimaryIndex } = React.useContext(TableContext)
  const { onAction: _onAction, textValue: _textValue, ...rest } = props
  const primaryIndex =
    columns && typeof children === 'function'
      ? columns.findIndex((column) =>
          Boolean((column as { primary?: boolean }).primary),
        )
      : contextPrimaryIndex
  const cells: ReactNode =
    columns && typeof children === 'function'
      ? React.Children.map(
          columns.map((column) => children(column)),
          (cell, index) =>
            React.isValidElement(cell) && index === primaryIndex
              ? React.cloneElement(
                  cell as React.ReactElement<{ rowHeader?: boolean }>,
                  {
                    rowHeader: true,
                  },
                )
              : cell,
        )
      : React.Children.map(children as ReactNode, (cell, index) =>
          React.isValidElement(cell) && index === primaryIndex
            ? React.cloneElement(
                cell as React.ReactElement<{ rowHeader?: boolean }>,
                {
                  rowHeader: true,
                },
              )
            : cell,
        )
  return (
    <tr
      data-key={id}
      className={cn(
        'border-b border-border transition-colors last:border-0 hover:bg-muted/40',
        className,
      )}
      {...rest}
    >
      {cells}
    </tr>
  )
}

function DataTableCell({
  children,
  className,
  rowHeader = false,
  ...props
}: React.ComponentProps<'td'> & { textValue?: string; rowHeader?: boolean }) {
  const { textValue: _textValue, ...rest } = props
  return (
    <td
      role={rowHeader ? 'rowheader' : undefined}
      className={cn(
        'align-middle px-3 py-2 whitespace-nowrap group-data-[density=compact]:px-2 group-data-[density=compact]:py-1.5 group-data-[wrap]:whitespace-normal',
        className,
      )}
      {...rest}
    >
      {children}
    </td>
  )
}

export const DataTable = Object.assign(DataTableRoot, {
  Body: DataTableBody,
  Row: DataTableRow,
  Cell: DataTableCell,
})
