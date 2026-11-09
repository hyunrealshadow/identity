import { Skeleton } from '@identity/ui/components/skeleton'
import { createContext, useContext, type ReactNode } from 'react'

/** Row padding inside a {@link SettingsGroup}; compact matches table cells. */
const SettingsDensity = createContext<'comfortable' | 'compact'>('comfortable')

/**
 * A titled list of settings. The title sits above the list; the list is one
 * surface with a divider between rows. `action` adds a control to the title
 * line, `footer` closes the list (for example with its save button).
 */
export function SettingsGroup({
  title,
  description,
  action,
  tone = 'default',
  density = 'comfortable',
  footer,
  children,
}: {
  title: string
  description?: string
  action?: ReactNode
  tone?: 'default' | 'danger'
  /** `compact` gives rows the same padding as data table cells. */
  density?: 'comfortable' | 'compact'
  footer?: ReactNode
  children: ReactNode
}) {
  const danger = tone === 'danger'
  return (
    <section>
      <div className="mb-2 flex min-h-8 items-center justify-between gap-3 px-1">
        <div className="min-w-0">
          <h2 className={`text-sm font-semibold ${danger ? 'text-destructive' : ''}`}>{title}</h2>
          {description ? (
            <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {action}
      </div>
      <div
        className={`divide-y divide-border overflow-hidden rounded-xl border bg-card ${
          danger ? 'console-card-danger border-destructive' : 'console-card border-border'
        }`}
      >
        <SettingsDensity.Provider value={density}>{children}</SettingsDensity.Provider>
        {footer ? (
          <div className="flex flex-wrap items-center justify-end gap-3 px-5 py-4">{footer}</div>
        ) : null}
      </div>
    </section>
  )
}

/**
 * One setting: its name and a short explanation, with the control at the end
 * of the row. A wide control (a text area, a translation editor) goes in
 * `children`, below the text and across the full row.
 */
export function SettingsRow({
  label,
  description,
  icon,
  action,
  children,
}: {
  label?: ReactNode
  description?: ReactNode
  icon?: ReactNode
  action?: ReactNode
  children?: ReactNode
}) {
  const heading = label || description || icon || action
  const compact = useContext(SettingsDensity) === 'compact'
  return (
    <div className={compact ? 'px-3 py-2' : 'px-5 py-4'}>
      {heading ? (
        <div className="flex items-center gap-3">
          {icon ? (
            <span
              className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground"
              aria-hidden="true"
            >
              {icon}
            </span>
          ) : null}
          <div className="min-w-0 flex-1">
            {label ? <div className="text-sm font-medium">{label}</div> : null}
            {description ? (
              <div className="mt-0.5 text-xs leading-5 text-muted-foreground">{description}</div>
            ) : null}
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </div>
      ) : null}
      {children ? <div className={heading ? 'mt-3' : undefined}>{children}</div> : null}
    </div>
  )
}

/** The shape of one row a {@link SettingsGroupSkeleton} stands in for. */
export type SettingsRowSkeletonKind =
  /** A label and description with a switch at the end. */
  | 'switch'
  /** A label and description with a select or button at the end. */
  | 'control'
  /** A label with a short value at the end. */
  | 'value'
  /** A label and description above a text area. */
  | 'textarea'
  /** A default value beside a translation editor. */
  | 'localized'
  /** A default text area beside a translation editor. */
  | 'localizedTextarea'

function RowTextSkeleton({ description }: { description: boolean }) {
  return (
    <div className="min-w-0 flex-1 space-y-2">
      <Skeleton className="h-4 w-32 rounded-lg" />
      {description ? <Skeleton className="h-3 w-64 max-w-full rounded-lg" /> : null}
    </div>
  )
}

function LocalizedSkeleton({ field }: { field: string }) {
  return (
    <div className="space-y-3">
      <Skeleton className="h-4 w-16 rounded-lg" />
      <div className="grid gap-4 md:grid-cols-2">
        {[0, 1].map((column) => (
          <div key={column} className="space-y-2">
            <Skeleton className="h-4 w-20 rounded-lg" />
            <Skeleton className={`${field} w-full rounded-lg`} />
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * Loading stand-in for a {@link SettingsGroup} with the same title spacing,
 * card and row padding, so the page keeps its layout once data arrives.
 */
export function SettingsGroupSkeleton({
  rows,
  description = false,
}: {
  rows: readonly SettingsRowSkeletonKind[]
  description?: boolean
}) {
  return (
    <section aria-hidden="true">
      <div className="mb-2 flex min-h-8 flex-col justify-center gap-1.5 px-1">
        <Skeleton className="h-4 w-24 rounded-lg" />
        {description ? <Skeleton className="h-3 w-56 rounded-lg" /> : null}
      </div>
      <div className="console-card divide-y divide-border overflow-hidden rounded-xl border border-border bg-card">
        {rows.map((kind, index) => (
          <div key={index} className="px-5 py-4">
            {kind === 'localized' || kind === 'localizedTextarea' ? (
              <LocalizedSkeleton field={kind === 'localized' ? 'h-10' : 'h-24'} />
            ) : kind === 'textarea' ? (
              <div className="space-y-3">
                <RowTextSkeleton description />
                <Skeleton className="h-20 w-full rounded-lg" />
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <RowTextSkeleton description={kind !== 'value'} />
                {kind === 'switch' ? (
                  <Skeleton className="h-5 w-10 shrink-0 rounded-full" />
                ) : kind === 'control' ? (
                  <Skeleton className="h-9 w-36 shrink-0 rounded-lg" />
                ) : (
                  <Skeleton className="h-4 w-36 shrink-0 rounded-lg" />
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}
