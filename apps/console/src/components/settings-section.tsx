import type { ReactNode } from 'react'

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
  footer,
  children,
}: {
  title: string
  description?: string
  action?: ReactNode
  tone?: 'default' | 'danger'
  footer?: ReactNode
  children: ReactNode
}) {
  const danger = tone === 'danger'
  return (
    <section>
      <div className="mb-2 flex min-h-8 items-center justify-between gap-3 px-1">
        <div className="min-w-0">
          <h2 className={`text-sm font-semibold ${danger ? 'text-danger' : ''}`}>{title}</h2>
          {description ? (
            <p className="mt-0.5 text-xs leading-5 text-muted">{description}</p>
          ) : null}
        </div>
        {action}
      </div>
      <div
        className={`divide-y divide-separator overflow-hidden rounded-3xl border bg-surface ${
          danger ? 'console-card-danger border-danger' : 'console-card border-border'
        }`}
      >
        {children}
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
  return (
    <div className="px-5 py-4">
      {heading ? (
        <div className="flex items-center gap-3">
          {icon ? (
            <span
              className="flex size-9 shrink-0 items-center justify-center rounded-field bg-surface-secondary text-muted"
              aria-hidden="true"
            >
              {icon}
            </span>
          ) : null}
          <div className="min-w-0 flex-1">
            {label ? <div className="text-sm font-medium">{label}</div> : null}
            {description ? (
              <div className="mt-0.5 text-xs leading-5 text-muted">{description}</div>
            ) : null}
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </div>
      ) : null}
      {children ? <div className={heading ? 'mt-3' : undefined}>{children}</div> : null}
    </div>
  )
}
