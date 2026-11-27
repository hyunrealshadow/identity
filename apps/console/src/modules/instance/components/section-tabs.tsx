import { Link } from '@tanstack/react-router'
import type { LucideIcon } from 'lucide-react'

import { useTranslator, type MessageKey } from '#/lib/i18n'

/** Pages that head a section of an instance area. */
export type SectionPath =
  | '/settings'
  | '/settings/protocol'
  | '/settings/authentication'
  | '/settings/session'
  | '/settings/signing-keys'
  | '/settings/encryption-keys'
  | '/email'
  | '/email/policies'
  | '/email/templates'

export interface SectionTab<Path extends SectionPath = SectionPath> {
  to: Path
  label: MessageKey
  icon?: LucideIcon
}

/**
 * The tab whose path is `pathname` or contains it: a nested page such as a
 * template editor keeps its section tab selected. The first tab is the
 * section's index and is selected otherwise.
 */
export function activeSectionTab<Path extends SectionPath>(
  tabs: ReadonlyArray<SectionTab<Path>>,
  pathname: string,
): Path | undefined {
  const path = pathname.replace(/\/+$/u, '')
  const [index, ...rest] = tabs
  const nested = [...rest]
    .sort((a, b) => b.to.length - a.to.length)
    .find((tab) => path.endsWith(tab.to) || path.includes(`${tab.to}/`))
  return nested?.to ?? index?.to
}

/** The row of links between an instance area's sections. */
export function SectionTabs<Tab extends SectionTab>({
  label,
  tabs,
  pathname,
  visible = () => true,
}: {
  label: string
  tabs: ReadonlyArray<Tab>
  pathname: string
  visible?: (tab: Tab) => boolean
}) {
  const t = useTranslator()
  const current = activeSectionTab<SectionPath>(tabs, pathname)
  return (
    <nav
      aria-label={label}
      className="mb-6 overflow-x-auto overflow-y-hidden border-b border-border"
    >
      <ul className="flex min-w-max items-center gap-1">
        {tabs
          .filter((tab) => tab.to === current || visible(tab))
          .map((tab) => {
            const Icon = tab.icon
            const active = tab.to === current
            return (
              <li key={tab.to}>
                <Link
                  to={tab.to}
                  className={
                    '-mb-px inline-flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring ' +
                    (active
                      ? 'border-primary font-semibold text-foreground'
                      : 'border-transparent text-muted-foreground hover:border-border hover:text-foreground')
                  }
                  aria-current={active ? 'page' : undefined}
                >
                  {Icon ? <Icon className="size-4" aria-hidden="true" /> : null}
                  {t(tab.label)}
                </Link>
              </li>
            )
          })}
      </ul>
    </nav>
  )
}
