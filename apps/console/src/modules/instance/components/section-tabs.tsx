import { Link } from '@tanstack/react-router'

import { useTranslator, type MessageKey } from '#/lib/i18n'

/** Pages that head a section of an instance area. */
export type SectionPath =
  | '/settings'
  | '/settings/protocol'
  | '/settings/authentication'
  | '/settings/signing-keys'
  | '/settings/encryption-keys'
  | '/email'
  | '/email/templates'

export interface SectionTab<Path extends SectionPath = SectionPath> {
  to: Path
  label: MessageKey
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
    <nav aria-label={label} className="mb-6 border-b border-border">
      <div className="flex gap-1 overflow-x-auto">
        {tabs
          .filter((tab) => tab.to === current || visible(tab))
          .map((tab) => {
            const active = tab.to === current
            return (
              <Link
                key={tab.to}
                to={tab.to}
                className={
                  'shrink-0 border-b-2 px-3 py-2.5 text-sm ' +
                  (active ? 'border-primary font-semibold' : 'border-transparent text-muted-foreground')
                }
                aria-current={active ? 'page' : undefined}
              >
                {t(tab.label)}
              </Link>
            )
          })}
      </div>
    </nav>
  )
}
