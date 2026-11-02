import { Link, useMatches } from '@tanstack/react-router'
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { useTranslator, type MessageKey } from '#/lib/i18n'

interface BreadcrumbDefinition {
  label: MessageKey
  to?: string
  link?: boolean
}

declare module '@tanstack/react-router' {
  interface StaticDataRouteOption {
    breadcrumbs?: readonly BreadcrumbDefinition[]
  }
}

interface Breadcrumb {
  label: string
  href?: string
}

const BreadcrumbContext = createContext<{
  labels: Record<string, { label: string; owner: symbol }>
  register: (path: string, label: string) => () => void
} | null>(null)

export function BreadcrumbProvider({ children }: { children: ReactNode }) {
  const [labels, setLabels] = useState<
    Record<string, { label: string; owner: symbol }>
  >({})
  const register = useCallback((path: string, label: string) => {
    const owner = Symbol()
    setLabels((current) => ({ ...current, [path]: { label, owner } }))
    return () => {
      setLabels((current) => {
        if (current[path]?.owner !== owner) return current
        const next = { ...current }
        delete next[path]
        return next
      })
    }
  }, [])
  const value = useMemo(() => ({ labels, register }), [labels, register])
  return (
    <BreadcrumbContext.Provider value={value}>
      {children}
    </BreadcrumbContext.Provider>
  )
}

/** Reuse already authorized detail data; breadcrumbs never fetch identities. */
export function useBreadcrumbLabel(path: string, label: string | undefined) {
  const register = useContext(BreadcrumbContext)?.register
  useEffect(() => {
    if (register && label) return register(path, label)
  }, [register, path, label])
}

export function usePageBreadcrumbs(): Breadcrumb[] {
  const t = useTranslator()
  const matches = useMatches()
  const labels = useContext(BreadcrumbContext)?.labels
  return matches.flatMap((match) =>
    (match.staticData.breadcrumbs ?? []).map((definition) => {
      const path = definition.to
        ? definition.to.replace(/\$([^/]+)/g, (_, key: string) =>
            encodeURIComponent((match.params as Record<string, string>)[key]),
          )
        : match.pathname.replace(/\/+$/, '') || '/'
      return {
        label:
          definition.link === false
            ? t(definition.label)
            : (labels?.[path]?.label ?? t(definition.label)),
        href: definition.link === false ? undefined : path,
      }
    }),
  )
}

export function AppBreadcrumbs({ items }: { items: readonly Breadcrumb[] }) {
  const t = useTranslator()
  return (
    <nav aria-label={t('breadcrumbLabel')} className="hidden md:block">
      <ol className="flex min-w-0 items-center gap-1.5 overflow-hidden text-xs text-muted">
        {items.map((item, index) => {
          const current = index === items.length - 1
          return (
            <li key={index} className="flex min-w-0 items-center gap-1.5">
              {index > 0 ? <span aria-hidden="true">/</span> : null}
              {item.href && !current ? (
                <Link
                  to={item.href}
                  className="max-w-48 truncate hover:text-foreground hover:underline"
                  title={item.label}
                >
                  {item.label}
                </Link>
              ) : (
                <span
                  aria-current={current ? 'page' : undefined}
                  className={`truncate ${current ? 'font-medium text-foreground' : ''}`}
                  title={item.label}
                >
                  {item.label}
                </span>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
