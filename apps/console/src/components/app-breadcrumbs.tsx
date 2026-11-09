import { Link, useMatches } from '@tanstack/react-router'
import {
  Breadcrumb as BreadcrumbRoot,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@identity/ui/components/breadcrumb'
import {
  Fragment,
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
    <BreadcrumbRoot aria-label={t('breadcrumbLabel')} className="hidden min-w-0 md:block">
      <BreadcrumbList className="flex-nowrap gap-1.5 overflow-hidden text-xs sm:gap-1.5">
        {items.map((item, index) => {
          const current = index === items.length - 1
          return (
            <Fragment key={index}>
              {index > 0 ? <BreadcrumbSeparator /> : null}
              <BreadcrumbItem className="min-w-0">
                {item.href && !current ? (
                  <BreadcrumbLink
                    className="max-w-48 truncate"
                    title={item.label}
                    render={<Link to={item.href} activeOptions={{ exact: true }} />}
                  >
                    {item.label}
                  </BreadcrumbLink>
                ) : current ? (
                  <BreadcrumbPage className="truncate font-medium" title={item.label}>
                    {item.label}
                  </BreadcrumbPage>
                ) : (
                  <span className="truncate" title={item.label}>
                    {item.label}
                  </span>
                )}
              </BreadcrumbItem>
            </Fragment>
          )
        })}
      </BreadcrumbList>
    </BreadcrumbRoot>
  )
}
