import { ChevronDown, Fingerprint, Mail, MapPin, Phone, RefreshCw, UserRound, type LucideIcon } from 'lucide-react'

import { ScopeConsentStatus } from '#/components/scope-consent-status'
import { translate, type Locale } from '#/lib/i18n'
import type { ScopeDisplay } from '#/lib/identity-types'

const scopeIcons = new Map<string, LucideIcon>([
  ['openid', Fingerprint],
  ['profile', UserRound],
  ['email', Mail],
  ['address', MapPin],
  ['phone', Phone],
  ['offline_access', RefreshCw],
])

export function ConsentPermissions({ scopes, locale }: { scopes: ScopeDisplay[]; locale: Locale }) {
  const hasScopeIcons = scopes.some((scope) => scopeIcons.has(scope.name))

  return (
    <details open className="group">
      <summary className="flex cursor-pointer list-none items-center gap-3 rounded-sm focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
        <span className="flex-1 text-sm font-medium">{translate(locale, 'permissions')}</span>
        <span className="text-xs text-muted">
          {translate(locale, 'permissionCount', { count: scopes.length })}
        </span>
        <ChevronDown className="size-4 shrink-0 -rotate-90 text-muted transition-transform group-open:rotate-0" aria-hidden="true" />
      </summary>
      <ul
        aria-label={translate(locale, 'permissions')}
        tabIndex={0}
        className="consent-permissions-list mt-3 max-h-[min(20rem,40dvh)] space-y-5 overflow-y-auto overscroll-contain rounded-sm pr-2 outline-none [scrollbar-gutter:stable] focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent"
      >
        {scopes.map((scope) => {
          const Icon = scopeIcons.get(scope.name)

          return (
            <li key={scope.name} className={hasScopeIcons ? 'grid grid-cols-[2.25rem_minmax(0,1fr)] items-start gap-3' : undefined}>
              {Icon ? (
                <span className="flex size-9 items-center justify-center rounded-lg bg-surface-secondary text-foreground">
                  <Icon className="size-4" aria-hidden="true" />
                </span>
              ) : null}
              <div className={hasScopeIcons ? 'col-start-2 min-w-0' : 'min-w-0'}>
                <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                  <p className="min-w-0 break-all text-sm font-medium">
                    {scope.display_name || scope.name}
                    {scope.essential ? <span className="sr-only"> ({translate(locale, 'required')})</span> : null}
                  </p>
                  <ScopeConsentStatus granted={scope.previously_granted} locale={locale} />
                </div>
                <p className="mt-0.5 text-xs leading-5 text-muted [overflow-wrap:anywhere]">
                  {scope.descriptions?.[locale] || scope.description}
                </p>
              </div>
            </li>
          )
        })}
      </ul>
    </details>
  )
}
