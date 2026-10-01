import { ChevronDown } from 'lucide-react'

import { ScopeConsentStatus } from '#/components/scope-consent-status'
import { scopeDescription, translate, type Locale } from '#/lib/i18n'
import type { ScopeDisplay } from '#/lib/identity-types'

export function ConsentPermissions({ scopes, locale }: { scopes: ScopeDisplay[]; locale: Locale }) {
  return (
    <details open className="group">
      <summary className="flex cursor-pointer list-none items-center gap-3 rounded-sm focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
        <span className="flex-1 text-sm font-medium">{translate(locale, 'permissions')}</span>
        <span className="text-xs text-muted">
          {translate(locale, 'permissionCount', { count: scopes.length })}
        </span>
        <ChevronDown className="size-4 shrink-0 -rotate-90 text-muted transition-transform group-open:rotate-0" aria-hidden="true" />
      </summary>
      <ul className="mt-5 space-y-5">
        {scopes.map((scope) => (
          <li key={scope.name}>
            <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
              <p className="min-w-0 break-all text-sm font-medium">
                {scope.name}
                {scope.essential ? <span className="sr-only"> ({translate(locale, 'required')})</span> : null}
              </p>
              <ScopeConsentStatus granted={scope.previously_granted} locale={locale} />
            </div>
            <p className="mt-1 text-xs leading-5 text-muted">
              {scopeDescription(locale, scope.name, scope.description)}
            </p>
          </li>
        ))}
      </ul>
    </details>
  )
}
