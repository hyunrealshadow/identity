import { Check } from 'lucide-react'

import { translate, type Locale } from '#/lib/i18n'

export function ScopeConsentStatus({ granted, locale }: { granted?: boolean; locale: Locale }) {
  // Only explicit prior approval gets a marker; missing and pending statuses stay quiet.
  if (granted !== true) return null

  return (
    <span className="inline-flex shrink-0 items-center text-muted" title={translate(locale, 'permissionPreviouslyGranted')}>
      <Check className="size-4" aria-hidden="true" />
      <span className="sr-only">{translate(locale, 'permissionPreviouslyGranted')}</span>
    </span>
  )
}
