import { Check, Clock, X } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { translate, type Locale } from '#/lib/i18n'

export type DeviceOutcome = 'approved' | 'denied' | 'expired'

/** The outcomes a decision can send the browser to as its own page. */
export function decisionOutcome(value: string | undefined): 'approved' | 'denied' | undefined {
  return value === 'approved' || value === 'denied' ? value : undefined
}

const titles = {
  approved: 'deviceApprovedTitle',
  denied: 'deviceDeniedTitle',
  expired: 'deviceExpiredTitle',
} as const

const descriptions = {
  approved: 'deviceApprovedDescription',
  denied: 'deviceDeniedDescription',
  expired: 'deviceExpiredDescription',
} as const

const icons = { approved: Check, denied: X, expired: Clock } as const

/** Final state of a device verification; there is nothing left to decide. */
export function DeviceOutcomePage({ locale, outcome }: { locale: Locale; outcome: DeviceOutcome }) {
  const Icon = icons[outcome]
  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={translate(locale, titles[outcome])}
      description={translate(locale, descriptions[outcome])}
      compact
      titleIcon={<Icon className="size-6" aria-hidden="true" />}
    >
      {null}
    </AuthShell>
  )
}
