import { Info } from 'lucide-react'

import { translate, type Locale } from '#/lib/i18n'

export function ConsentRevokeNotice({ locale }: { locale: Locale }) {
  return (
    <div className="mt-5 flex items-start gap-2 border-t border-border pt-4 text-xs leading-5 text-muted">
      <Info className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <p>{translate(locale, 'revoke')}</p>
    </div>
  )
}
