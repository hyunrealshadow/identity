import { AccountAvatar } from '#/components/account-avatar'
import { translate, type Locale } from '#/lib/i18n'
import type { ConsentAccount as ConsentAccountData } from '#/lib/identity-types'

export function ConsentAccount({ account, locale }: { account: ConsentAccountData; locale: Locale }) {
  return (
    <div className="mb-6 flex items-center gap-3 rounded-xl border border-border bg-surface-secondary p-3" aria-label={translate(locale, 'consentAccount')}>
      <AccountAvatar name={account.name} picture={account.picture} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-semibold" title={account.name}>{account.name}</p>
        <p className="truncate text-xs text-muted" title={account.email}>{account.email}</p>
      </div>
    </div>
  )
}
