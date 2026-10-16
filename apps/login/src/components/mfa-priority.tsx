import { Button } from '@heroui/react'

import { AccountActionForm } from './account-action-form'
import { translate, type Locale } from '#/lib/i18n'

export function MfaPriority({ locale, preference, totpEnabled, loginHint }: {
  locale: Locale
  preference: 'passkey' | 'otp'
  totpEnabled: boolean
  loginHint: string
}) {
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  return <AccountActionForm action="update-mfa-preference" requestFailedMessage={t('accountRequestFailed')} className="space-y-3">
    <input type="hidden" name="login_hint" value={loginHint} />
    <label className="block text-sm font-medium" htmlFor="preferred-mfa-method">{t('mfaPriority')}</label>
    <p className="text-sm leading-5 text-muted">{t('mfaPriorityDescription')}</p>
    <select id="preferred-mfa-method" name="preferred_mfa_method" defaultValue={totpEnabled ? preference : 'passkey'} className="h-10 w-full rounded-field border border-border bg-field px-3 text-sm">
      <option value="passkey">{t('mfaPreferPasskey')}</option>
      <option value="otp" disabled={!totpEnabled}>{t('mfaPreferOtp')}</option>
    </select>
    {!totpEnabled ? <p className="text-xs text-muted">{t('mfaPriorityRequiresOtp')}</p> : null}
    <Button type="submit" variant="secondary">{t('mfaSavePriority')}</Button>
  </AccountActionForm>
}
