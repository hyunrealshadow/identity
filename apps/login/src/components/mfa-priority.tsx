import { Button } from '@identity/ui/components/button'
import { Field, FieldLabel, FieldLegend, FieldSet } from '@identity/ui/components/field'
import { RadioGroup, RadioGroupItem } from '@identity/ui/components/radio-group'
import { useEffect, useState } from 'react'

import { AccountActionForm } from './account-action-form'
import { AccountDialog } from './account-dialog'
import { SettingsRow } from './account-settings'
import { useDialogState } from './use-dialog-state'
import { translate, type Locale } from '#/lib/i18n'

export function MfaPriority({ locale, preference, totpEnabled }: {
  locale: Locale
  preference: 'passkey' | 'otp'
  totpEnabled: boolean
}) {
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  const modal = useDialogState()
  const [method, setMethod] = useState<string>(preference)
  useEffect(() => {
    if (modal.isOpen) setMethod(totpEnabled ? preference : 'passkey')
  }, [modal.isOpen, preference, totpEnabled])

  return <section aria-label={t('mfaPriority')}>
    <SettingsRow title={t('mfaPriority')} description={t('mfaPriorityDescription')}
      detail={t(preference === 'otp' && totpEnabled ? 'mfaPreferOtp' : 'mfaPreferPasskey')}
      action={<Button variant="outline" onClick={modal.open}>{t('mfaChangePriority')}</Button>} />
    <AccountDialog state={modal} title={t('mfaPriority')} closeLabel={t('close')}>
      <AccountActionForm action="update-mfa-preference" requestFailedMessage={t('accountRequestFailed')} onSuccess={modal.close} className="grid gap-4">
        <FieldSet>
          <FieldLegend variant="label">{t('mfaPriorityDescription')}</FieldLegend>
          <RadioGroup name="preferred_mfa_method" value={method} onValueChange={(value) => setMethod(String(value))}>
            <Field orientation="horizontal">
              <RadioGroupItem value="passkey" id="mfa-prefer-passkey" />
              <FieldLabel htmlFor="mfa-prefer-passkey" className="font-normal">{t('mfaPreferPasskey')}</FieldLabel>
            </Field>
            <Field orientation="horizontal" data-disabled={!totpEnabled ? true : undefined}>
              <RadioGroupItem value="otp" id="mfa-prefer-otp" disabled={!totpEnabled} />
              <FieldLabel htmlFor="mfa-prefer-otp" className="font-normal">{t('mfaPreferOtp')}</FieldLabel>
            </Field>
          </RadioGroup>
        </FieldSet>
        {!totpEnabled ? <p className="text-xs text-muted-foreground">{t('mfaPriorityRequiresOtp')}</p> : null}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={modal.close}>{t('cancel')}</Button>
          <Button type="submit">{t('mfaSavePriority')}</Button>
        </div>
      </AccountActionForm>
    </AccountDialog>
  </section>
}
