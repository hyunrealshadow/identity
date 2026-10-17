import { Button, Label, Modal, Radio, RadioGroup, useOverlayState } from '@heroui/react'
import { useEffect, useState } from 'react'

import { AccountActionForm } from './account-action-form'
import { SettingsRow } from './account-settings'
import { translate, type Locale } from '#/lib/i18n'

export function MfaPriority({ locale, preference, totpEnabled }: {
  locale: Locale
  preference: 'passkey' | 'otp'
  totpEnabled: boolean
}) {
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  const modal = useOverlayState()
  const [method, setMethod] = useState<string>(preference)
  useEffect(() => {
    if (modal.isOpen) setMethod(totpEnabled ? preference : 'passkey')
  }, [modal.isOpen, preference, totpEnabled])

  return <section aria-label={t('mfaPriority')}>
    <SettingsRow title={t('mfaPriority')} description={t('mfaPriorityDescription')}
      detail={t(preference === 'otp' && totpEnabled ? 'mfaPreferOtp' : 'mfaPreferPasskey')}
      action={<Button variant="secondary" onPress={modal.open}>{t('mfaChangePriority')}</Button>} />
    <Modal state={modal}>
      <Modal.Backdrop isDismissable={false}>
        <Modal.Container size="lg" scroll="outside">
          <Modal.Dialog>
            {({ close }) => <>
              <Modal.CloseTrigger aria-label={t('close')} />
              <Modal.Header><Modal.Heading>{t('mfaPriority')}</Modal.Heading></Modal.Header>
              <Modal.Body>
                <AccountActionForm action="update-mfa-preference" requestFailedMessage={t('accountRequestFailed')} onSuccess={close} className="grid gap-4">
                  <RadioGroup name="preferred_mfa_method" value={method} onChange={setMethod}>
                    <Label>{t('mfaPriorityDescription')}</Label>
                    <Radio value="passkey"><Radio.Content><Radio.Control><Radio.Indicator /></Radio.Control>{t('mfaPreferPasskey')}</Radio.Content></Radio>
                    <Radio value="otp" isDisabled={!totpEnabled}><Radio.Content><Radio.Control><Radio.Indicator /></Radio.Control>{t('mfaPreferOtp')}</Radio.Content></Radio>
                  </RadioGroup>
                  {!totpEnabled ? <p className="text-xs text-muted">{t('mfaPriorityRequiresOtp')}</p> : null}
                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="secondary" onPress={close}>{t('cancel')}</Button>
                    <Button type="submit">{t('mfaSavePriority')}</Button>
                  </div>
                </AccountActionForm>
              </Modal.Body>
            </>}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  </section>
}
