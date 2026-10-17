import { Button, Input, Label, Modal, TextField, useOverlayState } from '@heroui/react'
import { useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef, useState, type FormEvent } from 'react'

import { SettingsRow } from './account-settings'
import { translate, type Locale } from '#/lib/i18n'
import { createPasskey, MAX_PASSKEYS_PER_ACCOUNT, passkeysSupported, type PasskeyOptions } from '#/lib/passkey'
import { passkeyAccountAction } from '#/lib/passkey-account.server'

const action = createServerFn({ method: 'POST' })
  .validator((data: Parameters<typeof passkeyAccountAction>[0]) => data)
  .handler(async ({ data }) => {
    const { options, ...result } = await passkeyAccountAction(data)
    return { ...result, optionsJson: options ? JSON.stringify(options) : undefined }
  })

export function PasskeySettings({ locale, keys }: { locale: Locale; keys: Array<{ id: string; name: string }> }) {
  const router = useRouter()
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [supported, setSupported] = useState(false)
  const [error, setError] = useState('')
  const [registrationError, setRegistrationError] = useState('')
  const inFlight = useRef(false)
  const registration = useRef<AbortController | null>(null)
  const modal = useOverlayState({
    onOpenChange: (isOpen) => {
      if (isOpen) {
        setName('')
        setRegistrationError('')
      }
    },
  })
  const atLimit = keys.length >= MAX_PASSKEYS_PER_ACCOUNT
  const t = (key: Parameters<typeof translate>[1], values?: Parameters<typeof translate>[2]) => translate(locale, key, values)

  useEffect(() => {
    setSupported(passkeysSupported())
    return () => registration.current?.abort()
  }, [])

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (inFlight.current || !supported || atLimit || !name.trim()) return
    inFlight.current = true
    const controller = new AbortController()
    registration.current = controller
    setBusy(true)
    setRegistrationError('')
    try {
      const begin = await action({ data: { action: 'begin' } })
      if (controller.signal.aborted) return
      if (begin.redirect) { window.location.assign(begin.redirect); return }
      if (begin.error) { setRegistrationError(begin.error); return }
      if (!begin.optionsJson) throw new Error('Missing passkey registration options')
      const options = JSON.parse(begin.optionsJson) as PasskeyOptions
      const credential = await createPasskey(options, controller.signal)
      if (controller.signal.aborted) return
      const result = await action({ data: {
        action: 'finish', id: options.challenge_id, name: name.trim(), credential: JSON.stringify(credential),
      } })
      if (controller.signal.aborted) return
      if (result.redirect) { window.location.assign(result.redirect); return }
      if (result.error) { setRegistrationError(result.error); return }
      if (!result.ok) throw new Error('Passkey registration failed')
      await router.invalidate()
      if (!controller.signal.aborted) modal.close()
    } catch (error) {
      if (!controller.signal.aborted) {
        const cancelled = (error instanceof Error || error instanceof DOMException) && error.name === 'NotAllowedError'
        setRegistrationError(t(cancelled ? 'passkeyCancelled' : 'passkeyFailed'))
      }
    } finally {
      if (!controller.signal.aborted) {
        registration.current = null
        inFlight.current = false
        setBusy(false)
      }
    }
  }

  async function remove(id: string) {
    if (inFlight.current || !window.confirm(t('passkeyDeleteConfirm'))) return
    inFlight.current = true
    setBusy(true)
    setError('')
    try {
      const result = await action({ data: { action: 'delete', id } })
      if (result.redirect) { window.location.assign(result.redirect); return }
      if (result.error) { setError(result.error); return }
      if (!result.ok) throw new Error('Passkey deletion failed')
      await router.invalidate()
    } catch {
      setError(t('passkeyFailed'))
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  return (
    <section aria-label={t('passkeys')}>
      <SettingsRow
        title={t('passkeys')}
        description={t('passkeysDescription')}
        detail={t('passkeyCount', { count: keys.length, limit: MAX_PASSKEYS_PER_ACCOUNT })}
        action={
          <Modal state={modal}>
            <Button variant="secondary" onPress={modal.open} isDisabled={!supported || busy || atLimit}>{t('passkeyAdd')}</Button>
            <Modal.Backdrop isDismissable={false} isKeyboardDismissDisabled={busy}>
              <Modal.Container size="lg" scroll="outside">
                <Modal.Dialog>
                  {({ close }) => (
                    <>
                      <Modal.CloseTrigger aria-label={t('close')} isDisabled={busy} />
                      <Modal.Header><Modal.Heading>{t('passkeyAdd')}</Modal.Heading></Modal.Header>
                      <Modal.Body>
                        <form className="grid gap-4" onSubmit={(event) => void register(event)} aria-busy={busy}>
                          <p className="text-sm leading-5 text-muted">{t('passkeySetupDescription', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p>
                          <TextField name="passkey_name" value={name} onChange={setName} maxLength={100} isRequired isDisabled={busy} fullWidth>
                            <Label>{t('passkeyName')}</Label>
                            <Input autoFocus autoComplete="off" placeholder={t('passkeyNamePlaceholder')} />
                          </TextField>
                          {registrationError ? <p role="alert" className="text-sm text-danger">{registrationError}</p> : null}
                          {atLimit ? <p role="alert" className="text-sm text-danger">{t('passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
                          <div className="flex justify-end gap-2">
                            <Button type="button" variant="secondary" onPress={close} isDisabled={busy}>{t('cancel')}</Button>
                            <Button type="submit" isDisabled={!supported || busy || atLimit || !name.trim()} isPending={busy}>{t('passkeyAdd')}</Button>
                          </div>
                        </form>
                      </Modal.Body>
                    </>
                  )}
                </Modal.Dialog>
              </Modal.Container>
            </Modal.Backdrop>
          </Modal>
        }
      />
      {keys.length ? <div className="mt-4 space-y-4">
        {keys.map((key) => <SettingsRow key={key.id} title={key.name} action={
          <Button variant="danger-soft" isDisabled={busy} aria-label={t('passkeyDelete') + ' ' + key.name} onPress={() => void remove(key.id)}>{t('passkeyDelete')}</Button>
        } />)}
      </div> : <p className="mt-4 text-sm text-muted">{t('passkeyEmpty')}</p>}
      {atLimit ? <p className="mt-3 text-xs text-muted">{t('passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
      <p className="no-js-only mt-3 text-xs text-muted">{t('passkeyRequiresJavascript')}</p>
      {!supported ? <p className="js-only mt-3 text-xs text-muted">{t('passkeyUnsupported')}</p> : null}
      {error ? <p role="alert" className="mt-3 text-sm text-danger">{error}</p> : null}
    </section>
  )
}
