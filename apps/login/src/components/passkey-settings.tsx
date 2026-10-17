import { Button, Input, Label, Modal, TextField } from '@heroui/react'
import { useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef, useState, type FormEvent } from 'react'

import { SettingsRow } from './account-settings'
import { useSecurityModal } from './use-security-modal'
import { translate, type Locale } from '#/lib/i18n'
import { createPasskey, MAX_PASSKEYS_PER_ACCOUNT, passkeysSupported, type PasskeyOptions } from '#/lib/passkey'
import { passkeyAccountAction } from '#/lib/passkey-account.server'

const action = createServerFn({ method: 'POST' })
  .validator((data: Parameters<typeof passkeyAccountAction>[0]) => data)
  .handler(async ({ data }) => {
    const { options, ...result } = await passkeyAccountAction(data)
    return { ...result, optionsJson: options ? JSON.stringify(options) : undefined }
  })

export function PasskeySettings({ locale, keys, loginHint, openRequested }: {
  locale: Locale
  keys: Array<{ id: string; name: string }>
  loginHint: string
  openRequested?: boolean
}) {
  const router = useRouter()
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [supported, setSupported] = useState(false)
  const [error, setError] = useState('')
  const [registrationError, setRegistrationError] = useState('')
  const inFlight = useRef(false)
  const registration = useRef<AbortController | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const { modal, prepare, pending, error: preparationError } = useSecurityModal({
    action: 'prepare-manage-passkeys', locale, loginHint, openRequested,
  })

  useEffect(() => {
    if (!modal.isOpen) return
    setName('')
    setRegistrationError('')
    setError('')
    setDeleting(null)
  }, [modal.isOpen])
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
      if (!controller.signal.aborted) setName('')
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
    if (inFlight.current) return
    inFlight.current = true
    setBusy(true)
    setError('')
    try {
      const result = await action({ data: { action: 'delete', id } })
      if (result.redirect) { window.location.assign(result.redirect); return }
      if (result.error) { setError(result.error); return }
      if (!result.ok) throw new Error('Passkey deletion failed')
      await router.invalidate()
      setDeleting(null)
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
        action={<Button variant="secondary" onPress={() => void prepare()} isDisabled={busy || pending} isPending={pending}>{t('passkeyManage')}</Button>}
      />
      <Modal state={modal}>
        <Modal.Backdrop isDismissable={false} isKeyboardDismissDisabled={busy}>
          <Modal.Container size="lg" scroll="outside">
            <Modal.Dialog>
              {({ close }) => (
                <>
                  <Modal.CloseTrigger aria-label={t('close')} isDisabled={busy} />
                  <Modal.Header><Modal.Heading>{t('passkeyManage')}</Modal.Heading></Modal.Header>
                  <Modal.Body className="space-y-5">
                    <div className="space-y-4">
                      <p className="text-sm text-muted">{t('passkeyCount', { count: keys.length, limit: MAX_PASSKEYS_PER_ACCOUNT })}</p>
                      {keys.length ? keys.map((key) => (
                        <div key={key.id} className="space-y-3">
                          <SettingsRow title={key.name} action={
                            <Button variant="danger-soft" isDisabled={busy} aria-label={t('passkeyDelete') + ' ' + key.name} onPress={() => { setDeleting(key.id); setError('') }}>{t('passkeyDelete')}</Button>
                          } />
                          {deleting === key.id ? <div className="space-y-3 rounded-xl bg-danger/5 p-3">
                            <p className="text-sm">{t('passkeyDeleteConfirm')}</p>
                            <div className="flex justify-end gap-2">
                              <Button variant="secondary" onPress={() => setDeleting(null)} isDisabled={busy}>{t('cancel')}</Button>
                              <Button variant="danger" onPress={() => void remove(key.id)} isDisabled={busy} isPending={busy}>{t('passkeyConfirmDelete')}</Button>
                            </div>
                          </div> : null}
                        </div>
                      )) : <p className="text-sm text-muted">{t('passkeyEmpty')}</p>}
                      {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
                    </div>
                    <form className="grid gap-4 border-t border-separator pt-5" onSubmit={(event) => void register(event)} aria-busy={busy}>
                      <p className="text-sm leading-5 text-muted">{t('passkeySetupDescription')}</p>
                      <TextField name="passkey_name" value={name} onChange={setName} maxLength={100} isRequired isDisabled={!supported || busy || atLimit} fullWidth>
                        <Label>{t('passkeyName')}</Label>
                        <Input autoComplete="off" placeholder={t('passkeyNamePlaceholder')} />
                      </TextField>
                      {registrationError ? <p role="alert" className="text-sm text-danger">{registrationError}</p> : null}
                      {atLimit ? <p className="text-xs text-muted">{t('passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
                      {!supported ? <p className="text-xs text-muted">{t('passkeyUnsupported')}</p> : null}
                      <div className="flex justify-end gap-2">
                        <Button type="button" variant="secondary" onPress={close} isDisabled={busy}>{t('close')}</Button>
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
      <p className="no-js-only mt-3 text-xs text-muted">{t('passkeyRequiresJavascript')}</p>
      {preparationError ? <p role="alert" className="mt-3 text-sm text-danger">{preparationError}</p> : null}
    </section>
  )
}
