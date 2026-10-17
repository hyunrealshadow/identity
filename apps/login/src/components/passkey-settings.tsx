import { Button, Input, Label, Modal, TextField, Tooltip } from '@heroui/react'
import { useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { KeyRound, Trash2 } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'

import { SettingsRow } from './account-settings'
import { MfaRecoverySetup } from './mfa-recovery-setup'
import { MfaStepper } from './mfa-stepper'
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

export function PasskeySettings({ locale, keys, loginHint, openRequested, totpEnabled = false }: {
  locale: Locale
  keys: Array<{ id: string; name: string }>
  loginHint: string
  openRequested?: boolean
  totpEnabled?: boolean
}) {
  const router = useRouter()
  const [view, setView] = useState<'manage' | 'enroll'>('manage')
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [supported, setSupported] = useState(false)
  const [error, setError] = useState('')
  const [registrationError, setRegistrationError] = useState('')
  const [recoveryEnrollment, setRecoveryEnrollment] = useState<{ recoveryCodes: Array<string>; enrollmentToken?: string | null }>()
  const [recoveryReady, setRecoveryReady] = useState(false)
  const [recoverySaved, setRecoverySaved] = useState(false)
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
    setView(keys.length ? 'manage' : 'enroll')
  }, [modal.isOpen])
  const atLimit = keys.length >= MAX_PASSKEYS_PER_ACCOUNT
  const hasRecoveryStep = Boolean(recoveryEnrollment?.recoveryCodes.length)
  const needsRecoveryStep = hasRecoveryStep && !recoverySaved
  const t = (key: Parameters<typeof translate>[1], values?: Parameters<typeof translate>[2]) => translate(locale, key, values)

  useEffect(() => {
    setRecoveryEnrollment(undefined)
    setRecoveryReady(false)
    setRecoverySaved(false)
    setRegistrationError('')
    if (!modal.isOpen || view !== 'enroll') return
    if (atLimit) { setRecoveryReady(true); return }
    let cancelled = false
    void (async () => {
      try {
        const result = await action({ data: { action: 'prepare' } })
        if (cancelled) return
        if (result.redirect) { window.location.assign(result.redirect); return }
        if (result.error) { setRegistrationError(result.error); return }
        if (!result.recoveryEnrollment) throw new Error('Missing recovery-code enrollment')
        setRecoveryEnrollment(result.recoveryEnrollment)
        setRecoveryReady(true)
      } catch {
        if (!cancelled) setRegistrationError(translate(locale, 'accountRequestFailed'))
      }
    })()
    return () => { cancelled = true }
  }, [modal.isOpen, view, atLimit, keys.length, locale])

  useEffect(() => {
    setSupported(passkeysSupported())
    return () => registration.current?.abort()
  }, [])

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (inFlight.current || !supported || atLimit || !name.trim() || !recoveryReady || needsRecoveryStep) return
    inFlight.current = true
    const controller = new AbortController()
    registration.current = controller
    setBusy(true)
    setRegistrationError('')
    try {
      const begin = await action({ data: { action: 'begin', recoveryEnrollmentToken: recoveryEnrollment?.enrollmentToken } })
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
      if (!controller.signal.aborted) { setName(''); setView('manage') }
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
                  <Modal.Header>
                    <Modal.Heading>{t(view === 'enroll' ? 'passkeyAdd' : 'passkeyManage')}</Modal.Heading>
                    {view === 'manage' ? <p className="mt-1 text-sm text-muted">{t('passkeyCount', { count: keys.length, limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
                  </Modal.Header>
                  <Modal.Body>
                    {view === 'manage' ? <>
                      {keys.length ? <ul aria-label={t('passkeys')} className="divide-y divide-separator">
                        {keys.map((key) => <li key={key.id} className="py-2 first:pt-0 last:pb-0">
                          <div className="flex min-w-0 items-start gap-3">
                            <KeyRound className="mt-1.5 size-5 shrink-0 text-muted" aria-hidden="true" />
                            <p className="min-w-0 flex-1 py-1.5 text-sm font-medium leading-5 text-foreground [overflow-wrap:anywhere]">{key.name}</p>
                            <Tooltip>
                              <Button size="sm" variant="ghost" isIconOnly className="shrink-0 text-danger" isDisabled={busy} aria-label={t('passkeyDelete') + ' ' + key.name} onPress={() => { setDeleting(key.id); setError('') }}>
                                <Trash2 className="size-4" aria-hidden="true" />
                              </Button>
                              <Tooltip.Content>{t('passkeyDelete')}</Tooltip.Content>
                            </Tooltip>
                          </div>
                          {deleting === key.id ? <div className="mt-3 space-y-3 border-t border-separator pt-3">
                            <p className="text-sm">{t('passkeyDeleteConfirm')}</p>
                            {keys.length === 1 && !totpEnabled ? <p className="text-sm text-danger">{t('mfaLastMethodRecoveryWarning')}</p> : null}
                            <div className="flex justify-end gap-2">
                              <Button variant="secondary" onPress={() => setDeleting(null)} isDisabled={busy}>{t('cancel')}</Button>
                              <Button variant="danger" onPress={() => void remove(key.id)} isDisabled={busy} isPending={busy}>{t('passkeyConfirmDelete')}</Button>
                            </div>
                          </div> : null}
                        </li>)}
                      </ul> : <p className="text-sm text-muted">{t('passkeyEmpty')}</p>}
                      {error ? <p role="alert" className="mt-3 text-sm text-danger">{error}</p> : null}
                      {atLimit ? <p className="mt-4 text-xs text-muted">{t('passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
                      <div className="mt-5 flex justify-end gap-2">
                        <Button type="button" variant="secondary" onPress={close} isDisabled={busy}>{t('close')}</Button>
                        <Button onPress={() => { setName(''); setView('enroll') }} isDisabled={busy || atLimit}>{t('passkeyAdd')}</Button>
                      </div>
                    </> : <div className="text-foreground">
                      {hasRecoveryStep ? <MfaStepper currentStep={needsRecoveryStep ? 1 : 2} label={t('passkeyAdd')} steps={[t('accountRecoveryCodesTitle'), t('passkeyAdd')]} /> : null}
                      {needsRecoveryStep ? <MfaRecoverySetup codes={recoveryEnrollment!.recoveryCodes} t={t} onContinue={() => setRecoverySaved(true)} /> : <form className="grid gap-4" onSubmit={(event) => void register(event)} aria-busy={busy}>
                        <div>
                          {hasRecoveryStep ? <h2 className="text-sm font-semibold">{t('passkeyAdd')}</h2> : null}
                          <p className={`${hasRecoveryStep ? 'mt-1 ' : ''}text-sm leading-5`}>{t('passkeySetupDescription')}</p>
                        </div>
                        <TextField name="passkey_name" value={name} onChange={setName} maxLength={100} isRequired isDisabled={!supported || busy || atLimit || !recoveryReady} fullWidth>
                          <Label>{t('passkeyName')}</Label>
                          <Input autoComplete="off" placeholder={t('passkeyNamePlaceholder')} />
                        </TextField>
                        {atLimit ? <p className="text-xs text-muted">{t('passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
                        {!supported ? <p className="text-xs text-muted">{t('passkeyUnsupported')}</p> : null}
                        <div className="flex items-center justify-between gap-2">
                          {hasRecoveryStep || keys.length ? <Button type="button" variant="ghost" onPress={() => hasRecoveryStep ? setRecoverySaved(false) : setView('manage')} isDisabled={busy}>{t('accountMfaBack')}</Button> : <span />}
                          <Button type="submit" isDisabled={!supported || busy || atLimit || !name.trim() || !recoveryReady} isPending={busy}>{t('passkeyAdd')}</Button>
                        </div>
                      </form>}
                    </div>}
                    {registrationError ? <p role="alert" className="text-sm text-danger">{registrationError}</p> : null}
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
