import { Button } from '@identity/ui/components/button'
import { Field, FieldLabel } from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import { Spinner } from '@identity/ui/components/spinner'
import { Tooltip, TooltipContent, TooltipTrigger } from '@identity/ui/components/tooltip'
import { useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { KeyRound, Trash2 } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'

import { AccountDialog } from './account-dialog'
import { SettingsRow } from './account-settings'
import { MfaRecoverySetup } from './mfa-recovery-setup'
import { MfaStepper } from './mfa-stepper'
import { useAccountReauth } from './reauthentication-popup'
import { useSecurityModal } from './use-security-modal'
import { translate, type Locale } from '#/lib/i18n'
import { startPopupPasskeyReauthFromRedirect } from '#/lib/popup-reauth.server'
import { createPasskey, MAX_PASSKEYS_PER_ACCOUNT, passkeysSupported, type PasskeyOptions } from '#/lib/passkey'
import { passkeyAccountAction } from '#/lib/passkey-account.server'

const action = createServerFn({ method: 'POST' })
  .validator((data: Parameters<typeof passkeyAccountAction>[0]) => data)
  .handler(async ({ data }) => {
    const { options, redirect, ...result } = await passkeyAccountAction(data)
    // Inside the account center the standard passkey reauthorization redirect
    // becomes a dialog request that resumes the passkey continuation.
    const reauth = await startPopupPasskeyReauthFromRedirect(redirect)
    return {
      ...result,
      redirect: reauth ? undefined : redirect,
      reauth,
      optionsJson: options ? JSON.stringify(options) : undefined,
    }
  })

export function PasskeySettings({ locale, keys, loginHint, openRequested, totpEnabled = false }: {
  locale: Locale
  keys: Array<{ id: string; name: string }>
  loginHint: string
  openRequested?: boolean
  totpEnabled?: boolean
}) {
  const router = useRouter()
  const { requestReauth, prepareAction } = useAccountReauth()
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

  async function executePasskey(data: Parameters<typeof passkeyAccountAction>[0]): ReturnType<typeof action> {
    const prepared = await prepareAction(`passkey-${data.action}`)
    if (prepared.redirect) return { redirect: prepared.redirect, reauth: undefined, optionsJson: undefined }
    if (prepared.reauth) return { reauth: prepared.reauth, redirect: undefined, optionsJson: undefined }
    if (prepared.localError || !prepared.ok) return { error: prepared.localError ?? translate(locale, 'accountRequestFailed'), reauth: undefined, redirect: undefined, optionsJson: undefined }
    return action({ data })
  }

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
        const result = await executePasskey({ action: 'prepare' })
        if (cancelled) return
        if (result.reauth) { requestReauth(result.reauth); return }
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
  }, [modal.isOpen, view, atLimit, keys.length, locale, requestReauth, prepareAction])

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
      const begin = await executePasskey({ action: 'begin', recoveryEnrollmentToken: recoveryEnrollment?.enrollmentToken })
      if (controller.signal.aborted) return
      if (begin.reauth) { requestReauth(begin.reauth); return }
      if (begin.redirect) { window.location.assign(begin.redirect); return }
      if (begin.error) { setRegistrationError(begin.error); return }
      if (!begin.optionsJson) throw new Error('Missing passkey registration options')
      const options = JSON.parse(begin.optionsJson) as PasskeyOptions
      const credential = await createPasskey(options, controller.signal)
      if (controller.signal.aborted) return
      const result = await executePasskey({
        action: 'finish', id: options.challenge_id, name: name.trim(), credential: JSON.stringify(credential),
      })
      if (controller.signal.aborted) return
      if (result.reauth) { requestReauth(result.reauth); return }
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
      const result = await executePasskey({ action: 'delete', id })
      if (result.reauth) { requestReauth(result.reauth); return }
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
        action={<Button variant="outline" onClick={() => void prepare()} disabled={busy || pending}>{pending ? <Spinner aria-hidden="true" role="presentation" /> : null}{t('passkeyManage')}</Button>}
      />
      <AccountDialog
        state={modal}
        busy={busy}
        closeLabel={t('close')}
        title={t(view === 'enroll' ? 'passkeyAdd' : 'passkeyManage')}
        description={view === 'manage' ? t('passkeyCount', { count: keys.length, limit: MAX_PASSKEYS_PER_ACCOUNT }) : undefined}
      >
        <div>
                    {view === 'manage' ? <>
                      {keys.length ? <ul aria-label={t('passkeys')} className="divide-y divide-border">
                        {keys.map((key) => <li key={key.id} className="py-2 first:pt-0 last:pb-0">
                          <div className="flex min-w-0 items-start gap-3">
                            <KeyRound className="mt-1.5 size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
                            <p className="min-w-0 flex-1 py-1.5 text-sm font-medium leading-5 text-foreground [overflow-wrap:anywhere]">{key.name}</p>
                            <Tooltip>
                              <TooltipTrigger
                                render={<Button size="icon-sm" variant="ghost" className="shrink-0 text-destructive hover:text-destructive" disabled={busy} aria-label={t('passkeyDelete') + ' ' + key.name} onClick={() => { setDeleting(key.id); setError('') }} />}
                              >
                                <Trash2 aria-hidden="true" />
                              </TooltipTrigger>
                              <TooltipContent>{t('passkeyDelete')}</TooltipContent>
                            </Tooltip>
                          </div>
                          {deleting === key.id ? <div className="mt-3 space-y-3 border-t border-border pt-3">
                            <p className="text-sm">{t('passkeyDeleteConfirm')}</p>
                            {keys.length === 1 && !totpEnabled ? <p className="text-sm text-destructive">{t('mfaLastMethodRecoveryWarning')}</p> : null}
                            <div className="flex justify-end gap-2">
                              <Button variant="outline" onClick={() => setDeleting(null)} disabled={busy}>{t('cancel')}</Button>
                              <Button variant="destructive" onClick={() => void remove(key.id)} disabled={busy}>{busy ? <Spinner aria-hidden="true" role="presentation" /> : null}{t('passkeyConfirmDelete')}</Button>
                            </div>
                          </div> : null}
                        </li>)}
                      </ul> : <p className="text-sm text-muted-foreground">{t('passkeyEmpty')}</p>}
                      {error ? <p role="alert" className="mt-3 text-sm text-destructive">{error}</p> : null}
                      {atLimit ? <p className="mt-4 text-xs text-muted-foreground">{t('passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
                      <div className="mt-5 flex justify-end gap-2">
                        <Button type="button" variant="outline" onClick={modal.close} disabled={busy}>{t('close')}</Button>
                        <Button onClick={() => { setName(''); setView('enroll') }} disabled={busy || atLimit}>{t('passkeyAdd')}</Button>
                      </div>
                    </> : <div className="text-foreground">
                      {hasRecoveryStep ? <MfaStepper currentStep={needsRecoveryStep ? 1 : 2} label={t('passkeyAdd')} steps={[t('accountRecoveryCodesTitle'), t('passkeyAdd')]} /> : null}
                      {needsRecoveryStep ? <MfaRecoverySetup codes={recoveryEnrollment!.recoveryCodes} t={t} onContinue={() => setRecoverySaved(true)} /> : <form className="grid gap-4" onSubmit={(event) => void register(event)} aria-busy={busy}>
                        <div>
                          {hasRecoveryStep ? <h2 className="text-sm font-semibold">{t('passkeyAdd')}</h2> : null}
                          <p className={`${hasRecoveryStep ? 'mt-1 ' : ''}text-sm leading-5`}>{t('passkeySetupDescription')}</p>
                        </div>
                        <Field data-disabled={!supported || busy || atLimit || !recoveryReady ? true : undefined}>
                          <FieldLabel htmlFor="passkey-name">{t('passkeyName')}</FieldLabel>
                          <Input id="passkey-name" name="passkey_name" value={name} onChange={(event) => setName(event.target.value)} maxLength={100} required disabled={!supported || busy || atLimit || !recoveryReady} autoComplete="off" placeholder={t('passkeyNamePlaceholder')} />
                        </Field>
                        {atLimit ? <p className="text-xs text-muted-foreground">{t('passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT })}</p> : null}
                        {!supported ? <p className="text-xs text-muted-foreground">{t('passkeyUnsupported')}</p> : null}
                        <div className="flex items-center justify-between gap-2">
                          {hasRecoveryStep || keys.length ? <Button type="button" variant="ghost" onClick={() => hasRecoveryStep ? setRecoverySaved(false) : setView('manage')} disabled={busy}>{t('accountMfaBack')}</Button> : <span />}
                          <Button type="submit" disabled={!supported || busy || atLimit || !name.trim() || !recoveryReady}>{busy ? <Spinner aria-hidden="true" role="presentation" /> : null}{t('passkeyAdd')}</Button>
                        </div>
                      </form>}
                    </div>}
                    {registrationError ? <p role="alert" className="text-sm text-destructive">{registrationError}</p> : null}
        </div>
      </AccountDialog>
      <p className="no-js-only mt-3 text-xs text-muted-foreground">{t('passkeyRequiresJavascript')}</p>
      {preparationError ? <p role="alert" className="mt-3 text-sm text-destructive">{preparationError}</p> : null}
    </section>
  )
}
