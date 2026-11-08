import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { Button, buttonVariants } from '@identity/ui/components/button'
import { Field, FieldLabel } from '@identity/ui/components/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from '@identity/ui/components/input-group'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { Check, Copy, ExternalLink, TriangleAlert } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AccountActionForm } from '#/components/account-action-form'
import { AccountDialog } from '#/components/account-dialog'
import { useDialogState } from '#/components/use-dialog-state'
import { PageHeading, PasswordField, SettingsCard, SettingsRow } from '#/components/account-settings'
import { RecoveryCodeList, RecoveryCodeTools } from '#/components/recovery-code-tools'
import { TotpQrCode } from '#/components/totp-qr-code'
import { TotpInput } from '#/components/totp-input'
import { translate } from '#/lib/i18n'
import { useAccount } from './route'
import { PasskeySettings } from '#/components/passkey-settings'
import { MfaPriority } from '#/components/mfa-priority'
import { MfaStepper, stepTitle } from '#/components/mfa-stepper'
import { MfaRecoverySetup } from '#/components/mfa-recovery-setup'

interface SecuritySearch {
  setup?: 'mfa'
  step?: 'verify'
  confirm?: 'disable-mfa' | 'change-password' | 'recovery-codes' | 'passkeys'
}

export const Route = createFileRoute('/account/security')({
  validateSearch: (search): SecuritySearch => ({
    setup: search.setup === 'mfa' ? 'mfa' : undefined,
    step: search.step === 'verify' ? 'verify' : undefined,
    confirm:
      search.confirm === 'disable-mfa' || search.confirm === 'change-password' || search.confirm === 'recovery-codes' || search.confirm === 'passkeys'
        ? search.confirm
        : undefined,
  }),
  component: SecurityPage,
})

function SecurityPage() {
  const { locale, data, flash, mfa } = useAccount()
  const search = Route.useSearch()
  const security = data.security
  const loginHint = data.account.username
  const t = (key: Parameters<typeof translate>[1], values?: Parameters<typeof translate>[2]) => translate(locale, key, values)

  return (
    <>
      <PageHeading title={t('accountSecurity')} description={t('accountSecurityDescription')} />
      <div className="space-y-4">
        <SettingsCard title={t('accountPassword')} description={t('accountPasswordDescription')}>
          <SettingsRow title="••••••••" action={<PasswordModal flash={flash} loginHint={loginHint} openForm={search.confirm === 'change-password'} t={t} />} />
        </SettingsCard>
        <SettingsCard title={t('accountMfaRowTitle')} description={t('accountMfaDescription')}>
          <div className="divide-y divide-border">
            {(data.passkeys?.length ?? 0) > 0 ? <div className="pb-5"><MfaPriority locale={locale} preference={security.preferredMfaMethod} totpEnabled={security.totpEnabled} /></div> : null}
            <div className={(data.passkeys?.length ?? 0) > 0 ? 'py-5' : 'pb-5'}><PasskeySettings totpEnabled={security.totpEnabled} loginHint={loginHint} openRequested={search.confirm === 'passkeys'} locale={locale} keys={data.passkeys ?? []} /></div>
            <div className={security.totpEnabled ? 'py-5' : 'pt-5'}>
              <SettingsRow
                title={t('accountMfa')}
                description={security.totpEnabled ? t('accountMfaEnabled') : t('accountMfaNotEnabled')}
                action={security.totpEnabled
                  ? <DeleteMfaModal lastMethod={(data.passkeys?.length ?? 0) === 0} loginHint={loginHint} openConfirm={search.confirm === 'disable-mfa'} t={t} />
                  : <MfaSetupAction flash={flash} mfa={mfa} loginHint={loginHint} openSetup={search.setup === 'mfa'} initialStep={search.step === 'verify' ? 3 : undefined} t={t} />}
              />
            </div>
            {security.totpEnabled || (data.passkeys?.length ?? 0) > 0 ? (
              <div className="pt-5">
                <SettingsRow
                  title={t('accountRecoveryCodes')}
                  description={t('accountRecoveryCodesManageDescription')}
                  detail={t('accountRecoveryCodesRemaining', { count: security.recoveryCodesRemaining })}
                  action={<RecoveryCodesModal mfa={mfa} remaining={security.recoveryCodesRemaining} loginHint={loginHint} openManage={search.confirm === 'recovery-codes'} t={t} />}
                />
              </div>
            ) : null}
          </div>
        </SettingsCard>
      </div>
    </>
  )
}

type Flash = ReturnType<typeof useAccount>['flash']
type Mfa = ReturnType<typeof useAccount>['mfa']
type Translator = (key: Parameters<typeof translate>[1], values?: Parameters<typeof translate>[2]) => string

function PasswordModal({ flash, loginHint, openForm, t }: { flash: Flash; loginHint: string; openForm: boolean; t: Translator }) {
  const modal = useDialogState()
  const navigate = useNavigate()

  useEffect(() => {
    if (!openForm) return
    modal.open()
    void navigate({ to: '/account/security', replace: true })
  }, [openForm])

  return <>
    <AccountActionForm action="prepare-change-password" requestFailedMessage={t('accountRequestFailed')} onSuccess={() => modal.open()}>
      <input type="hidden" name="login_hint" value={loginHint} />
      <Button type="submit" variant="outline">{t('accountChangePassword')}</Button>
    </AccountActionForm>
    <AccountDialog state={modal} title={t('accountChangePassword')} closeLabel={t('close')}>
      <AccountActionForm action="change-password" requestFailedMessage={t('accountRequestFailed')} onSuccess={modal.close} className="grid gap-4">
        <input type="hidden" name="login_hint" value={loginHint} />
        <PasswordField name="new_password" label={t('accountNewPassword')} error={flash.fields?.new_password} />
        <PasswordField name="confirm_password" label={t('accountConfirmPassword')} error={flash.fields?.confirm_password} />
        <div className="flex justify-end"><Button type="submit">{t('accountChangePassword')}</Button></div>
      </AccountActionForm>
    </AccountDialog>
  </>
}

function MfaSetupAction({ flash, mfa, loginHint, openSetup, initialStep, t }: { flash: Flash; mfa: Mfa; loginHint: string; openSetup: boolean; initialStep?: 3; t: Translator }) {
  const hasModalContent = Boolean(mfa.enrollment)
  const modal = useDialogState()
  const navigate = useNavigate()

  useEffect(() => {
    if (!openSetup) return
    if (hasModalContent) modal.open()
    void navigate({ to: '/account/security', replace: true })
  }, [hasModalContent, openSetup])

  return (
    <>
      {!hasModalContent ? (
        <AccountActionForm action="begin-totp" requestFailedMessage={t('accountRequestFailed')} onSuccess={() => modal.open()}>
          <Button type="submit" variant="outline">{t('accountMfaEnable')}</Button>
        </AccountActionForm>
      ) : (
        <Button variant="outline" onClick={modal.open}>{t('accountMfaEnable')}</Button>
      )}
      {hasModalContent ? (
        <AccountDialog state={modal} title={t('accountMfa')} closeLabel={t('close')}>
          {mfa.enrollment ? (
            <MfaEnrollmentWizard enrollment={mfa.enrollment} loginHint={loginHint} initialStep={initialStep} codeError={flash.fields?.code} validationRevision={flash.fields} close={modal.close} t={t} />
          ) : (
            <p className="text-sm text-muted-foreground">{t('accountMfaRecommendation')}</p>
          )}
        </AccountDialog>
      ) : null}
    </>
  )
}

function DeleteMfaModal({ loginHint, openConfirm, t, lastMethod }: { lastMethod: boolean; loginHint: string; openConfirm: boolean; t: Translator }) {
  const modal = useDialogState()
  const navigate = useNavigate()

  useEffect(() => {
    if (!openConfirm) return
    modal.open()
    void navigate({ to: '/account/security', replace: true })
  }, [openConfirm])

  return (
    <>
      <AccountActionForm
        action="prepare-disable-totp"
        requestFailedMessage={t('accountRequestFailed')}
        onSuccess={() => modal.open()}
      >
        <input type="hidden" name="login_hint" value={loginHint} />
        <Button type="submit" variant="destructive">{t('accountMfaDelete')}</Button>
      </AccountActionForm>
      <AccountDialog state={modal} title={t('accountMfaDeleteTitle')} description={t('accountMfaDeleteDescription')} closeLabel={t('close')} className="sm:max-w-md">
        {lastMethod ? <p className="text-sm text-destructive">{t('mfaLastMethodRecoveryWarning')}</p> : null}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={modal.close}>{t('cancel')}</Button>
          <AccountActionForm action="disable-totp" requestFailedMessage={t('accountRequestFailed')} onSuccess={modal.close}>
            <input type="hidden" name="login_hint" value={loginHint} />
            <Button type="submit" variant="destructive">{t('accountMfaDelete')}</Button>
          </AccountActionForm>
        </div>
      </AccountDialog>
    </>
  )
}

function RecoveryCodesModal({ mfa, remaining, loginHint, openManage, t }: { mfa: Mfa; remaining: number; loginHint: string; openManage: boolean; t: Translator }) {
  const modal = useDialogState()
  const navigate = useNavigate()
  const codes = mfa.recoveryCodes

  useEffect(() => {
    if (!openManage) return
    modal.open()
    void navigate({ to: '/account/security', replace: true })
  }, [openManage])

  return (
    <>
      <Button variant="outline" onClick={modal.open}>{t('accountRecoveryCodesManage')}</Button>
      <AccountDialog state={modal} title={codes ? t('accountRecoveryCodesNewTitle') : t('accountRecoveryCodes')} closeLabel={t('close')}>
        {codes ? (
          <div>
            <p className="text-sm leading-5 text-muted-foreground">{t('accountRecoveryCodesRegeneratedDescription')}</p>
            <div className="mt-4">
              <RecoveryCodeList codes={codes} copyLabel={t('accountRecoveryCodeCopy')} copiedLabel={t('accountRecoveryCodeCopied')} />
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <RecoveryCodeTools codes={codes} copyLabel={t('accountRecoveryCodesCopy')} copiedLabel={t('accountRecoveryCodesCopied')} printLabel={t('accountRecoveryCodesPrint')} downloadLabel={t('accountRecoveryCodesDownload')} />
              <Button type="button" className="ms-auto" onClick={modal.close}>{t('done')}</Button>
            </div>
          </div>
        ) : (
          <div>
            <p className="text-sm leading-5 text-muted-foreground">{t('accountRecoveryCodesManageSummary', { count: remaining })}</p>
            <p className="mt-3 text-sm leading-5 text-destructive">{t('accountRecoveryCodesRegenerateWarning')}</p>
            <div className="mt-5 flex justify-end">
              <AccountActionForm action="regenerate-recovery-codes" requestFailedMessage={t('accountRequestFailed')} onSuccess={() => modal.open()}>
                <input type="hidden" name="login_hint" value={loginHint} />
                <Button type="submit" variant="destructive">{t('accountRecoveryCodesRegenerate')}</Button>
              </AccountActionForm>
            </div>
          </div>
        )}
      </AccountDialog>
    </>
  )
}
function MfaEnrollmentWizard({ enrollment, loginHint, initialStep, codeError, validationRevision, close, t }: { enrollment: NonNullable<Mfa['enrollment']>; loginHint: string; initialStep?: 3; codeError?: string; validationRevision?: Flash['fields']; close: () => void; t: Translator }) {
  const hasRecoveryStep = enrollment.recovery_codes.length > 0
  const [step, setStep] = useState<1 | 2 | 3>(initialStep ?? (codeError ? 3 : hasRecoveryStep ? 1 : 2))
  const [method, setMethod] = useState<'qr' | 'manual'>('qr')
  const [code, setCode] = useState('')
  const [showCodeError, setShowCodeError] = useState(Boolean(codeError))
  const [secretCopied, setSecretCopied] = useState(false)
  const [otpAuthCopied, setOtpAuthCopied] = useState(false)
  const visibleCodeError = showCodeError ? codeError : undefined

  useEffect(() => {
    setCode('')
    setShowCodeError(Boolean(codeError))
  }, [codeError, validationRevision])

  function retryVerification(value: string) {
    setCode(value)
    if (showCodeError) setShowCodeError(false)
  }

  function returnToConfiguration() {
    setCode('')
    setShowCodeError(false)
    setStep(2)
  }

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(enrollment.secret)
      setSecretCopied(true)
      window.setTimeout(() => setSecretCopied(false), 2000)
    } catch {
      // The setup key remains selectable when clipboard access is unavailable.
    }
  }

  async function copyOtpAuthUri() {
    try {
      await navigator.clipboard.writeText(enrollment.otp_auth_uri)
      setOtpAuthCopied(true)
      window.setTimeout(() => setOtpAuthCopied(false), 2000)
    } catch {
      // The URI remains available through the authenticator link.
    }
  }

  return (
    <div className="text-foreground">
      <MfaStepper
        currentStep={hasRecoveryStep ? step : step === 2 ? 1 : 2}
        label={t('accountMfa')}
        steps={hasRecoveryStep ? [t('accountMfaRecoveryStep'), t('accountMfaStepScan'), t('accountMfaStepVerify')] : [t('accountMfaStepScan'), t('accountMfaStepVerify')]}
      />

      {step === 1 ? (
        <MfaRecoverySetup codes={enrollment.recovery_codes} t={t} onContinue={() => setStep(2)} />
      ) : null}

      {step === 2 ? (
        <div>
          <h2 className="text-sm font-semibold">{stepTitle(t('accountMfaStepScan'))}</h2>
          <p className="mt-1 text-sm leading-5 text-muted-foreground">{t('accountMfaStepScanDescription')}</p>
          <div className="mt-4 flex gap-2">
            <Button type="button" size="sm" variant={method === 'qr' ? 'default' : 'outline'} aria-pressed={method === 'qr'} onClick={() => setMethod('qr')}>{t('accountMfaUseQrCode')}</Button>
            <Button type="button" size="sm" variant={method === 'manual' ? 'default' : 'outline'} aria-pressed={method === 'manual'} onClick={() => setMethod('manual')}>{t('accountMfaUseSetupKey')}</Button>
          </div>
          <div className="mt-4 min-h-48">
            {method === 'qr' ? (
              <TotpQrCode uri={enrollment.otp_auth_uri} label={t('accountMfaUseQrCode')} />
            ) : (
              <div className="max-w-lg">
                <Field>
                  <FieldLabel htmlFor="totp-setup-key">{t('accountMfaSecret')}</FieldLabel>
                  <InputGroup className="bg-muted/50">
                    <InputGroupInput id="totp-setup-key" name="totp-setup-key" value={enrollment.secret} readOnly className="font-mono" />
                    <InputGroupAddon align="inline-end">
                      <InputGroupButton
                        size="icon-xs"
                        aria-label={secretCopied ? t('accountMfaSecretCopied') : t('accountMfaSecretCopy')}
                        onClick={() => void copySecret()}
                      >
                        {secretCopied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                      </InputGroupButton>
                    </InputGroupAddon>
                  </InputGroup>
                </Field>
                <div className="mt-3 flex items-center gap-2">
                  <a href={enrollment.otp_auth_uri} className={buttonVariants({ variant: 'link', className: 'h-auto px-0' })}>
                    {t('accountMfaOpenAuthenticator')}
                    <ExternalLink aria-hidden="true" />
                  </a>
                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    aria-label={otpAuthCopied ? t('accountMfaOtpAuthCopied') : t('accountMfaOtpAuthCopy')}
                    onClick={() => void copyOtpAuthUri()}
                  >
                    {otpAuthCopied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                  </Button>
                </div>
              </div>
            )}
          </div>
          <div className="mt-4 flex items-center justify-between gap-2">
            {hasRecoveryStep ? <Button type="button" variant="ghost" onClick={() => setStep(1)}>{t('accountMfaBack')}</Button> : <span />}
            <Button type="button" onClick={() => setStep(3)}>{t('accountMfaContinue')}</Button>
          </div>
        </div>
      ) : null}

      {step === 3 ? (
        <div>
          <h2 className="text-sm font-semibold">{stepTitle(t('accountMfaStepVerify'))}</h2>
          <p className="mt-1 text-sm leading-5 text-muted-foreground">{t('accountMfaStepVerifyDescription')}</p>
          <AccountActionForm action="confirm-totp" requestFailedMessage={t('accountRequestFailed')} onSuccess={close} className="mt-4 grid gap-3">
            <input type="hidden" name="login_hint" value={loginHint} />
            <div className="grid gap-2">
              <FieldLabel htmlFor="mfa-code">{t('otp')}</FieldLabel>
              <TotpInput
                id="mfa-code"
                name="code"
                value={code}
                onChange={retryVerification}
                autoFocus
                isInvalid={Boolean(visibleCodeError)}
                aria-describedby={visibleCodeError ? 'mfa-code-error' : undefined}
                className="w-fit"
              />
              {visibleCodeError ? <p id="mfa-code-error" className="text-sm text-destructive">{visibleCodeError}</p> : null}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="ghost" onClick={returnToConfiguration}>{t('accountMfaBack')}</Button>
              <Button type="submit" className="ms-auto">{t('accountMfaConfirm')}</Button>
            </div>
          </AccountActionForm>
          {visibleCodeError ? (
            <Alert className="mt-4">
              <TriangleAlert className="text-warning" aria-hidden="true" />
              <AlertTitle>{t('accountMfaLegacyTitle')}</AlertTitle>
              <AlertDescription>
                <p>{t('accountMfaLegacyDescription')}</p>
                <AccountActionForm
                  action="use-legacy-totp"
                  requestFailedMessage={t('accountRequestFailed')}
                  onSuccess={() => {
                    setCode('')
                    setShowCodeError(false)
                  }}
                  className="mt-3"
                >
                  <Button type="submit" size="sm" variant="outline">{t('accountMfaUseLegacy')}</Button>
                </AccountActionForm>
              </AlertDescription>
            </Alert>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
