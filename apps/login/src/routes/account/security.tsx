import { Alert, Button, InputGroup, Label, Link, Modal, TextField, useOverlayState } from '@heroui/react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { Check, Copy } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AccountActionForm } from '#/components/account-action-form'
import { PageHeading, PasswordField, SettingsCard, SettingsRow } from '#/components/account-settings'
import { RecoveryCodeList, RecoveryCodeTools } from '#/components/recovery-code-tools'
import { TotpQrCode } from '#/components/totp-qr-code'
import { TotpInput } from '#/components/totp-input'
import { translate } from '#/lib/i18n'
import { useAccount } from './route'

interface SecuritySearch {
  setup?: 'mfa'
  step?: 'verify'
  confirm?: 'disable-mfa' | 'change-password' | 'recovery-codes'
}

export const Route = createFileRoute('/account/security')({
  validateSearch: (search): SecuritySearch => ({
    setup: search.setup === 'mfa' ? 'mfa' : undefined,
    step: search.step === 'verify' ? 'verify' : undefined,
    confirm:
      search.confirm === 'disable-mfa' || search.confirm === 'change-password' || search.confirm === 'recovery-codes'
        ? search.confirm
        : undefined,
  }),
  component: SecurityPage,
})

function SecurityPage() {
  const { locale, data, flash, mfa } = useAccount()
  const search = Route.useSearch()
  const security = data.viewer.security
  const loginHint = data.viewer.account.username
  const t = (key: Parameters<typeof translate>[1], values?: Parameters<typeof translate>[2]) => translate(locale, key, values)

  return (
    <>
      <PageHeading title={t('accountSecurity')} description={t('accountSecurityDescription')} />
      <div className="space-y-4">
        <SettingsCard title={t('accountPassword')} description={t('accountPasswordDescription')}>
          <SettingsRow title="••••••••" action={<PasswordModal flash={flash} loginHint={loginHint} requiresAal2={security.totpEnabled} openForm={search.confirm === 'change-password'} t={t} />} />
        </SettingsCard>
        <SettingsCard title={t('accountMfaRowTitle')} description={t('accountMfaDescription')}>
          <div className="divide-y divide-separator">
            <div className={security.totpEnabled ? 'pb-5' : undefined}>
              <SettingsRow
                title={t('accountMfa')}
                description={security.totpEnabled ? t('accountMfaEnabled') : t('accountMfaNotEnabled')}
                action={security.totpEnabled
                  ? <DeleteMfaModal loginHint={loginHint} openConfirm={search.confirm === 'disable-mfa'} t={t} />
                  : <MfaSetupAction flash={flash} mfa={mfa} loginHint={loginHint} openSetup={search.setup === 'mfa'} initialStep={search.step === 'verify' ? 3 : undefined} t={t} />}
              />
            </div>
            {security.totpEnabled ? (
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

function PasswordModal({ flash, loginHint, requiresAal2, openForm, t }: { flash: Flash; loginHint: string; requiresAal2: boolean; openForm: boolean; t: Translator }) {
  const modal = useOverlayState()
  const navigate = useNavigate()

  useEffect(() => {
    if (!openForm) return
    modal.open()
    void navigate({ to: '/account/security', replace: true })
  }, [openForm])

  return <><AccountActionForm action="prepare-change-password" requestFailedMessage={t('accountRequestFailed')} onSuccess={() => modal.open()}><input type="hidden" name="login_hint" value={loginHint} /><input type="hidden" name="requires_aal2" value={String(requiresAal2)} /><Button type="submit" variant="secondary">{t('accountChangePassword')}</Button></AccountActionForm><Modal state={modal}><Modal.Backdrop isDismissable={false}><Modal.Container size="lg"><Modal.Dialog>{({ close }) => <><Modal.CloseTrigger aria-label={t('close')} /><Modal.Header><Modal.Heading>{t('accountChangePassword')}</Modal.Heading></Modal.Header><Modal.Body><AccountActionForm action="change-password" requestFailedMessage={t('accountRequestFailed')} onSuccess={close} className="grid gap-4"><input type="hidden" name="login_hint" value={loginHint} /><PasswordField name="new_password" label={t('accountNewPassword')} error={flash.fields?.new_password} /><PasswordField name="confirm_password" label={t('accountConfirmPassword')} error={flash.fields?.confirm_password} /><div className="flex justify-end"><Button type="submit">{t('accountChangePassword')}</Button></div></AccountActionForm></Modal.Body></>}</Modal.Dialog></Modal.Container></Modal.Backdrop></Modal></>
}

function MfaSetupAction({ flash, mfa, loginHint, openSetup, initialStep, t }: { flash: Flash; mfa: Mfa; loginHint: string; openSetup: boolean; initialStep?: 3; t: Translator }) {
  const hasModalContent = Boolean(mfa.enrollment)
  const modal = useOverlayState()
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
          <Button type="submit" variant="secondary">{t('accountMfaEnable')}</Button>
        </AccountActionForm>
      ) : null}
      {hasModalContent ? <Modal state={modal}>
        <Modal.Trigger><Button variant="secondary">{t('accountMfaEnable')}</Button></Modal.Trigger>
        <Modal.Backdrop isDismissable={false}>
          <Modal.Container size="lg" scroll="outside">
            <Modal.Dialog>
              {({ close }) => <>
                <Modal.CloseTrigger aria-label={t('close')} />
                <Modal.Header><Modal.Heading>{t('accountMfa')}</Modal.Heading></Modal.Header>
                <Modal.Body>
                <div className="space-y-5">
            {mfa.enrollment ? (
              <MfaEnrollmentWizard enrollment={mfa.enrollment} loginHint={loginHint} initialStep={initialStep} codeError={flash.fields?.code} validationRevision={flash.fields} close={close} t={t} />
            ) : (
              <p className="text-sm text-muted">{t('accountMfaRecommendation')}</p>
            )}
                </div>
                </Modal.Body>
              </>}
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal> : null}
    </>
  )
}

function DeleteMfaModal({ loginHint, openConfirm, t }: { loginHint: string; openConfirm: boolean; t: Translator }) {
  const modal = useOverlayState()
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
        <Button type="submit" variant="danger-soft">{t('accountMfaDelete')}</Button>
      </AccountActionForm>
      <Modal state={modal}>
      <Modal.Backdrop isDismissable={false}>
        <Modal.Container size="md">
          <Modal.Dialog>
            {({ close }) => (
              <>
                <Modal.CloseTrigger aria-label={t('close')} />
                <Modal.Header>
                  <Modal.Heading>{t('accountMfaDeleteTitle')}</Modal.Heading>
                </Modal.Header>
                <Modal.Body>
                  <p className="text-sm text-muted">{t('accountMfaDeleteDescription')}</p>
                  <div className="mt-5 flex justify-end gap-2">
                    <Button type="button" variant="secondary" onPress={close}>{t('cancel')}</Button>
                    <AccountActionForm action="disable-totp" requestFailedMessage={t('accountRequestFailed')} onSuccess={close}>
                      <input type="hidden" name="login_hint" value={loginHint} />
                      <Button type="submit" variant="danger">{t('accountMfaDelete')}</Button>
                    </AccountActionForm>
                  </div>
                </Modal.Body>
              </>
            )}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
      </Modal>
    </>
  )
}

function RecoveryCodesModal({ mfa, remaining, loginHint, openManage, t }: { mfa: Mfa; remaining: number; loginHint: string; openManage: boolean; t: Translator }) {
  const modal = useOverlayState()
  const navigate = useNavigate()
  const codes = mfa.recoveryCodes

  useEffect(() => {
    if (!openManage) return
    modal.open()
    void navigate({ to: '/account/security', replace: true })
  }, [openManage])

  return (
    <Modal state={modal}>
      <Modal.Trigger><Button variant="secondary">{t('accountRecoveryCodesManage')}</Button></Modal.Trigger>
      <Modal.Backdrop isDismissable={false}>
        <Modal.Container size="lg" scroll="outside">
          <Modal.Dialog>
            {({ close }) => (
              <>
                <Modal.CloseTrigger aria-label={t('close')} />
                <Modal.Header><Modal.Heading>{codes ? t('accountRecoveryCodesNewTitle') : t('accountRecoveryCodes')}</Modal.Heading></Modal.Header>
                <Modal.Body>
                  {codes ? (
                    <>
                      <p className="text-sm leading-5">{t('accountRecoveryCodesRegeneratedDescription')}</p>
                      <div className="mt-4">
                        <RecoveryCodeList codes={codes} copyLabel={t('accountRecoveryCodeCopy')} copiedLabel={t('accountRecoveryCodeCopied')} />
                      </div>
                      <div className="mt-4 flex flex-wrap items-center gap-2">
                        <RecoveryCodeTools codes={codes} copyLabel={t('accountRecoveryCodesCopy')} copiedLabel={t('accountRecoveryCodesCopied')} printLabel={t('accountRecoveryCodesPrint')} downloadLabel={t('accountRecoveryCodesDownload')} />
                        <Button type="button" className="ms-auto" onPress={close}>{t('done')}</Button>
                      </div>
                    </>
                  ) : (
                    <>
                      <p className="text-sm leading-5">{t('accountRecoveryCodesManageSummary', { count: remaining })}</p>
                      <p className="mt-3 text-sm leading-5 text-danger">{t('accountRecoveryCodesRegenerateWarning')}</p>
                      <div className="mt-5 flex justify-end">
                        <AccountActionForm action="regenerate-recovery-codes" requestFailedMessage={t('accountRequestFailed')} onSuccess={() => modal.open()}>
                          <input type="hidden" name="login_hint" value={loginHint} />
                          <Button type="submit" variant="danger">{t('accountRecoveryCodesRegenerate')}</Button>
                        </AccountActionForm>
                      </div>
                    </>
                  )}
                </Modal.Body>
              </>
            )}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  )
}

function MfaEnrollmentWizard({ enrollment, loginHint, initialStep, codeError, validationRevision, close, t }: { enrollment: NonNullable<Mfa['enrollment']>; loginHint: string; initialStep?: 3; codeError?: string; validationRevision?: Flash['fields']; close: () => void; t: Translator }) {
  const [step, setStep] = useState<1 | 2 | 3>(initialStep ?? (codeError ? 3 : 1))
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
        currentStep={step}
        label={t('accountMfa')}
        steps={[t('accountMfaRecoveryStep'), t('accountMfaStepScan'), t('accountMfaStepVerify')]}
      />

      {step === 1 ? (
        <div>
          <h2 className="text-sm font-semibold">{t('accountMfaRecoveryStep')}</h2>
          <p className="mt-1 text-sm leading-5">{t('accountMfaRecoveryStepDescription')}</p>
          <div className="mt-4">
            <RecoveryCodeList codes={enrollment.recovery_codes} copyLabel={t('accountRecoveryCodeCopy')} copiedLabel={t('accountRecoveryCodeCopied')} />
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <RecoveryCodeTools codes={enrollment.recovery_codes} copyLabel={t('accountRecoveryCodesCopy')} copiedLabel={t('accountRecoveryCodesCopied')} printLabel={t('accountRecoveryCodesPrint')} downloadLabel={t('accountRecoveryCodesDownload')} />
            <Button type="button" className="ms-auto" onPress={() => setStep(2)}>{t('accountMfaContinue')}</Button>
          </div>
        </div>
      ) : null}

      {step === 2 ? (
        <div>
          <h2 className="text-sm font-semibold">{t('accountMfaStepScan')}</h2>
          <p className="mt-1 text-sm leading-5">{t('accountMfaStepScanDescription')}</p>
          <div className="mt-4 flex gap-2">
            <Button type="button" size="sm" variant={method === 'qr' ? 'primary' : 'secondary'} onPress={() => setMethod('qr')}>{t('accountMfaUseQrCode')}</Button>
            <Button type="button" size="sm" variant={method === 'manual' ? 'primary' : 'secondary'} onPress={() => setMethod('manual')}>{t('accountMfaUseSetupKey')}</Button>
          </div>
          <div className="mt-4 min-h-48">
            {method === 'qr' ? (
              <TotpQrCode uri={enrollment.otp_auth_uri} label={t('accountMfaUseQrCode')} />
            ) : (
              <div className="max-w-lg">
                <TextField fullWidth name="totp-setup-key" value={enrollment.secret}>
                  <Label>{t('accountMfaSecret')}</Label>
                  <InputGroup variant="secondary" fullWidth>
                    <InputGroup.Input readOnly className="font-mono" />
                    <InputGroup.Suffix className="pe-0">
                      <Button
                        type="button"
                        isIconOnly
                        size="sm"
                        variant="ghost"
                        aria-label={secretCopied ? t('accountMfaSecretCopied') : t('accountMfaSecretCopy')}
                        title={secretCopied ? t('accountMfaSecretCopied') : t('accountMfaSecretCopy')}
                        onPress={() => void copySecret()}
                      >
                        {secretCopied ? <Check className="size-4" aria-hidden="true" /> : <Copy className="size-4" aria-hidden="true" />}
                      </Button>
                    </InputGroup.Suffix>
                  </InputGroup>
                </TextField>
                <div className="mt-3 flex items-center gap-2">
                  <Link href={enrollment.otp_auth_uri}>
                    {t('accountMfaOpenAuthenticator')}
                  </Link>
                  <Button
                    type="button"
                    isIconOnly
                    size="sm"
                    variant="ghost"
                    aria-label={otpAuthCopied ? t('accountMfaOtpAuthCopied') : t('accountMfaOtpAuthCopy')}
                    title={otpAuthCopied ? t('accountMfaOtpAuthCopied') : t('accountMfaOtpAuthCopy')}
                    onPress={() => void copyOtpAuthUri()}
                  >
                    {otpAuthCopied ? <Check className="size-4" aria-hidden="true" /> : <Copy className="size-4" aria-hidden="true" />}
                  </Button>
                </div>
              </div>
            )}
          </div>
          <div className="mt-4 flex items-center justify-between gap-2">
            <Button type="button" variant="ghost" onPress={() => setStep(1)}>{t('accountMfaBack')}</Button>
            <Button type="button" onPress={() => setStep(3)}>{t('accountMfaContinue')}</Button>
          </div>
        </div>
      ) : null}

      {step === 3 ? (
        <div>
          <h2 className="text-sm font-semibold">{t('accountMfaStepVerify')}</h2>
          <p className="mt-1 text-sm leading-5">{t('accountMfaStepVerifyDescription')}</p>
          <AccountActionForm action="confirm-totp" requestFailedMessage={t('accountRequestFailed')} onSuccess={close} className="mt-4 grid gap-3">
            <input type="hidden" name="login_hint" value={loginHint} />
            <div className="grid gap-2">
              <Label>{t('otp')}</Label>
              <TotpInput
                name="code"
                value={code}
                onChange={retryVerification}
                isInvalid={Boolean(visibleCodeError)}
                aria-describedby={visibleCodeError ? 'mfa-code-error' : undefined}
              />
              {visibleCodeError ? <p id="mfa-code-error" className="text-xs text-danger">{visibleCodeError}</p> : null}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="ghost" onPress={returnToConfiguration}>{t('accountMfaBack')}</Button>
              <Button type="submit" className="ms-auto">{t('accountMfaConfirm')}</Button>
            </div>
          </AccountActionForm>
          {visibleCodeError ? (
            <Alert status="warning" className="mt-4">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('accountMfaLegacyTitle')}</Alert.Title>
                <Alert.Description>{t('accountMfaLegacyDescription')}</Alert.Description>
                <AccountActionForm
                  action="use-legacy-totp"
                  requestFailedMessage={t('accountRequestFailed')}
                  onSuccess={() => {
                    setCode('')
                    setShowCodeError(false)
                  }}
                  className="mt-3"
                >
                  <Button type="submit" size="sm" variant="secondary">{t('accountMfaUseLegacy')}</Button>
                </AccountActionForm>
              </Alert.Content>
            </Alert>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

function MfaStepper({ currentStep, label, steps }: { currentStep: 1 | 2 | 3; label: string; steps: Array<string> }) {
  return (
    <ol className="mb-8 flex w-full" aria-label={label}>
      {steps.map((title, index) => {
        const number = (index + 1) as 1 | 2 | 3
        const status = number < currentStep ? 'complete' : number === currentStep ? 'active' : 'inactive'
        return (
          <li
            key={title}
            className="relative flex min-w-0 flex-1 flex-col items-center text-center"
            data-status={status}
            aria-current={status === 'active' ? 'step' : undefined}
          >
            {index < steps.length - 1 ? (
              <span
                className={`absolute left-1/2 top-3.5 h-0.5 w-full ${status === 'complete' ? 'bg-success' : 'bg-separator'}`}
                aria-hidden="true"
              />
            ) : null}
            <span
              className={`relative z-10 flex size-7 items-center justify-center rounded-full border text-xs font-semibold ${status === 'complete' ? 'border-success bg-success text-white' : status === 'active' ? 'border-foreground bg-foreground text-background' : 'border-separator bg-background text-muted'}`}
              aria-hidden="true"
            >
              {status === 'complete' ? <Check className="size-4" strokeWidth={2.5} /> : number}
            </span>
            <span className={`mt-2 max-w-32 text-xs leading-4 ${status === 'active' ? 'font-semibold text-foreground' : status === 'complete' ? 'font-medium text-success' : 'text-muted'}`}>
              {stepTitle(title)}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

function stepTitle(value: string) {
  return value
    .replace(/^第\s*\d+\s*步\s*/, '')
    .replace(/^Step\s+\d+\s+/i, '')
}
