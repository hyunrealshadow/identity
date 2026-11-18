import { Button } from '@identity/ui/components/button'
import { Field, FieldLabel } from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, CircleAlert, Fingerprint } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { LoginClient } from '#/components/login-client'
import { PasskeyLogin } from '#/components/passkey-login'
import { ProgressiveForm } from '#/components/progressive-form'
import { RecoveryCodeList, RecoveryCodeTools } from '#/components/recovery-code-tools'
import { SubmitButton } from '#/components/submit-button'
import { errorMessage, identityJson, isTerminalLoginError } from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  ChallengeResponse,
  LoginStatusResponse,
  PasskeyEnrollmentResponse,
} from '#/lib/identity-types'
import { translate, type Locale } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { submitLoginPasskeySetup } from '#/lib/login-passkey-setup.server'
import { loginChallengeDestination, loginPasskeySetupPath } from '#/lib/login-navigation'
import { createPasskey, passkeysSupported, type PasskeyOptions } from '#/lib/passkey'
import { consumeFormFlash } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'

interface PasskeySetupSearch {
  login_id?: string
  restart?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadPasskeySetupPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; restart?: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginPasskeySetupPath)
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const page = {
      loginId,
      locale,
      uiLocales,
      csrfToken: '',
      status: undefined as LoginStatusResponse | undefined,
      recoveryCodes: [] as Array<string>,
      // WebAuthn options stay JSON so the loader result remains serializable.
      optionsJson: undefined as string | undefined,
      error: flash?.message,
      restartRequired: false,
      restartUnavailable: false,
      redirectTo: undefined as string | undefined,
    }
    if (!loginId) return { ...page, error: page.error ?? translate(locale, 'missingLogin') }

    try {
      const active = await identityJson<ActiveAccountsResponse>('/api/auth/sessions/active')
      page.csrfToken = active.csrf_token
      if (data.restart === 'required' || data.restart === 'unavailable') {
        const restartUnavailable = data.restart === 'unavailable'
        return {
          ...page,
          restartRequired: true,
          restartUnavailable,
          error:
            page.error ??
            translate(
              locale,
              restartUnavailable ? 'authorizationRestartUnavailable' : 'challengeExpiredDescription',
            ),
        }
      }
      const status = await identityJson<LoginStatusResponse>(
        `/api/auth/login/${encodeURIComponent(loginId)}`,
      )
      page.status = status
      if (status.status === 'expired') {
        return { ...page, restartRequired: true, error: translate(locale, 'challengeExpiredDescription') }
      }
      if (status.status !== 'mfa_enrollment_required' || status.enrollment_method !== 'passkey') {
        // The interaction moved on, or asks for another credential: continue
        // wherever it now stands.
        const search = new URLSearchParams({ login_id: loginId })
        if (uiLocales) search.set('ui_locales', uiLocales)
        return {
          ...page,
          redirectTo:
            status.continue_uri ??
            status.challenge_uri ??
            (status.status === 'mfa_required' && status.preferred_credential_type
              ? loginChallengeDestination(loginId, status.preferred_credential_type, uiLocales)
              : `/login?${search}`),
        }
      }
      const enrollment = await identityJson<PasskeyEnrollmentResponse>(
        '/api/auth/login/passkey-enrollment',
        { method: 'POST', csrfToken: active.csrf_token, body: { id: loginId } },
      )
      return {
        ...page,
        recoveryCodes: enrollment.recovery_codes,
        optionsJson: JSON.stringify(enrollment.options),
      }
    } catch (error) {
      if (isTerminalLoginError(error)) {
        return {
          ...page,
          restartRequired: true,
          error: page.error ?? translate(locale, 'challengeExpiredDescription'),
        }
      }
      return { ...page, error: page.error ?? errorMessage(error, locale) }
    }
  })

const confirmPasskey = createServerFn({ method: 'POST' })
  .validator(
    (data: {
      loginId: string
      csrfToken: string
      challengeId: string
      name: string
      credential: string
      locale: Locale
    }) => data,
  )
  .handler(async ({ data }) => {
    try {
      const result = await identityJson<ChallengeResponse>(
        '/api/auth/login/passkey-enrollment/confirm',
        {
          method: 'POST',
          csrfToken: data.csrfToken,
          body: {
            id: data.loginId,
            challenge_id: data.challengeId,
            name: data.name,
            credential: JSON.parse(data.credential) as unknown,
          },
        },
      )
      return { registered: result.status === 'mfa_required' }
    } catch (error) {
      return { error: errorMessage(error, data.locale) }
    }
  })

export const Route = createFileRoute('/login/passkey-setup')({
  validateSearch: (search): PasskeySetupSearch => ({
    login_id: optionalString(search.login_id),
    restart: optionalString(search.restart),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: async ({ deps }) => {
    const page = await loadPasskeySetupPage({ data: deps })
    if (page.redirectTo) {
      throw redirect({ href: withUiLocales(page.redirectTo, deps.uiLocales), reloadDocument: true })
    }
    return page
  },
  server: {
    handlers: {
      POST: ({ request }) => submitLoginPasskeySetup(request),
    },
  },
  component: PasskeySetupPage,
})

function PasskeySetupPage() {
  const data = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const options = data.optionsJson ? (JSON.parse(data.optionsJson) as PasskeyOptions) : undefined
  const user = data.status?.user
  const hasRecoveryCodes = data.recoveryCodes.length > 0
  // Recovery codes first (they are stored with the new passkey), then
  // registration, then sign-in with the passkey just created.
  const [screen, setScreen] = useState<'recovery' | 'create' | 'signIn'>(
    hasRecoveryCodes ? 'recovery' : 'create',
  )
  const [name, setName] = useState('')
  const [supported, setSupported] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const registration = useRef<AbortController | null>(null)
  const pathname = loginPasskeySetupPath
  const canSwitchAccount = !data.status?.requires_reauthentication

  useEffect(() => {
    setSupported(passkeysSupported())
    return () => registration.current?.abort()
  }, [])

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!options || registration.current || !supported || !name.trim()) return
    const controller = new AbortController()
    registration.current = controller
    setBusy(true)
    setError('')
    try {
      const credential = await createPasskey(options, controller.signal)
      if (controller.signal.aborted) return
      const result = await confirmPasskey({
        data: {
          loginId: data.loginId,
          csrfToken: data.csrfToken,
          challengeId: options.challenge_id,
          name: name.trim(),
          credential: JSON.stringify(credential),
          locale: data.locale,
        },
      })
      if (controller.signal.aborted) return
      if (result.registered) setScreen('signIn')
      else setError(result.error ?? t('passkeyFailed'))
    } catch (caught) {
      if (!controller.signal.aborted) {
        const cancelled =
          (caught instanceof Error || caught instanceof DOMException) && caught.name === 'NotAllowedError'
        setError(t(cancelled ? 'passkeyCancelled' : 'passkeyFailed'))
      }
    } finally {
      if (registration.current === controller) {
        registration.current = null
        setBusy(false)
      }
    }
  }

  const hiddenFields = (
    <>
      <input type="hidden" name="login_id" value={data.loginId} />
      <input type="hidden" name="csrf_token" value={data.csrfToken} />
      <input type="hidden" name="ui_locales" value={data.uiLocales} />
    </>
  )

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      tone={data.restartRequired ? 'danger' : 'default'}
      titleIcon={data.restartRequired ? <CircleAlert className="size-6" aria-hidden="true" /> : undefined}
      title={
        data.restartRequired
          ? t('challengeExpiredTitle')
          : screen === 'recovery'
            ? t('accountRecoveryCodesTitle')
            : screen === 'signIn'
              ? t('passkeySetupSignInTitle')
              : t('passkeySetupTitle')
      }
      description={
        data.restartUnavailable
          ? t('authorizationRestartUnavailable')
          : data.restartRequired
            ? data.error || t('challengeExpiredDescription')
            : screen === 'recovery'
              ? t('passkeySetupRecoveryDescription')
              : screen === 'signIn'
                ? t('passkeySetupSignInDescription')
                : t('passkeySetupLoginDescription')
      }
    >
      <LoginClient client={data.status?.client} locale={data.locale} />
      {user ? (
        <div className="mb-6 flex items-center gap-3 rounded-xl border bg-muted/50 p-3">
          <AccountAvatar name={user.name} picture={user.picture} />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{user.name}</p>
            <p className="truncate text-xs text-muted-foreground">{user.email}</p>
          </div>
        </div>
      ) : null}

      {data.error && !data.restartRequired ? (
        <ErrorAlert className="mb-5" title={t('verificationFailed')} message={data.error} />
      ) : null}

      {data.restartRequired && !data.restartUnavailable ? (
        <ProgressiveForm action={pathname} enhancementErrorMessage={t('enhancedNavigationError')}>
          <input type="hidden" name="intent" value="restart" />
          {hiddenFields}
          <SubmitButton fullWidth>{t('restartSignIn')}</SubmitButton>
        </ProgressiveForm>
      ) : null}

      {!data.restartRequired && options && screen === 'recovery' ? (
        <>
          <RecoveryCodeList
            codes={data.recoveryCodes}
            copyLabel={t('accountRecoveryCodeCopy')}
            copiedLabel={t('accountRecoveryCodeCopied')}
          />
          <div className="js-only mt-3 flex flex-wrap gap-2">
            <RecoveryCodeTools
              codes={data.recoveryCodes}
              copyLabel={t('accountRecoveryCodesCopy')}
              copiedLabel={t('accountRecoveryCodesCopied')}
              printLabel={t('accountRecoveryCodesPrint')}
              downloadLabel={t('accountRecoveryCodesDownload')}
            />
          </div>
          <Button className="js-only mt-6 w-full" onClick={() => setScreen('create')}>
            {t('mfaSetupRecoveryContinue')}
          </Button>
          <p className="no-js-only mt-6 text-xs text-muted-foreground">{t('passkeyRequiresJavascript')}</p>
        </>
      ) : null}

      {!data.restartRequired && options && screen === 'create' ? (
        <form className="space-y-6" onSubmit={(event) => void register(event)} noValidate>
          <Field>
            <FieldLabel htmlFor="passkey-setup-name">{t('passkeyName')}</FieldLabel>
            <Input
              id="passkey-setup-name"
              value={name}
              maxLength={100}
              autoFocus
              placeholder={t('passkeyNamePlaceholder')}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Button
            type="submit"
            className="w-full"
            disabled={!supported || !name.trim()}
            loading={busy}
          >
            {busy ? null : <Fingerprint aria-hidden="true" />}
            {t('passkeySetupCreate')}
          </Button>
          <p className="no-js-only text-xs text-muted-foreground">{t('passkeyRequiresJavascript')}</p>
          {!supported ? <p className="js-only text-xs text-muted-foreground">{t('passkeyUnsupported')}</p> : null}
          {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
        </form>
      ) : null}

      {!data.restartRequired && screen === 'signIn' ? (
        <PasskeyLogin
          loginId={data.loginId}
          csrfToken={data.csrfToken}
          locale={data.locale}
          uiLocales={data.uiLocales || undefined}
          primary
        />
      ) : null}

      {!data.restartRequired && canSwitchAccount && data.loginId ? (
        <ProgressiveForm action={pathname} className="mt-6" enhancementErrorMessage={t('enhancedNavigationError')}>
          {hiddenFields}
          <SubmitButton
            name="intent"
            value="switch"
            variant="link"
            size="sm"
            className="mx-auto flex w-fit font-semibold"
          >
            <ArrowLeft className="size-4" aria-hidden="true" />
            {t('switchAccount')}
          </SubmitButton>
        </ProgressiveForm>
      ) : null}
    </AuthShell>
  )
}
