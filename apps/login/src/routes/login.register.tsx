import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ArrowLeft, CircleAlert, MailCheck } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { LoginClient } from '#/components/login-client'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { useSecondsUntil } from '#/components/use-seconds-until'
import { errorMessage, identityJson, isTerminalLoginError } from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
  RegistrationCheckResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { loginRegisterPath } from '#/lib/login-navigation'
import { submitRegistration } from '#/lib/registration.server'
import { consumeFormFlash } from '#/lib/responses.server'

interface RegisterSearch {
  login_id?: string
  /** The token of an emailed registration link. */
  token?: string
  restart?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadRegisterPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; token?: string; restart?: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(loginRegisterPath)
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const page = {
      status: undefined as LoginStatusResponse | undefined,
      csrfToken: '',
      loginId,
      locale,
      uiLocales,
      error: flash?.fields ? undefined : flash?.message,
      fields: flash?.fields ?? {},
      values: flash?.values ?? {},
      linkEmail: undefined as string | undefined,
      linkError: undefined as string | undefined,
      restartRequired: data.restart === 'required' || data.restart === 'unavailable',
      restartUnavailable: data.restart === 'unavailable',
    }
    if (!loginId) return { ...page, error: page.error ?? translate(locale, 'missingLogin') }

    try {
      page.csrfToken = (await identityJson<ActiveAccountsResponse>('/api/auth/sessions/active')).csrf_token
      if (page.restartRequired) {
        return {
          ...page,
          error: page.error ?? translate(locale, page.restartUnavailable ? 'authorizationRestartUnavailable' : 'challengeExpiredDescription'),
        }
      }
      page.status = await identityJson<LoginStatusResponse>(`/api/auth/login/${encodeURIComponent(loginId)}`)
      if (page.status.status === 'expired') {
        return { ...page, restartRequired: true, error: translate(locale, 'challengeExpiredDescription') }
      }
      if (data.token) {
        try {
          const link = await identityJson<RegistrationCheckResponse>('/api/auth/login/registration/check', {
            method: 'POST',
            csrfToken: page.csrfToken,
            body: { id: loginId, token: data.token },
          })
          page.linkEmail = link.email
        } catch (error) {
          if (isTerminalLoginError(error)) throw error
          page.linkError = errorMessage(error, locale)
        }
      }
      return page
    } catch (error) {
      if (isTerminalLoginError(error)) {
        return { ...page, restartRequired: true, error: page.error ?? translate(locale, 'challengeExpiredDescription') }
      }
      return { ...page, error: page.error ?? errorMessage(error, locale) }
    }
  })

/**
 * Create an account from the identifier step. The address comes first: an
 * emailed link verifies it, and only then are a username and password
 * chosen. The page says the same thing whether or not the address already
 * has an account.
 */
export const Route = createFileRoute('/login/register')({
  validateSearch: (search): RegisterSearch => ({
    login_id: optionalString(search.login_id),
    token: optionalString(search.token),
    restart: optionalString(search.restart),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    token: search.token,
    restart: search.restart,
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => loadRegisterPage({ data: deps }),
  headers: () => ({
    'Cache-Control': 'no-store',
    // A link's token is in this page's address; never pass it on.
    'Referrer-Policy': 'no-referrer',
  }),
  server: {
    handlers: {
      POST: ({ request }) => submitRegistration(request),
    },
  },
  component: RegisterPage,
})

function RegisterPage() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const token = search.token
  const creating = Boolean(token) && Boolean(data.linkEmail)
  const resendAt = data.status?.registration_resend_available_at
  const sent = !creating && Boolean(resendAt)
  const resendWait = useSecondsUntil(resendAt)
  const available = data.status?.registration_available ?? false
  const { restartRequired, restartUnavailable } = data
  const signInPage = `/login?${new URLSearchParams({
    login_id: data.loginId,
    ...(data.uiLocales ? { ui_locales: data.uiLocales } : {}),
  })}`
  const hidden = (
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
      tone={restartRequired ? 'danger' : 'default'}
      titleIcon={restartRequired ? <CircleAlert className="size-6" aria-hidden="true" /> : undefined}
      title={
        restartRequired
          ? t('challengeExpiredTitle')
          : creating
            ? t('registrationDetailsTitle')
            : t('registrationTitle')
      }
      description={
        restartUnavailable
          ? t('authorizationRestartUnavailable')
          : restartRequired
            ? data.error || t('challengeExpiredDescription')
            : creating
              ? t('registrationDetailsDescription')
              : sent
                ? t('registrationSentDescription')
                : t('registrationDescription')
      }
    >
      <LoginClient client={data.status?.client} locale={data.locale} />

      {data.linkError && !restartRequired ? (
        <ErrorAlert className="mb-5" title={t('registrationLinkFailed')} message={data.linkError} />
      ) : data.error && !restartRequired ? (
        <ErrorAlert className="mb-5" message={data.error} />
      ) : null}

      {restartRequired ? (
        restartUnavailable ? null : (
          <ProgressiveForm action={loginRegisterPath} className="progressive-form" enhancementErrorMessage={t('enhancedNavigationError')}>
            <input type="hidden" name="intent" value="restart" />
            {hidden}
            <SubmitButton fullWidth>{t('restartSignIn')}</SubmitButton>
          </ProgressiveForm>
        )
      ) : creating ? (
        <ProgressiveForm
          action={loginRegisterPath}
          className="progressive-form space-y-6"
          enhancementErrorMessage={t('enhancedNavigationError')}
          validationErrors={data.fields}
          noValidate
        >
          {hidden}
          <input type="hidden" name="intent" value="register" />
          <input type="hidden" name="token" value={token} />
          <div className="space-y-1.5">
            <p className="text-sm font-medium">{t('accountEmail')}</p>
            <p className="truncate rounded-lg border bg-muted/50 px-3 py-2 text-sm">{data.linkEmail}</p>
          </div>
          <TextField
            required
            name="username"
            label={t('accountUsername')}
            error={data.fields.username}
            defaultValue={data.values.username}
            autoFocus
            autoComplete="username"
            description={t('registrationUsernameHint')}
          />
          <TextField
            required
            name="new_password"
            label={t('password')}
            error={data.fields.new_password}
            type="password"
            autoComplete="new-password"
            reveal={{ show: t('showPassword'), hide: t('hidePassword') }}
          />
          <TextField
            required
            name="confirm_password"
            label={t('installConfirmPassword')}
            error={data.fields.confirm_password}
            type="password"
            autoComplete="new-password"
          />
          <SubmitButton fullWidth>{t('registrationSubmit')}</SubmitButton>
        </ProgressiveForm>
      ) : available ? (
        <>
          {sent ? (
            <p className="mb-4 flex items-start gap-2 rounded-lg bg-muted/60 px-3 py-2.5 text-sm text-muted-foreground" role="status">
              <MailCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
              {t('registrationSentNotice')}
            </p>
          ) : null}
          <ProgressiveForm
            action={loginRegisterPath}
            className="progressive-form space-y-6"
            enhancementErrorMessage={t('enhancedNavigationError')}
            validationErrors={data.fields}
            noValidate
          >
            {hidden}
            <input type="hidden" name="intent" value="send" />
            <TextField
              required
              name="email"
              type="email"
              label={t('accountEmail')}
              error={data.fields.email}
              defaultValue={data.values.email}
              autoFocus={!sent}
              autoComplete="email"
              placeholder="name@example.com"
            />
            <SubmitButton variant={sent ? 'outline' : 'default'} fullWidth disabled={resendWait > 0}>
              {!sent
                ? t('registrationSend')
                : resendWait > 0
                  ? translate(data.locale, 'registrationResendIn', { seconds: resendWait })
                  : t('registrationResend')}
            </SubmitButton>
          </ProgressiveForm>
        </>
      ) : data.status && !data.error && !data.linkError ? (
        <ErrorAlert className="mb-5" message={t('registrationUnavailable')} />
      ) : null}

      {!restartRequired && data.loginId ? (
        <a
          href={signInPage}
          className="text-link mx-auto mt-6 flex w-fit items-center gap-1.5 text-sm font-semibold"
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('registrationBack')}
        </a>
      ) : null}
    </AuthShell>
  )
}
