import {
  Alert,
  FieldError,
  Input,
  Label,
  TextField,
} from '@heroui/react'
import {
  Outlet,
  createFileRoute,
  redirect,
  useRouterState,
} from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ChevronRight, Plus } from 'lucide-react'
import { useState } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { beginAuthorization } from '#/lib/authorization-flow'
import {
  errorMessage,
  IdentityApiError,
  identityJson,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  IdentifierResponse,
  LoginStatusResponse,
  SelectAccountResponse,
} from '#/lib/identity-types'
import {
  consumeFormFlash,
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'

interface LoginSearch {
  login_id?: string
  no_accounts?: string
  identifier?: string
  error?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadLoginPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/login')
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales || flash?.values.ui_locales || ''
    const identifierError =
      flash?.fields?.identifier ??
      (flash?.field === 'identifier' ? flash.message : undefined)
    const pageError = identifierError ? undefined : flash?.message

    if (!loginId) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        accounts: [],
        csrfToken: '',
        loginId,
        locale,
        uiLocales,
        error: pageError ?? translate(locale, 'missingLogin'),
        fieldError: identifierError,
        formValues: flash?.values ?? {},
        challengeUri: undefined,
      }
    }

    try {
      const [active, status] = await Promise.all([
        identityJson<ActiveAccountsResponse>('/api/auth/sessions/active'),
        identityJson<LoginStatusResponse>(
          `/api/auth/login/${encodeURIComponent(loginId)}`,
        ),
      ])

      return {
        accounts:
          status.prompt === 'login' || status.requires_reauthentication
            ? []
            : active.accounts,
        csrfToken: active.csrf_token,
        loginId,
        locale: requestLocale(status.ui_locales),
        uiLocales: status.ui_locales?.join(' ') ?? '',
        error: pageError,
        fieldError: identifierError,
        formValues: flash?.values ?? {},
        challengeUri: status.challenge_uri,
      }
    } catch (error) {
      const locale = requestLocale()
      return {
        accounts: [],
        csrfToken: '',
        loginId,
        locale,
        uiLocales,
        error: pageError ?? errorMessage(error, locale),
        fieldError: identifierError,
        formValues: flash?.values ?? {},
        challengeUri: undefined,
      }
    }
  })

export const Route = createFileRoute('/login')({
  validateSearch: (search): LoginSearch => ({
    login_id: optionalString(search.login_id),
    no_accounts: optionalString(search.no_accounts),
    identifier: optionalString(search.identifier),
    error: optionalString(search.error),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    uiLocales: search.ui_locales,
  }),
  loader: async ({ deps, location }) => {
    if (!deps.loginId) {
      throw redirect({ href: await beginAuthorization() })
    }
    const page = await loadLoginPage({ data: deps })
    if (location.pathname === '/login' && page.challengeUri) {
      throw redirect({ href: page.challengeUri })
    }
    return page
  },
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const intent = String(form.get('intent') ?? '')
        const loginId = String(form.get('login_id') ?? '')
        const csrfToken = String(form.get('csrf_token') ?? '')
        const locale = formLocale(request, form.get('ui_locales'))
        const uiLocales = optionalString(form.get('ui_locales'))

        if (!loginId) {
          return formErrorResponse(request, '/login', translate(locale, 'missingLoginShort'), {})
        }

        try {
          if (intent === 'select') {
            const result = await identityJson<SelectAccountResponse>('/api/auth/login/select', {
              method: 'POST',
              csrfToken,
              body: {
                id: String(form.get('session_id') ?? ''),
                login_id: loginId,
              },
            })
            return navigationResponse(request, result.continue_uri)
          }

          const identifier = String(form.get('identifier') ?? '').trim()
          if (!identifier) {
            return formErrorResponse(
              request,
              '/login',
              translate(locale, 'identifierRequired'),
              { login_id: loginId, ui_locales: uiLocales },
              'identifier',
            )
          }

          const result = await identityJson<IdentifierResponse>(
            '/api/auth/login/identifier',
            {
              method: 'POST',
              csrfToken,
              body: {
                id: loginId,
                identifier,
              },
            },
          )
          const credentialType = result.credential_types.includes('password')
            ? 'password'
            : result.credential_types.includes('otp')
              ? 'otp'
              : result.credential_types[0]

          if (!credentialType) throw new Error(translate(locale, 'noCredential'))

          const destination = new URL('/login/challenge', request.url)
          destination.searchParams.set('login_id', result.id)
          destination.searchParams.set('credential_type', credentialType)
          if (uiLocales) destination.searchParams.set('ui_locales', uiLocales)
          return navigationResponse(request, destination.toString())
        } catch (error) {
          const values = {
            login_id: loginId,
            identifier: optionalString(form.get('identifier')),
            ui_locales: uiLocales,
          }
          if (error instanceof IdentityApiError && error.fields.length > 0) {
            return formValidationErrorResponse(
              request,
              '/login',
              error.message,
              values,
              Object.fromEntries(
                error.fields.map((fieldError) => [
                  fieldError.field,
                  fieldError.message,
                ]),
              ),
            )
          }
          return formErrorResponse(request, '/login', errorMessage(error, locale), {
            ...values,
          })
        }
      },
    },
  },
  component: LoginRoute,
})

function LoginRoute() {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })

  return pathname === '/login' ? <LoginPage /> : <Outlet />
}

function LoginPage() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  const [identifierError, setIdentifierError] = useState(data.fieldError)
  const loginId = data.loginId
  const showAccounts = data.accounts.length > 0 && search.no_accounts !== '1'
  const visibleError = search.error ?? data.error
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)

  return (
    <AuthShell
      lang={data.locale}
      title={showAccounts ? t('chooseAccount') : t('signIn')}
      description={
        showAccounts
          ? t('chooseAccountDescription')
          : t('signInDescription')
      }
    >
      {visibleError ? <ErrorAlert message={visibleError} title={t('unableToContinue')} /> : null}

      {showAccounts ? (
        <div className="auth-stagger-fast space-y-3">
          {data.accounts.map((account) => (
            <ProgressiveForm
              action="/login"
              key={account.id}
              className="progressive-form"
              enhancementErrorMessage={t('enhancedNavigationError')}
            >
              <input type="hidden" name="intent" value="select" />
              <input type="hidden" name="login_id" value={loginId} />
              <input type="hidden" name="session_id" value={account.id} />
              <input type="hidden" name="ui_locales" value={data.uiLocales} />
              <input
                type="hidden"
                name="csrf_token"
                value={data.csrfToken}
              />
              <SubmitButton
                variant="secondary"
                fullWidth
                className="group h-auto justify-start gap-3 px-4 py-3 text-left hover:-translate-y-0.5 hover:shadow-[0_14px_30px_-14px_rgba(0,0,0,0.3)]"
              >
                <AccountAvatar name={account.name} picture={account.picture} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-semibold">
                    {account.name}
                  </span>
                  <span className="block truncate text-xs text-muted">
                    {account.email}
                  </span>
                </span>
                <ChevronRight
                  className="size-4 text-muted transition-transform duration-200 group-hover:translate-x-0.5 group-hover:text-foreground"
                  aria-hidden="true"
                />
              </SubmitButton>
            </ProgressiveForm>
          ))}
          <a
            href={`/login?login_id=${encodeURIComponent(loginId)}&no_accounts=1${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
            className="flex min-h-11 items-center justify-center gap-2 rounded-xl text-sm font-semibold text-accent transition-colors duration-200 hover:bg-accent/5 active:scale-[0.98]"
          >
            <Plus className="size-4" aria-hidden="true" />
              {t('useAnotherAccount')}
          </a>
        </div>
      ) : (
        <ProgressiveForm action="/login" className="progressive-form space-y-5" enhancementErrorMessage={t('enhancedNavigationError')}>
          <input type="hidden" name="intent" value="identifier" />
          <input type="hidden" name="login_id" value={loginId} />
          <input type="hidden" name="csrf_token" value={data.csrfToken} />
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
          <TextField isRequired fullWidth name="identifier" isInvalid={!!identifierError}>
            <Label>{t('identifier')}</Label>
            <Input
              autoFocus
              defaultValue={data.formValues.identifier ?? search.identifier}
              autoComplete="username"
              placeholder="name@example.com"
              onChange={() => setIdentifierError(undefined)}
            />
            <FieldError>{identifierError}</FieldError>
          </TextField>
          <SubmitButton fullWidth>
            {t('next')}
          </SubmitButton>
          {data.accounts.length > 0 ? (
            <a
              href={`/login?login_id=${encodeURIComponent(loginId)}${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
              className="auth-link mx-auto flex w-fit justify-center text-sm font-semibold text-accent"
            >
              {t('backToAccounts')}
            </a>
          ) : null}
        </ProgressiveForm>
      )}
    </AuthShell>
  )
}

function ErrorAlert({ message, title }: { message: string; title: string }) {
  return (
    <Alert
      status="danger"
      className="auth-alert mb-5"
    >
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{title}</Alert.Title>
        <Alert.Description>{message}</Alert.Description>
      </Alert.Content>
    </Alert>
  )
}
