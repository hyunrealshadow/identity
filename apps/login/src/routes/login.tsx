import {
  Alert,
  Avatar,
  Button,
  Input,
  Label,
  TextField,
} from '@heroui/react'
import {
  Outlet,
  createFileRoute,
  useRouterState,
} from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ChevronRight, Plus, UserRound } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import {
  errorMessage,
  identityJson,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  IdentifierResponse,
  LoginStatusResponse,
} from '#/lib/identity-types'
import {
  formErrorResponse,
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
  .validator((data: { loginId: string }) => data)
  .handler(async ({ data }) => {
    try {
      const [active, status] = await Promise.all([
        identityJson<ActiveAccountsResponse>('/api/auth/sessions/active'),
        identityJson<LoginStatusResponse>(
          `/api/auth/login/${encodeURIComponent(data.loginId)}`,
        ),
      ])

      return {
        accounts: status.prompt === 'login' ? [] : active.accounts,
        csrfToken: active.csrf_token,
        locale: requestLocale(status.ui_locales),
        uiLocales: status.ui_locales?.join(' ') ?? '',
        error: undefined,
      }
    } catch (error) {
      const locale = requestLocale()
      return {
        accounts: [],
        csrfToken: '',
        locale,
        uiLocales: '',
        error: errorMessage(error, locale),
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
  loaderDeps: ({ search }) => ({ loginId: search.login_id ?? '' }),
  loader: ({ deps }) =>
    deps.loginId
      ? loadLoginPage({ data: { loginId: deps.loginId } })
      : Promise.resolve({
          accounts: [],
          csrfToken: '',
          locale: 'en-US' as const,
          uiLocales: '',
          error: translate('en-US', 'missingLogin'),
        }),
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
            await identityJson('/api/auth/login/select', {
              method: 'POST',
              csrfToken,
              body: {
                id: String(form.get('session_id') ?? ''),
                login_id: loginId,
              },
            })
            return navigationResponse(
              request,
              `/oauth2/continue?login_id=${encodeURIComponent(loginId)}`,
            )
          }

          const identifier = String(form.get('identifier') ?? '').trim()
          if (!identifier) {
            return formErrorResponse(
              request,
              '/login',
              translate(locale, 'identifierRequired'),
              { login_id: loginId, ui_locales: uiLocales },
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
          return formErrorResponse(request, '/login', errorMessage(error, locale), {
            login_id: loginId,
            identifier: optionalString(form.get('identifier')),
            ui_locales: uiLocales,
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
  const loginId = search.login_id ?? ''
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
        <div className="space-y-3">
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
              <Button
                type="submit"
                variant="secondary"
                fullWidth
                className="h-auto justify-start gap-3 px-4 py-3 text-left"
              >
                <Avatar size="sm">
                  <Avatar.Fallback>{account.name.slice(0, 1)}</Avatar.Fallback>
                </Avatar>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-semibold">
                    {account.name}
                  </span>
                  <span className="block truncate text-xs text-muted">
                    {account.email}
                  </span>
                </span>
                <ChevronRight className="size-4 text-muted" aria-hidden="true" />
              </Button>
            </ProgressiveForm>
          ))}
          <a
            href={`/login?login_id=${encodeURIComponent(loginId)}&no_accounts=1${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
            className="flex min-h-11 items-center justify-center gap-2 rounded-xl text-sm font-semibold text-accent transition hover:bg-accent/5"
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
          <TextField isRequired fullWidth name="identifier">
            <Label>{t('identifier')}</Label>
            <Input
              autoFocus
              defaultValue={search.identifier}
              autoComplete="username"
              placeholder="name@example.com"
            />
          </TextField>
          <Button type="submit" fullWidth>
            {t('next')}
          </Button>
          {data.accounts.length > 0 ? (
            <a
              href={`/login?login_id=${encodeURIComponent(loginId)}${data.uiLocales ? `&ui_locales=${encodeURIComponent(data.uiLocales)}` : ''}`}
              className="flex justify-center text-sm font-semibold text-accent hover:underline"
            >
              {t('backToAccounts')}
            </a>
          ) : null}
        </ProgressiveForm>
      )}

      <div className="mt-7 flex items-center justify-center gap-2 text-xs text-muted">
        <UserRound className="size-3.5" aria-hidden="true" />
        {t('loginPrivacy')}
      </div>
    </AuthShell>
  )
}

function ErrorAlert({ message, title = 'Unable to continue' }: { message: string; title?: string }) {
  return (
    <Alert status="danger" className="mb-5">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{title}</Alert.Title>
        <Alert.Description>{message}</Alert.Description>
      </Alert.Content>
    </Alert>
  )
}
