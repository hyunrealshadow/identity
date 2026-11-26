import {
  Outlet,
  createFileRoute,
  redirect,
  useRouterState,
} from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { beginAuthorization } from '#/lib/authorization-flow'
import {
  errorMessage,
  identityJson,
} from '#/lib/identity.server'
import type {
  ActiveAccountsResponse,
  LoginStatusResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'
import { submitLoginPost } from '#/modules/auth/lib/login-route.server'
import {
  LoginPageView,
  type LoginPageSearch,
} from '#/modules/auth/pages/login-page'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadLoginPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/login')
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
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
        loginHint: undefined,
        challengeUri: undefined,
        client: undefined,
        registrationAvailable: false,
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
        locale: requestLocale(uiLocales.split(' ')),
        uiLocales,
        error: pageError,
        fieldError: identifierError,
        formValues: flash?.values ?? {},
        loginHint: status.login_hint,
        challengeUri: status.challenge_uri,
        client: status.client,
        registrationAvailable: status.registration_available ?? false,
      }
    } catch (error) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        accounts: [],
        csrfToken: '',
        loginId,
        locale,
        uiLocales,
        error: pageError ?? errorMessage(error, locale),
        fieldError: identifierError,
        formValues: flash?.values ?? {},
        loginHint: undefined,
        challengeUri: undefined,
        client: undefined,
        registrationAvailable: false,
      }
    }
  })

export const Route = createFileRoute('/login')({
  validateSearch: (search): LoginPageSearch => ({
    login_id: optionalString(search.login_id),
    // The router's JSON search parser turns the link's `no_accounts=1` into
    // a number. Preserve that flag so "Use another account" opens the form.
    no_accounts: search.no_accounts === 1 || search.no_accounts === '1' ? '1' : undefined,
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
      // The provider endpoint belongs to the server even when it shares our origin
      throw redirect({
        href: withUiLocales(await beginAuthorization(), deps.uiLocales),
        reloadDocument: true,
      })
    }
    const page = await loadLoginPage({ data: deps })
    if (location.pathname === '/login' && page.challengeUri) {
      throw redirect({ href: withUiLocales(page.challengeUri, deps.uiLocales) })
    }
    return page
  },
  server: {
    handlers: {
      POST: ({ request }) => submitLoginPost(request),
    },
  },
  component: LoginRoute,
})

function LoginRoute() {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })
  const search = Route.useSearch()
  const data = Route.useLoaderData()

  return pathname === '/login' ? <LoginPageView data={data} search={search} /> : <Outlet />
}
