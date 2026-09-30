import { Alert } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ChevronDown, ExternalLink } from 'lucide-react'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import {
  errorMessage,
  identityJson,
} from '#/lib/identity.server'
import type {
  ConsentApiResponse,
  ConsentPageData,
} from '#/lib/identity-types'
import {
  consumeFormFlash,
  formErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import { scopeDescription, translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'

interface ConsentSearch {
  login_id?: string
  error?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadConsentPage = createServerFn({ method: 'GET' })
  .validator((data: { loginId: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/consent')
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales || flash?.values.ui_locales || ''

    if (!loginId) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        consent: undefined,
        locale,
        uiLocales,
        error: flash?.message ?? translate(locale, 'missingConsent'),
      }
    }

    try {
      const consent = await identityJson<ConsentPageData>(
        `/oauth2/consent?login_id=${encodeURIComponent(loginId)}`,
      )
      return {
        consent,
        locale: requestLocale(uiLocales ? uiLocales.split(' ') : consent.ui_locales),
        uiLocales: uiLocales || consent.ui_locales?.join(' ') || '',
        error: flash?.message,
      }
    } catch (error) {
      const locale = requestLocale()
      return {
        consent: undefined,
        locale,
        uiLocales,
        error: flash?.message ?? errorMessage(error, locale),
      }
    }
  })

export const Route = createFileRoute('/consent')({
  validateSearch: (search): ConsentSearch => ({
    login_id: optionalString(search.login_id),
    error: optionalString(search.error),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => loadConsentPage({ data: deps }),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const loginId = String(form.get('login_id') ?? '')
        const decision = form.get('decision') === 'deny' ? 'deny' : 'approve'
        const locale = formLocale(request, form.get('ui_locales'))
        const uiLocales = optionalString(form.get('ui_locales'))

        if (!loginId) {
          return formErrorResponse(request, '/consent', translate(locale, 'missingConsentShort'), {})
        }

        try {
          const result = await identityJson<ConsentApiResponse>(
            '/oauth2/consent',
            {
              method: 'POST',
              csrfToken: String(form.get('csrf_token') ?? ''),
              body: {
                login_id: loginId,
                decision,
              },
            },
          )
          if (!result.continue_uri) {
            throw new Error(translate(locale, 'continuationMissing'))
          }
          return navigationResponse(request, result.continue_uri)
        } catch (error) {
          return formErrorResponse(request, '/consent', errorMessage(error, locale), {
            login_id: loginId,
            ui_locales: uiLocales,
          })
        }
      },
    },
  },
  component: ConsentPage,
})

function ConsentPage() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  const consent = data.consent
  const visibleError = search.error ?? data.error
  const t = (key: Parameters<typeof translate>[1], values?: Record<string, string | number>) =>
    translate(data.locale, key, values)

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      wide
      headerAlign="left"
      title={t('consentTitle')}
      description={
        consent
          ? t('consentDescription', { client: consent.client_name })
          : t('consentFallback')
      }
    >
      {visibleError ? (
        <Alert
          status="danger"
          className="auth-alert mb-5"
        >
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('consentLoadFailed')}</Alert.Title>
            <Alert.Description>{visibleError}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}

      {consent ? (
        <>
          <div className="mb-5 rounded-xl border border-border p-4">
            <div className="flex items-center gap-3">
              {consent.logo_uri ? (
                <img
                  src={consent.logo_uri}
                  alt=""
                  className="size-10 shrink-0 rounded-xl object-contain"
                  referrerPolicy="no-referrer"
                />
              ) : null}
              <div className="min-w-0">
                <p className="break-words text-base font-semibold">{consent.client_name}</p>
                {consent.client_uri ? (
                  <a
                    href={consent.client_uri}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-1 flex items-center gap-2 text-sm text-muted hover:underline"
                  >
                    <span className="truncate">{consent.client_uri}</span>
                    <ExternalLink className="size-4 shrink-0" aria-hidden="true" />
                  </a>
                ) : null}
              </div>
            </div>
          </div>

          <details open className="group rounded-xl border border-border p-4">
            <summary className="flex cursor-pointer list-none items-center gap-3 rounded-sm focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
              <span className="flex-1 text-base font-semibold">{t('permissions')}</span>
              <span className="text-xs text-muted">
                {t('permissionCount', { count: consent.scopes.length })}
              </span>
              <ChevronDown className="size-4 shrink-0 -rotate-90 transition-transform group-open:rotate-0" aria-hidden="true" />
            </summary>
            <ul className="mt-3 divide-y divide-border px-1">
              {consent.scopes.map((scope) => (
                <li key={scope.name} className="py-4">
                  <p className="break-all text-sm font-semibold">
                    {scope.name}
                    {scope.essential ? <span className="sr-only"> ({t('required')})</span> : null}
                  </p>
                  <p className="mt-1 text-xs leading-5 text-muted">
                    {scopeDescription(data.locale, scope.name, scope.description)}
                  </p>
                </li>
              ))}
            </ul>
          </details>

          <p className="mt-6 text-sm leading-6 text-muted">
            {t('revoke')}
          </p>

          <ProgressiveForm
            action="/consent"
            className="progressive-form mt-5 grid grid-cols-2 gap-3"
            enhancementErrorMessage={t('enhancedNavigationError')}
          >
            <input
              type="hidden"
              name="login_id"
              value={consent.login_id}
            />
            <input
              type="hidden"
              name="csrf_token"
              value={consent.csrf_token}
            />
            <input type="hidden" name="ui_locales" value={data.uiLocales} />
            <SubmitButton fullWidth className="h-11 text-base font-semibold" name="decision" value="deny" variant="secondary">
              {t('deny')}
            </SubmitButton>
            <SubmitButton fullWidth className="h-11 text-base font-semibold" name="decision" value="approve">
              {t('allow')}
            </SubmitButton>
          </ProgressiveForm>
        </>
      ) : null}
    </AuthShell>
  )
}
