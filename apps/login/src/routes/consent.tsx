import { Alert } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { ExternalLink } from 'lucide-react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { ConsentPermissions } from '#/components/consent-permissions'
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
import { translate } from '#/lib/i18n'
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
          <div className="mb-6 rounded-xl border border-border bg-surface-secondary p-3">
            <div className="flex items-center gap-3">
              <AccountAvatar name={consent.client_name} picture={consent.logo_uri} />
              <div className="min-w-0">
                <p className="break-words text-sm font-semibold">{consent.client_name}</p>
                {consent.client_uri ? (
                  <a
                    href={consent.client_uri}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-1 flex items-center gap-1 text-xs text-muted hover:underline"
                  >
                    <span className="truncate">{consent.client_uri}</span>
                    <ExternalLink className="size-3 shrink-0" aria-hidden="true" />
                  </a>
                ) : null}
              </div>
            </div>
          </div>

          <ConsentPermissions scopes={consent.scopes} locale={data.locale} />

          <p className="mt-4 text-xs leading-5 text-muted">
            {t('revoke')}
          </p>

          <ProgressiveForm
            action="/consent"
            className="progressive-form mt-6 grid grid-cols-2 gap-3"
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
            <SubmitButton fullWidth name="decision" value="deny" variant="secondary">
              {t('deny')}
            </SubmitButton>
            <SubmitButton fullWidth name="decision" value="approve">
              {t('allow')}
            </SubmitButton>
          </ProgressiveForm>
        </>
      ) : null}
    </AuthShell>
  )
}
