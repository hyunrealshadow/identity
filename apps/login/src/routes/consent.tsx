import { Alert, Chip } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Check, ExternalLink, ShieldCheck } from 'lucide-react'

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
        locale: requestLocale(consent.ui_locales),
        uiLocales: consent.ui_locales?.join(' ') ?? '',
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
          <div className="mb-5 rounded-xl border border-border bg-surface-secondary p-4">
            <div className="flex items-start gap-3">
              <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-accent text-accent-foreground shadow-sm shadow-black/10">
                <ShieldCheck className="size-5" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <p className="font-semibold">{consent.client_name}</p>
                {consent.client_uri ? (
                  <a
                    href={consent.client_uri}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-1 inline-flex items-center gap-1 truncate text-xs font-medium text-accent hover:underline"
                  >
                    {consent.client_uri}
                    <ExternalLink className="size-3" aria-hidden="true" />
                  </a>
                ) : null}
              </div>
            </div>
          </div>

          <section aria-labelledby="permissions-title">
            <div className="mb-3 flex items-center justify-between gap-3">
              <h2 id="permissions-title" className="text-sm font-semibold">
                {t('permissions')}
              </h2>
              <Chip size="sm" variant="soft">
                {t('permissionCount', { count: consent.scopes.length })}
              </Chip>
            </div>
            <ul className="auth-stagger-fast space-y-2">
              {consent.scopes.map((scope) => (
                <li
                  key={scope.name}
                  className="flex gap-3 rounded-xl border border-border px-3 py-3 transition-colors duration-200 hover:border-black/15 hover:bg-black/[0.02]"
                >
                  <Check
                    className="mt-0.5 size-4 shrink-0 text-accent"
                    aria-hidden="true"
                  />
                  <span className="min-w-0">
                    <span className="flex items-center gap-2 text-sm font-semibold">
                      {scope.name}
                      {scope.essential ? (
                        <Chip size="sm" variant="soft">
                          {t('required')}
                        </Chip>
                      ) : null}
                    </span>
                    <span className="mt-0.5 block text-xs leading-5 text-muted">
                      {scopeDescription(data.locale, scope.name, scope.description)}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          </section>

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
            <SubmitButton name="decision" value="deny" variant="secondary">
              {t('deny')}
            </SubmitButton>
            <SubmitButton name="decision" value="approve">
              {t('allow')}
            </SubmitButton>
          </ProgressiveForm>

          <p className="mt-5 text-center text-xs leading-5 text-muted">
            {t('revoke')}
          </p>
        </>
      ) : null}
    </AuthShell>
  )
}
