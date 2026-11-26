import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { translate, type Locale } from '#/lib/i18n'
import type { ConsentPageData } from '#/lib/identity-types'
import { ConsentAccount } from '#/modules/consent/components/consent-account'
import { ConsentNotice } from '#/modules/consent/components/consent-notice'
import { ConsentPermissions } from '#/modules/consent/components/consent-permissions'

export interface ConsentSearch {
  login_id?: string
  error?: string
  ui_locales?: string
}

export interface ConsentRouteData {
  consent?: ConsentPageData
  locale: Locale
  uiLocales: string
  error?: string
}

export function ConsentPageView({
  data,
  search,
}: {
  data: ConsentRouteData
  search: ConsentSearch
}) {
  const consent = data.consent
  const visibleError = search.error ?? data.error
  const t = (
    key: Parameters<typeof translate>[1],
    values?: Record<string, string | number>,
  ) => translate(data.locale, key, values)

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
        <ErrorAlert
          className="mb-5"
          title={t('consentLoadFailed')}
          message={visibleError}
        />
      ) : null}

      {consent ? (
        <>
          <ConsentAccount account={consent.account} locale={data.locale} />

          <ConsentPermissions scopes={consent.scopes} locale={data.locale} />

          <ProgressiveForm
            action="/consent"
            className="progressive-form mt-6 grid grid-cols-2 gap-3"
            enhancementErrorMessage={t('enhancedNavigationError')}
          >
            <input type="hidden" name="login_id" value={consent.login_id} />
            <input
              type="hidden"
              name="csrf_token"
              value={consent.csrf_token}
            />
            <input type="hidden" name="ui_locales" value={data.uiLocales} />
            <SubmitButton
              fullWidth
              name="decision"
              value="deny"
              variant="outline"
            >
              {t('deny')}
            </SubmitButton>
            <SubmitButton fullWidth name="decision" value="approve">
              {t('allow')}
            </SubmitButton>
          </ProgressiveForm>

          <ConsentNotice message={t('revoke')} />
        </>
      ) : null}
    </AuthShell>
  )
}
