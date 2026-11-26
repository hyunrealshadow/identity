import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SigningAlgorithmField } from '#/components/signing-algorithm-field'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { translate, type Locale } from '#/lib/i18n'
import type { SigningAlgorithmOption } from '#/lib/identity-types'

/** Offered first: compact keys that every client library verifies. */
const DEFAULT_SIGNING_OPTION = 'ES256:ECDSA_P256'

export interface InstallSearch {
  error?: string
  username?: string
  email?: string
  domain?: string
  application_url?: string
  console_url?: string
}

export interface InstallPageData {
  signingAlgorithms: Array<SigningAlgorithmOption>
  defaults: {
    domain: string
    application_url: string
    console_url: string
  }
  locale: Locale
  error?: string
  fieldErrors: Record<string, string>
  formValues: Record<string, string | undefined>
}

export function InstallPageView({
  data,
  search,
}: {
  data: InstallPageData
  search: InstallSearch
}) {
  const { locale, error, fieldErrors, formValues, defaults, signingAlgorithms } =
    data
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      title={t('installTitle')}
      description={t('installDescription')}
    >
      {error ? (
        <ErrorAlert
          className="mb-5"
          title={t('installFailed')}
          message={error}
        />
      ) : null}

      <ProgressiveForm
        action="/install"
        className="progressive-form space-y-5"
        enhancementErrorMessage={t('installNavigationError')}
        validationErrors={fieldErrors}
      >
        <TextField
          required
          name="domain"
          label={t('installIdentityUrl')}
          defaultValue={formValues.domain ?? search.domain ?? defaults.domain}
          autoFocus
          inputMode="url"
          placeholder="https://id.example.com"
        />
        <TextField
          required
          name="application_url"
          label={t('installApplicationUrl')}
          defaultValue={
            formValues.application_url ??
            search.application_url ??
            defaults.application_url
          }
          inputMode="url"
          placeholder="https://login.example.com"
        />
        <TextField
          required
          name="console_url"
          label={t('installConsoleUrl')}
          description={t('installConsoleOriginDescription')}
          defaultValue={
            formValues.console_url ?? search.console_url ?? defaults.console_url
          }
          inputMode="url"
          placeholder="https://login.example.com"
        />
        <TextField
          required
          name="username"
          label={t('installAdminUsername')}
          defaultValue={formValues.username ?? search.username}
          autoComplete="username"
          placeholder="admin"
        />
        <TextField
          required
          name="email"
          label={t('installAdminEmail')}
          defaultValue={formValues.email ?? search.email}
          autoComplete="email"
          inputMode="email"
          placeholder="admin@example.com"
        />
        <TextField
          required
          name="password"
          type="password"
          label={t('installPassword')}
          autoComplete="new-password"
        />
        <TextField
          required
          name="confirm_password"
          type="password"
          label={t('installConfirmPassword')}
          autoComplete="new-password"
        />

        <SigningAlgorithmField
          label={t('installSigningAlgorithm')}
          description={t('installSigningAlgorithmDescription')}
          options={signingAlgorithms}
          defaultValue={formValues.signing_option || DEFAULT_SIGNING_OPTION}
        />

        <SubmitButton fullWidth>{t('installSubmit')}</SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}
