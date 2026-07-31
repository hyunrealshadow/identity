import { Alert, FieldError, Input, Label, TextField } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import {
  errorMessage,
  IdentityApiError,
  identityJson,
} from '#/lib/identity.server'
import type { InstallResponse } from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'
import {
  consumeFormFlash,
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import { persistClientCredentials } from '#/lib/client-credentials.server'

interface InstallSearch {
  error?: string
  username?: string
  email?: string
  domain?: string
  application_url?: string
}

const visibleInstallFields = new Set([
  'domain',
  'application_url',
  'username',
  'email',
  'password',
  'confirm_password',
])

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadInstallPage = createServerFn({ method: 'GET' }).handler(async () => {
  const flash = consumeFormFlash('/install')
  const hasUnmappedFieldError = Object.keys(flash?.fields ?? {}).some(
    (field) => !visibleInstallFields.has(field),
  )
  return {
    locale: requestLocale(),
    error:
      flash?.field || (flash?.fields && !hasUnmappedFieldError)
        ? undefined
        : flash?.message,
    fieldErrors: {
      ...(flash?.fields ?? {}),
      ...(flash?.field ? { [flash.field]: flash.message } : {}),
    },
    formValues: flash?.values ?? {},
  }
})

export const Route = createFileRoute('/install')({
  validateSearch: (search): InstallSearch => ({
    error: optionalString(search.error),
    username: optionalString(search.username),
    email: optionalString(search.email),
    domain: optionalString(search.domain),
    application_url: optionalString(search.application_url),
  }),
  loader: () => loadInstallPage(),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const username = String(form.get('username') ?? '').trim()
        const email = String(form.get('email') ?? '').trim()
        const domain = String(form.get('domain') ?? '').trim()
        const applicationUrl = String(
          form.get('application_url') ?? '',
        ).trim()
        const password = String(form.get('password') ?? '')
        const confirmPassword = String(form.get('confirm_password') ?? '')
        const values = {
          username,
          email,
          domain,
          application_url: applicationUrl,
        }
        const locale = formLocale(request, null)

        if (password !== confirmPassword) {
          return formErrorResponse(
            request,
            '/install',
            translate(locale, 'installPasswordMismatch'),
            values,
            'confirm_password',
          )
        }

        try {
          const result = await identityJson<InstallResponse>('/install', {
            method: 'POST',
            body: {
              username,
              email,
              password,
              domain,
              application_url: applicationUrl,
              key_algorithm: String(
                form.get('key_algorithm') ?? 'ecdsa-p256',
              ),
            },
          })
          await persistClientCredentials(
            result.client_id,
            result.client_secret,
            applicationUrl,
          )
          return navigationResponse(request, '/')
        } catch (error) {
          if (error instanceof IdentityApiError && error.fields.length > 0) {
            return formValidationErrorResponse(
              request,
              '/install',
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
          return formErrorResponse(
            request,
            '/install',
            errorMessage(error),
            values,
          )
        }
      },
    },
  },
  component: InstallPage,
})

function InstallPage() {
  const search = Route.useSearch()
  const { locale, error, fieldErrors, formValues } = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  const fieldError = (name: string) => fieldErrors[name]

  return (
    <AuthShell
      lang={locale}
      title={t('installTitle')}
      description={t('installDescription')}
    >
      {error ? (
        <Alert
          status="danger"
          className="auth-alert mb-5"
        >
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('installFailed')}</Alert.Title>
            <Alert.Description>{error}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}

      <ProgressiveForm
        action="/install"
        className="progressive-form space-y-5"
        enhancementErrorMessage={t('installNavigationError')}
      >
        <TextField
          isRequired
          fullWidth
          name="domain"
          isInvalid={Boolean(fieldError('domain'))}
        >
          <Label>{t('installIdentityUrl')}</Label>
          <Input
            autoFocus
            defaultValue={
              formValues.domain ?? search.domain ?? 'https://localhost:5150'
            }
            inputMode="url"
            placeholder="https://id.example.com"
          />
          <FieldError>{fieldError('domain')}</FieldError>
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="application_url"
          isInvalid={Boolean(fieldError('application_url'))}
        >
          <Label>{t('installApplicationUrl')}</Label>
          <Input
            defaultValue={
              formValues.application_url ??
              search.application_url ??
              'https://localhost:3000'
            }
            inputMode="url"
            placeholder="https://account.example.com"
          />
          <FieldError>{fieldError('application_url')}</FieldError>
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="username"
          isInvalid={Boolean(fieldError('username'))}
        >
          <Label>{t('installAdminUsername')}</Label>
          <Input
            autoComplete="username"
            defaultValue={formValues.username ?? search.username}
            placeholder="admin"
          />
          <FieldError>{fieldError('username')}</FieldError>
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="email"
          isInvalid={Boolean(fieldError('email'))}
        >
          <Label>{t('installAdminEmail')}</Label>
          <Input
            autoComplete="email"
            defaultValue={formValues.email ?? search.email}
            inputMode="email"
            placeholder="admin@example.com"
          />
          <FieldError>{fieldError('email')}</FieldError>
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="password"
          isInvalid={Boolean(fieldError('password'))}
        >
          <Label>{t('installPassword')}</Label>
          <Input autoComplete="new-password" type="password" />
          <FieldError>{fieldError('password')}</FieldError>
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="confirm_password"
          isInvalid={Boolean(fieldError('confirm_password'))}
        >
          <Label>{t('installConfirmPassword')}</Label>
          <Input autoComplete="new-password" type="password" />
          <FieldError>
            {fieldError('confirm_password')}
          </FieldError>
        </TextField>

        <input type="hidden" name="key_algorithm" value="ecdsa-p256" />

        <SubmitButton fullWidth>{t('installSubmit')}</SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}
