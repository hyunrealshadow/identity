import {
  errorMessage,
  IdentityApiError,
  identityInternalJson,
} from '#/lib/identity.server'
import type { InstallResponse } from '#/lib/identity-types'
import { markInstallationComplete } from '#/lib/installation-status.server'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import {
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'

export async function submitInstallPost(request: Request) {
  const form = await request.formData()
  const username = String(form.get('username') ?? '').trim()
  const email = String(form.get('email') ?? '').trim()
  const domain = String(form.get('domain') ?? '').trim()
  const applicationUrl = String(form.get('application_url') ?? '').trim()
  const consoleUrl = String(form.get('console_url') ?? '').trim()
  const password = String(form.get('password') ?? '')
  const confirmPassword = String(form.get('confirm_password') ?? '')
  const values = {
    username,
    email,
    domain,
    application_url: applicationUrl,
    console_url: consoleUrl,
    signing_option: `${String(form.get('signing_algorithm') ?? '')}:${String(form.get('key_algorithm') ?? '')}`,
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
    await identityInternalJson<InstallResponse>('/internal/installation', {
      method: 'POST',
      locale,
      body: {
        username,
        email,
        password,
        domain,
        application_url: applicationUrl,
        console_url: consoleUrl,
        // Enum values from the chosen option; Identity rejects others.
        signing_algorithm: String(form.get('signing_algorithm') ?? ''),
        key_algorithm: String(form.get('key_algorithm') ?? ''),
      },
    })
    markInstallationComplete()
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
      errorMessage(error, locale),
      values,
    )
  }
}
