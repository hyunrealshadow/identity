import {
  errorMessage,
  identityJson,
  LocalizedError,
} from '#/lib/identity.server'
import type { ConsentApiResponse } from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import { formErrorResponse, navigationResponse } from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

export async function submitConsentPost(request: Request) {
  const form = await request.formData()
  const loginId = String(form.get('login_id') ?? '')
  const decision = form.get('decision') === 'deny' ? 'deny' : 'approve'
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))

  if (!loginId) {
    return formErrorResponse(
      request,
      '/consent',
      translate(locale, 'missingConsentShort'),
      {},
    )
  }

  try {
    const result = await identityJson<ConsentApiResponse>('/oauth2/consent', {
      method: 'POST',
      csrfToken: String(form.get('csrf_token') ?? ''),
      body: {
        login_id: loginId,
        decision,
      },
    })
    if (!result.continue_uri) {
      throw new LocalizedError(translate(locale, 'continuationMissing'))
    }
    return navigationResponse(
      request,
      withUiLocales(result.continue_uri, uiLocales),
    )
  } catch (error) {
    return formErrorResponse(request, '/consent', errorMessage(error, locale), {
      login_id: loginId,
      ui_locales: uiLocales,
    })
  }
}
