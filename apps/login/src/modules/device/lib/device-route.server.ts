import { errorMessage, LocalizedError } from '#/lib/identity.server'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import { formErrorResponse, navigationResponse } from '#/lib/responses.server'
import { decisionOutcome } from '#/modules/device/components/device-outcome'
import {
  beginDeviceVerification,
  decideDeviceVerification,
  deviceInteractionPath,
} from '#/modules/device/lib/device-verification.server'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

export async function submitDevicePost(request: Request) {
  const form = await request.formData()
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))
  const code = String(form.get('user_code') ?? '').trim()
  const loginId = String(form.get('login_id') ?? '')

  // The entered code is resolved here so a code that matches no request
  // is reported on the entry form itself, instead of sending the browser
  // to a page that can only ask it to sign in.
  if (form.get('intent') === 'enter-code') {
    const values = { user_code: code, ui_locales: uiLocales }
    if (!code) {
      return formErrorResponse(
        request,
        '/device',
        translate(locale, 'missingDeviceCode'),
        { ui_locales: uiLocales },
        'user_code',
      )
    }

    const lookup = await beginDeviceVerification(code, locale, uiLocales)
    if (lookup.status === 'unknown') {
      return formErrorResponse(
        request,
        '/device',
        translate(locale, 'deviceCodeInvalid'),
        values,
        'user_code',
      )
    }
    if (lookup.status === 'failed') {
      return formErrorResponse(request, '/device', lookup.message, values)
    }

    return navigationResponse(request, lookup.loginUri)
  }

  const decision = form.get('decision') === 'deny' ? 'deny' : 'approve'
  if (!loginId) {
    return formErrorResponse(
      request,
      '/device',
      translate(locale, 'missingConsentShort'),
      { ui_locales: uiLocales },
    )
  }

  try {
    const result = await decideDeviceVerification(
      loginId,
      decision,
      String(form.get('csrf_token') ?? ''),
    )
    const outcome = decisionOutcome(result.status)
    if (!outcome) {
      throw new LocalizedError(translate(locale, 'deviceDecisionUnknown'))
    }

    return navigationResponse(
      request,
      `/device/${outcome}${uiLocales ? `?ui_locales=${encodeURIComponent(uiLocales)}` : ''}`,
    )
  } catch (error) {
    return formErrorResponse(
      request,
      '/device',
      errorMessage(error, locale),
      { login_id: loginId, ui_locales: uiLocales },
      undefined,
      deviceInteractionPath(loginId, uiLocales),
    )
  }
}
