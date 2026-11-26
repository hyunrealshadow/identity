import { errorMessage } from '#/lib/identity.server'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import { formErrorResponse, navigationResponse } from '#/lib/responses.server'
import {
  confirmEmailVerification,
  isFinalVerificationError,
} from '#/modules/auth/lib/email-verification.server'

export const VERIFY_EMAIL_PATH = '/verify-email'

export async function submitVerifyEmailPost(request: Request) {
  const form = await request.formData()
  const locale = formLocale(request, null)
  const token = String(form.get('token') ?? '').trim()
  if (!token) {
    return formErrorResponse(
      request,
      VERIFY_EMAIL_PATH,
      translate(locale, 'verifyEmailMissingLink'),
      {},
    )
  }
  try {
    const result = await confirmEmailVerification(token, locale)
    return navigationResponse(
      request,
      `${VERIFY_EMAIL_PATH}/${result.changed ? 'changed' : 'verified'}`,
    )
  } catch (error) {
    // A link that can never work is not offered again; a transient
    // failure keeps it so the user can retry.
    const destination = isFinalVerificationError(error)
      ? VERIFY_EMAIL_PATH
      : `${VERIFY_EMAIL_PATH}?token=${encodeURIComponent(token)}`
    return formErrorResponse(
      request,
      VERIFY_EMAIL_PATH,
      errorMessage(error, locale),
      {},
      undefined,
      destination,
    )
  }
}
