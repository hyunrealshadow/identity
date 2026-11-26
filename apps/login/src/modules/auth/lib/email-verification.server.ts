import { identityInternalJson, IdentityApiError } from '#/lib/identity.server'
import type { Locale } from '#/lib/i18n'

/** Error code of a link that is unknown, expired, used, or voided. */
export const EMAIL_VERIFICATION_INVALID = 15011

export interface EmailVerificationResult {
  status: 'verified'
  email: string
  /** Whether the account's address was replaced by the verified one. */
  changed: boolean
}

/**
 * Consume an emailed verification link. Holding the link proves control of
 * the mailbox, so no account session is needed; the token only ever travels
 * from the page form to Identity's private listener.
 */
export async function confirmEmailVerification(token: string, locale: Locale) {
  return identityInternalJson<EmailVerificationResult>('/internal/email-verification', {
    method: 'POST',
    body: { token },
    locale,
  })
}

/** Whether retrying the same link cannot succeed. */
export function isFinalVerificationError(error: unknown) {
  return error instanceof IdentityApiError
    && (error.code === EMAIL_VERIFICATION_INVALID || error.status === 409)
}
