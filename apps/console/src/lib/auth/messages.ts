import type { AuthErrorCode } from '#/lib/auth/transaction'
import type { MessageKey } from '#/lib/i18n'

const authMessages: Record<AuthErrorCode, MessageKey> = {
  missing_transaction: 'authMissingTransaction',
  expired_transaction: 'authExpiredTransaction',
  invalid_transaction: 'authInvalidTransaction',
  state_mismatch: 'authStateMismatch',
  nonce_mismatch: 'authNonceMismatch',
  issuer_mismatch: 'authIssuerMismatch',
  callback_mismatch: 'authCallbackMismatch',
  discovery_failed: 'authDiscoveryFailed',
  exchange_failed: 'authExchangeFailed',
  claims_invalid: 'authClaimsInvalid',
  token_response_invalid: 'authTokenResponseInvalid',
  missing_end_session: 'signOutSsoUnavailable',
  reauthentication_loop: 'authReauthenticationLoopDescription',
}

export function authErrorKey(code: AuthErrorCode | undefined): MessageKey {
  return code ? authMessages[code] : 'authFailedDescription'
}
