import type { GraphqlRequestError } from './graphql.server'

export const MFA_SETUP_CONTINUATION = '/account/mfa/setup'
export const MFA_VERIFICATION_CONTINUATION = '/account/security?setup=mfa&step=verify'
export const MFA_DISABLE_CONTINUATION = '/account/security?confirm=disable-mfa'
export const RECOVERY_CODES_CONTINUATION = '/account/security?confirm=recovery-codes'
export const PASSWORD_CHANGE_CONTINUATION = '/account/security?confirm=change-password'

export function requiresAccountReauthentication(error: GraphqlRequestError) {
  return error.errors.some(
    ({ extensions }) =>
      extensions?.code === 'FRESH_AUTHENTICATION_REQUIRED' ||
      extensions?.code === 'insufficient_user_authentication' ||
      extensions?.requiredScope === 'password.change' ||
      extensions?.requiredScope === 'account.update',
  )
}

export function accountReauthenticationReturnTo(action: string) {
  if (action === 'begin-totp') return MFA_SETUP_CONTINUATION
  if (action === 'confirm-totp') return MFA_VERIFICATION_CONTINUATION
  if (action === 'prepare-disable-totp') return MFA_DISABLE_CONTINUATION
  if (action === 'regenerate-recovery-codes') return RECOVERY_CODES_CONTINUATION
  if (action === 'prepare-change-password') return PASSWORD_CHANGE_CONTINUATION
  return accountActionDestination(action)
}

export function accountActionDestination(action: string) {
  if (action.startsWith('revoke')) return '/account/sessions'
  if (action === 'update-profile') {
    return '/account/profile'
  }
  if (action === 'update-username' || action === 'update-email') {
    return '/account/identifiers'
  }
  return '/account/security'
}
