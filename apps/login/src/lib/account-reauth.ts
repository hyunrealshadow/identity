import type { GraphqlRequestError } from './graphql.server'

export const MFA_SETUP_CONTINUATION = '/account/mfa/setup'

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
  return action === 'begin-totp'
    ? MFA_SETUP_CONTINUATION
    : accountActionDestination(action)
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
