import { preflightOperation, type PreflightContext, type PreflightResult } from '@identity/graphql-access'

/** Actual operations shared by account actions and their browser preflight. */
export const accountOperations = {
  'prepare-manage-passkeys': { authorization: 'elevated', document: `mutation PrepareMfaManagement { prepareMfaManagement }` },
  'revoke-session': { authorization: 'default', document: `mutation RevokeSession($id: ID!) { revokeSession(id: $id) { session { id status } } }` },
  'revoke-others': { authorization: 'default', document: `mutation RevokeOthers { revokeOtherSessions { revokedCount } }` },
  'update-mfa-preference': { authorization: 'default', document: `mutation UpdateMfaPreference($method: PreferredMfaMethod!) { updatePreferredMfaMethod(method: $method) }` },
  'update-profile': { authorization: 'default', document: `mutation UpdateProfile($input: UpdateProfileInput!) { updateProfile(input: $input) { user { id username givenName familyName nickname locale theme zoneInfo } } }` },
  'update-username': { authorization: 'elevated', document: `mutation UpdateUsername($input: UpdateUsernameInput!) { updateUsername(input: $input) { user { id username } } }` },
  'update-email': { authorization: 'elevated', document: `mutation UpdateEmail($input: UpdateEmailInput!) { updateEmail(input: $input) { user { id email emailVerified } } }` },
  'change-password': { authorization: 'elevated', document: `mutation ChangePassword($input: ChangePasswordInput!) { changePassword(input: $input) { changed } }` },
  'begin-totp': { authorization: 'elevated', document: `mutation BeginTotpEnrollment { beginTotpEnrollment { secret otpAuthUri enrollmentToken recoveryCodes } }` },
  'use-legacy-totp': { authorization: 'elevated', document: `mutation ChangeTotpEnrollmentAlgorithm($input: ChangeTotpEnrollmentAlgorithmInput!) {
          changeTotpEnrollmentAlgorithm(input: $input) {
            secret otpAuthUri enrollmentToken recoveryCodes
          }
        }` },
  'confirm-totp': { authorization: 'elevated', document: `mutation ConfirmTotpEnrollment($input: ConfirmTotpEnrollmentInput!) { confirmTotpEnrollment(input: $input) { recoveryCodes } }` },
  'disable-totp': { authorization: 'elevated', document: `mutation DisableTotp { disableTotp { changed } }` },
  'regenerate-recovery-codes': { authorization: 'elevated', document: `mutation RegenerateRecoveryCodes { regenerateRecoveryCodes { recoveryCodes } }` },
  'passkey-prepare': { authorization: 'elevated', document: `mutation PrepareMfaRecoveryCodes { prepareMfaRecoveryCodes { recoveryCodes enrollmentToken } }` },
  'passkey-begin': { authorization: 'elevated', document: `mutation BeginPasskeyRegistration($recoveryEnrollmentToken: String) { beginPasskeyRegistration(recoveryEnrollmentToken: $recoveryEnrollmentToken) }` },
  'passkey-finish': { authorization: 'elevated', document: `mutation RegisterPasskey($id: String!, $name: String!, $credential: JSON!) { finishPasskeyRegistration(challengeId: $id, name: $name, credential: $credential) }` },
  'passkey-delete': { authorization: 'elevated', document: `mutation DeletePasskey($id: String!) { deletePasskey(id: $id) }` },
} as const

export function accountOperation(action: string) {
  const resolved = action === 'prepare-change-password' ? 'change-password'
    : action === 'prepare-disable-totp' ? 'disable-totp' : action
  return Object.hasOwn(accountOperations, resolved)
    ? accountOperations[resolved as keyof typeof accountOperations] : undefined
}

/** Safe advisory claims only; access and refresh tokens remain server-side. */
export interface AccountAccessContext {
  default?: PreflightContext
  elevated?: PreflightContext
}

export function preflightAccountAction(action: string, access?: AccountAccessContext): PreflightResult {
  const operation = accountOperation(action)
  const context = operation && access?.[operation.authorization]
  if (!operation || !context) return { status: 'unknown', requiredScopes: [] }
  return preflightOperation(operation.document, undefined, context)
}
