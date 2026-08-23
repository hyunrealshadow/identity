import { getRequestHeader } from '@tanstack/react-start/server'

import { graphqlFieldErrors } from './account-errors'
import { localePreferenceValue } from './account-locale'
import {
  accountReauthenticationReturnTo,
  requiresAccountReauthentication,
} from './account-reauth'
import { loadClientCredentials } from './client-credentials.server'
import { GraphqlRequestError, identityGraphql } from './graphql.server'
import { translate, type Locale } from './i18n'
import { requestLocale } from './i18n.server'
import {
  clearElevatedAuthorization,
  clearMfaUiState,
  finishLogout,
  mfaUiState,
  startReauthorization,
  storeMfaEnrollment,
} from './oauth.server'
import { storeAccountFlash } from './oauth-session.server'

export interface AccountActionInput {
  action: string
  values: Record<string, string>
}

export interface AccountActionResult {
  redirect?: string
  ok?: boolean
}

export async function executeAccountAction(
  input: AccountActionInput,
): Promise<AccountActionResult> {
  const locale = requestLocale()
  const credentials = await loadClientCredentials()
  const origin = getRequestHeader('origin')
  if (origin && origin !== new URL(credentials.application_url).origin) {
    await storeAccountFlash({
      error: translate(locale, 'accountInvalidRequestOrigin'),
    })
    return { ok: false }
  }

  const { action, values } = input
  try {
    if (action === 'logout') {
      const response = await finishLogout(credentials.application_url)
      return { redirect: response.headers.get('location') ?? '/' }
    }
    if (action === 'cancel-totp') {
      await clearMfaUiState()
      return { ok: true }
    }
    if (action === 'revoke-session') {
      await requireGraphql(
        `mutation RevokeSession($id: ID!) { revokeSession(id: $id) { session { id status } } }`,
        { id: values.session_id ?? '' },
      )
    } else if (action === 'revoke-others') {
      await requireGraphql(
        `mutation RevokeOthers { revokeOtherSessions { revokedCount } }`,
      )
    } else if (action === 'update-profile') {
      await requireGraphql(
        `mutation UpdateProfile($input: UpdateProfileInput!) { updateProfile(input: $input) { user { id username givenName familyName nickname } } }`,
        {
          input: {
            givenName: nullableValue(values.given_name),
            familyName: nullableValue(values.family_name),
            nickname: nullableValue(values.nickname),
            website: nullableValue(values.website),
            birthdate: nullableValue(values.birthdate),
            locale: localePreferenceValue(values.locale),
          },
        },
      )
    } else if (action === 'update-username') {
      await requireGraphql(
        `mutation UpdateUsername($input: UpdateUsernameInput!) { updateUsername(input: $input) { user { id username } } }`,
        {
          input: {
            username: values.username ?? '',
          },
        },
        { authorization: 'elevated' },
      )
      await clearElevatedAuthorization()
    } else if (action === 'update-email') {
      await requireGraphql(
        `mutation UpdateEmail($input: UpdateEmailInput!) { updateEmail(input: $input) { user { id email emailVerified } } }`,
        {
          input: {
            email: values.email ?? '',
          },
        },
        { authorization: 'elevated' },
      )
      await clearElevatedAuthorization()
    } else if (action === 'change-password') {
      const newPassword = values.new_password ?? ''
      if (newPassword !== (values.confirm_password ?? '')) {
        throw new AccountActionError(
          translate(locale, 'accountPasswordMismatch'),
          { confirm_password: translate(locale, 'accountPasswordMismatch') },
        )
      }
      await requireGraphql(
        `mutation ChangePassword($input: ChangePasswordInput!) { changePassword(input: $input) { changed } }`,
        {
          input: {
            currentPassword: values.current_password ?? '',
            newPassword,
          },
        },
        { authorization: 'elevated' },
      )
      await clearElevatedAuthorization()
    } else if (action === 'begin-totp') {
      const result = await requireGraphql<{
        beginTotpEnrollment: {
          secret: string
          otpAuthUri: string
          enrollmentToken: string
          recoveryCodes: Array<string>
        }
      }>(
        `mutation BeginTotpEnrollment { beginTotpEnrollment { secret otpAuthUri enrollmentToken recoveryCodes } }`,
        undefined,
        { authorization: 'elevated' },
      )
      await storeMfaEnrollment({
        secret: result.beginTotpEnrollment.secret,
        otp_auth_uri: result.beginTotpEnrollment.otpAuthUri,
        enrollment_token: result.beginTotpEnrollment.enrollmentToken,
        recovery_codes: result.beginTotpEnrollment.recoveryCodes,
      })
    } else if (action === 'use-legacy-totp') {
      const mfa = await mfaUiState()
      if (!mfa.enrollment) {
        throw new AccountActionError(
          translate(locale, 'accountMfaSetupExpired'),
          { code: translate(locale, 'accountMfaSetupExpired') },
        )
      }
      const result = await requireGraphql<{
        changeTotpEnrollmentAlgorithm: {
          secret: string
          otpAuthUri: string
          enrollmentToken: string
          recoveryCodes: Array<string>
        }
      }>(
        `mutation ChangeTotpEnrollmentAlgorithm($input: ChangeTotpEnrollmentAlgorithmInput!) {
          changeTotpEnrollmentAlgorithm(input: $input) {
            secret otpAuthUri enrollmentToken recoveryCodes
          }
        }`,
        {
          input: {
            enrollmentToken: mfa.enrollment.enrollment_token,
            algorithm: 'SHA1',
          },
        },
        { authorization: 'elevated' },
      )
      await storeMfaEnrollment({
        secret: result.changeTotpEnrollmentAlgorithm.secret,
        otp_auth_uri: result.changeTotpEnrollmentAlgorithm.otpAuthUri,
        enrollment_token: result.changeTotpEnrollmentAlgorithm.enrollmentToken,
        recovery_codes: result.changeTotpEnrollmentAlgorithm.recoveryCodes,
      })
    } else if (action === 'confirm-totp') {
      const mfa = await mfaUiState()
      if (!mfa.enrollment) {
        throw new AccountActionError(
          translate(locale, 'accountMfaSetupExpired'),
          { code: translate(locale, 'accountMfaSetupExpired') },
        )
      }
      await requireGraphql(
        `mutation ConfirmTotpEnrollment($input: ConfirmTotpEnrollmentInput!) { confirmTotpEnrollment(input: $input) { recoveryCodes } }`,
        {
          input: {
            enrollmentToken: mfa.enrollment.enrollment_token,
            code: values.code ?? '',
          },
        },
        { authorization: 'elevated' },
      )
      await clearMfaUiState()
      await clearElevatedAuthorization()
    } else if (action === 'disable-totp') {
      await requireGraphql(
        `mutation DisableTotp { disableTotp { changed } }`,
        undefined,
        { authorization: 'elevated' },
      )
      await clearMfaUiState()
      await clearElevatedAuthorization()
    } else {
      throw new AccountActionError(translate(locale, 'accountUnknownAction'))
    }

    if (action !== 'use-legacy-totp') {
      await storeAccountFlash({ message: 'saved' })
    }
    return { ok: true }
  } catch (error) {
    if (
      (action === 'change-password' ||
        isIdentifierAction(action) ||
        isMfaAction(action)) &&
      error instanceof GraphqlRequestError &&
      requiresAccountReauthentication(error)
    ) {
      const challenge = error.challenge
      const response = await startReauthorization(
        accountReauthenticationReturnTo(action),
        reauthPurpose(action),
        {
          acrValues: challenge?.acrValues,
          maxAge: challenge?.maxAge,
        },
      )
      return {
        redirect: response.headers.get('location') ?? '/',
      }
    }
    await storeAccountFlash(accountFlashFromError(error, locale))
    return { ok: false }
  }
}

async function requireGraphql<T>(
  query: string,
  variables?: Record<string, unknown>,
  options?: { authorization?: 'default' | 'elevated' },
) {
  const data = await identityGraphql<T>(query, variables, options)
  if (!data) {
    throw new AccountActionError(
      translate(requestLocale(), 'accountAuthenticationRequired'),
    )
  }
  return data
}

class AccountActionError extends Error {
  readonly fields: Record<string, string>

  constructor(message: string, fields: Record<string, string> = {}) {
    super(message)
    this.name = 'AccountActionError'
    this.fields = fields
  }
}

function accountFlashFromError(
  error: unknown,
  locale: Locale,
): { error: string; fields?: Record<string, string> } {
  if (error instanceof AccountActionError) {
    return { error: error.message, fields: error.fields }
  }
  if (error instanceof GraphqlRequestError) {
    const fields = graphqlFieldErrors(error.errors)
    return {
      error: error.message,
      fields: Object.keys(fields).length ? fields : undefined,
    }
  }
  return {
    error:
      error instanceof Error
        ? error.message
        : translate(locale, 'temporaryError'),
  }
}

function isMfaAction(action: string) {
  return [
    'begin-totp',
    'use-legacy-totp',
    'confirm-totp',
    'disable-totp',
  ].includes(action)
}

function isIdentifierAction(action: string) {
  return action === 'update-username' || action === 'update-email'
}

function reauthPurpose(action: string) {
  if (action === 'disable-totp') {
    return 'mfa'
  }
  if (isIdentifierAction(action)) return 'account'
  return isMfaAction(action) ? 'account' : 'password'
}

function nullableValue(value?: string) {
  const normalized = value?.trim() ?? ''
  return normalized || null
}
