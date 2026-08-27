import { getRequestHeader } from '@tanstack/react-start/server'

import { graphqlFieldErrors } from './account-errors'
import { localePreferenceValue } from './account-locale'
import { themePreferenceValue } from './appearance'
import {
  accountReauthenticationReturnTo,
  requiresAccountReauthentication,
} from './account-reauth'
import { GraphqlRequestError, identityGraphql } from './graphql.server'
import { translate, type Locale } from './i18n'
import { requestLocale } from './i18n.server'
import {
  clearElevatedAuthorization,
  clearMfaUiState,
  finishLogout,
  hasFreshAuthentication,
  mfaUiState,
  startReauthorization,
  storeMfaEnrollment,
  storeRegeneratedRecoveryCodes,
} from './oauth.server'
import { storeAccountFlash } from './oauth-session.server'
import { loadApplicationUrl } from './runtime-config.server'

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
  const applicationUrl = loadApplicationUrl()
  const origin = getRequestHeader('origin')
  if (origin && origin !== new URL(applicationUrl).origin) {
    await storeAccountFlash({
      error: translate(locale, 'accountInvalidRequestOrigin'),
    })
    return { ok: false }
  }

  const { action, values } = input
  try {
    if (action === 'logout') {
      const response = await finishLogout(applicationUrl)
      return { redirect: response.headers.get('location') ?? '/' }
    }
    if (action === 'cancel-totp') {
      await clearMfaUiState()
      return { ok: true }
    }
    if (action === 'prepare-change-password' || action === 'prepare-disable-totp') {
      const requiresAal2 =
        action === 'prepare-disable-totp' ||
        (action === 'prepare-change-password' && values.requires_aal2 === 'true')
      const requiredAcr = requiresAal2 ? 'urn:identity:acr:aal2' : undefined
      if (await hasFreshAuthentication(requiredAcr)) return { ok: true }

      const loginHint = values.login_hint?.trim()
      if (!loginHint) {
        throw new AccountActionError(
          translate(locale, 'accountAuthenticationRequired'),
        )
      }
      const response = await startReauthorization(
        accountReauthenticationReturnTo(action),
        action === 'prepare-change-password' ? 'password' : 'mfa',
        {
          loginHint,
          acrValues: requiredAcr ?? 'urn:identity:acr:aal1',
          maxAge: requiresAal2 ? 60 * 60 : 5 * 60,
        },
      )
      return { redirect: response.headers.get('location') ?? '/' }
    } else if (action === 'revoke-session') {
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
        `mutation UpdateProfile($input: UpdateProfileInput!) { updateProfile(input: $input) { user { id username givenName familyName nickname locale theme } } }`,
        {
          input: {
            givenName: nullableValue(values.given_name),
            familyName: nullableValue(values.family_name),
            nickname: nullableValue(values.nickname),
            website: nullableValue(values.website),
            birthdate: nullableValue(values.birthdate),
            locale: localePreferenceValue(values.locale),
            theme: themePreferenceValue(values.theme),
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
      if (!(await hasFreshAuthentication())) {
        const loginHint = values.login_hint?.trim() || await currentAccountLoginHint()
        if (!loginHint) {
          throw new AccountActionError(
            translate(locale, 'accountAuthenticationRequired'),
            { code: translate(locale, 'accountAuthenticationRequired') },
          )
        }
        const response = await startReauthorization(
          accountReauthenticationReturnTo(action),
          'account',
          {
            loginHint,
            acrValues: 'urn:identity:acr:aal1',
            maxAge: 5 * 60,
          },
        )
        return { redirect: response.headers.get('location') ?? '/' }
      }
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
    } else if (action === 'regenerate-recovery-codes') {
      const requiredAcr = 'urn:identity:acr:aal2'
      if (!(await hasFreshAuthentication(requiredAcr))) {
        const loginHint = values.login_hint?.trim() || await currentAccountLoginHint()
        if (!loginHint) {
          throw new AccountActionError(
            translate(locale, 'accountAuthenticationRequired'),
          )
        }
        const response = await startReauthorization(
          accountReauthenticationReturnTo(action),
          'mfa',
          {
            loginHint,
            acrValues: requiredAcr,
            maxAge: 60 * 60,
          },
        )
        return { redirect: response.headers.get('location') ?? '/' }
      }
      const result = await requireGraphql<{
        regenerateRecoveryCodes: { recoveryCodes: Array<string> }
      }>(
        `mutation RegenerateRecoveryCodes { regenerateRecoveryCodes { recoveryCodes } }`,
        undefined,
        { authorization: 'elevated' },
      )
      await storeRegeneratedRecoveryCodes(
        result.regenerateRecoveryCodes.recoveryCodes,
      )
      await clearElevatedAuthorization()
    } else {
      throw new AccountActionError(translate(locale, 'accountUnknownAction'))
    }

    if (
      action !== 'use-legacy-totp' &&
      action !== 'prepare-disable-totp' &&
      action !== 'prepare-change-password'
    ) {
      await storeAccountFlash({ message: 'saved' })
    }
    return { ok: true }
  } catch (error) {
    if (
      (action === 'change-password' ||
        action === 'prepare-change-password' ||
        isIdentifierAction(action) ||
        isMfaAction(action)) &&
      error instanceof GraphqlRequestError &&
      requiresAccountReauthentication(error)
    ) {
      const challenge = error.challenge
      const loginHint = values.login_hint?.trim() || await currentAccountLoginHint()
      if (!loginHint) {
        await storeAccountFlash({
          error: translate(locale, 'accountAuthenticationRequired'),
        })
        return { ok: false }
      }
      const response = await startReauthorization(
        accountReauthenticationReturnTo(action),
        reauthPurpose(action),
        {
          loginHint,
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

async function currentAccountLoginHint() {
  try {
    const data = await identityGraphql<{
      viewer: { account: { username: string } }
    }>(
      `query ReauthenticationLoginHint { viewer { account { username } } }`,
    )
    const username = data?.viewer.account.username.trim()
    return username || undefined
  } catch {
    return undefined
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
    'prepare-disable-totp',
    'begin-totp',
    'use-legacy-totp',
    'confirm-totp',
    'disable-totp',
    'regenerate-recovery-codes',
  ].includes(action)
}

function isIdentifierAction(action: string) {
  return action === 'update-username' || action === 'update-email'
}

function reauthPurpose(action: string) {
  if (
    action === 'disable-totp' ||
    action === 'prepare-disable-totp' ||
    action === 'regenerate-recovery-codes'
  ) {
    return 'mfa'
  }
  if (isIdentifierAction(action)) return 'account'
  return isMfaAction(action) ? 'account' : 'password'
}

function nullableValue(value?: string) {
  const normalized = value?.trim() ?? ''
  return normalized || null
}
