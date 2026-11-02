import { accountOperation, accountOperations } from './account-operations'
import { getRequestHeader } from '@tanstack/react-start/server'

import { graphqlFieldErrors } from './account-errors'
import { localePreferenceValue } from './account-locale'
import { themePreferenceValue } from './appearance'
import { timeZonePreferenceValue } from './time-zone'
import {
  accountActionDestination,
  accountReauthenticationReturnTo,
  requiresAccountReauthentication,
} from './account-reauth'
import type { AccountReauthRequest } from './popup-reauth'
import { AccountSessionExpiredError, GraphqlRequestError, identityGraphql, preflightIdentityGraphql } from './graphql.server'
import { translate, type Locale } from './i18n'
import { requestLocale } from './i18n.server'
import {
  clearElevatedAuthorization,
  clearMfaUiState,
  completeTotpStateChange,
  finishLogout,
  mfaUiState,
  startAccountSwitch,
  startPopupReauthorization,
  restartPopupReauthorization,
  restartAccountSignIn,
  storeMfaEnrollment,
  storeRegeneratedRecoveryCodes,
} from './oauth.server'
import { storeAccountFlash } from './oauth-session.server'
import { loadApplicationUrl } from './runtime-config.server'

export interface AccountActionInput {
  action: string
  values: Record<string, string>
  preflightOnly?: boolean
}

export interface AccountActionResult {
  redirect?: string
  /** Present only when a reauthentication should continue in the dialog. */
  reauth?: AccountReauthRequest
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
    if (input.preflightOnly) {
      const operation = accountOperation(action)
      if (!operation) throw new AccountActionError(translate(locale, 'accountUnknownAction'))
      await preflightIdentityGraphql(operation.document, undefined, { authorization: operation.authorization })
      return { ok: true }
    }
    if (action === 'retry-reauthentication') {
      if (!await currentAccountLoginHint()) throw new AccountSessionExpiredError()
      const reauth = await restartPopupReauthorization(values.state ?? '')
      return reauth ? { reauth } : { ok: false }
    }
    if (action === 'switch-account') {
      // A normal sign-in with explicit provider-side selection. It uses a fixed
      // safe route and never inherits a reauthentication login hint.
      const response = await startAccountSwitch('/account/profile')
      return { redirect: response.headers.get('location') ?? '/' }
    }
    if (action === 'logout') {
      const response = await finishLogout(applicationUrl)
      return { redirect: response.headers.get('location') ?? '/' }
    }
    if (action === 'cancel-totp') {
      await clearMfaUiState()
      return { ok: true }
    }
    if (action === 'prepare-manage-passkeys') {
      await requireGraphql(
        accountOperations["prepare-manage-passkeys"].document,
        undefined,
        { authorization: 'elevated' },
      )
      return { ok: true }
    }
    if (action === 'prepare-change-password' || action === 'prepare-disable-totp') {
      await preflightIdentityGraphql(
        action === 'prepare-change-password'
          ? accountOperations["change-password"].document
          : accountOperations["disable-totp"].document,
        undefined,
        { authorization: 'elevated' },
      )
      return { ok: true }
    } else if (action === 'revoke-session') {
      await requireGraphql(
        accountOperations["revoke-session"].document,
        { id: values.session_id ?? '' },
      )
    } else if (action === 'revoke-others') {
      await requireGraphql(
        accountOperations["revoke-others"].document,
      )
    } else if (action === 'update-mfa-preference') {
      const method = values.preferred_mfa_method
      if (method !== 'passkey' && method !== 'otp') throw new AccountActionError(translate(locale, 'mfaInvalidPriority'))
      await requireGraphql(
        accountOperations["update-mfa-preference"].document,
        { method: method.toUpperCase() },
      )
    } else if (action === 'update-profile') {
      const input: Record<string, string | null> = {}
      const addProfileValue = (
        formName: string,
        fieldName: string,
        normalize: (value: string | undefined) => string | null = nullableValue,
      ) => {
        // Profile forms are sparse patches: fields absent from the submitted
        // form are omitted instead of being cleared.
        if (!Object.prototype.hasOwnProperty.call(values, formName)) return
        input[fieldName] = normalize(values[formName])
      }
      addProfileValue('given_name', 'givenName')
      addProfileValue('family_name', 'familyName')
      addProfileValue('nickname', 'nickname')
      addProfileValue('website', 'website')
      addProfileValue('birthdate', 'birthdate')
      addProfileValue('locale', 'locale', localePreferenceValue)
      addProfileValue('theme', 'theme', themePreferenceValue)
      addProfileValue('zone_info', 'zoneInfo', timeZonePreferenceValue)
      await requireGraphql(
        accountOperations["update-profile"].document,
        { input },
      )
    } else if (action === 'update-username') {
      await requireGraphql(
        accountOperations["update-username"].document,
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
        accountOperations["update-email"].document,
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
        accountOperations["change-password"].document,
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
        accountOperations["begin-totp"].document,
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
        accountOperations["use-legacy-totp"].document,
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
        accountOperations["confirm-totp"].document,
        {
          input: {
            enrollmentToken: mfa.enrollment.enrollment_token,
            code: values.code ?? '',
          },
        },
        { authorization: 'elevated' },
      )
      await completeTotpStateChange(true)
      await clearElevatedAuthorization()
    } else if (action === 'disable-totp') {
      await requireGraphql(
        accountOperations["disable-totp"].document,
        undefined,
        { authorization: 'elevated' },
      )
      await completeTotpStateChange(false)
      await clearElevatedAuthorization()
    } else if (action === 'regenerate-recovery-codes') {
      const result = await requireGraphql<{
        regenerateRecoveryCodes: { recoveryCodes: Array<string> }
      }>(
        accountOperations["regenerate-recovery-codes"].document,
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

    if (action !== 'use-legacy-totp') {
      await storeAccountFlash({ message: 'saved' })
    }
    return { ok: true }
  } catch (error) {
    if (error instanceof AccountSessionExpiredError) {
      return { redirect: (await restartAccountSignIn(accountActionDestination(action))).toString() }
    }
    if (
      (action === 'change-password' ||
        action === 'prepare-change-password' ||
        isIdentifierAction(action) ||
        isMfaAction(action)) &&
      error instanceof GraphqlRequestError &&
      requiresAccountReauthentication(error)
    ) {
      const challenge = error.challenge
      // A page's submitted hint is not evidence that its session is still
      // usable. Check live access before choosing the popup recovery path.
      let loginHint: string | undefined
      try {
        loginHint = await currentAccountLoginHint()
      } catch (lookupError) {
        await storeAccountFlash(accountFlashFromError(lookupError, locale))
        return { ok: false }
      }
      if (!loginHint) {
        return { redirect: (await restartAccountSignIn(accountActionDestination(action))).toString() }
      }
      const reauth = await startPopupReauthorization(
        accountReauthenticationReturnTo(action),
        reauthPurpose(action),
        {
          loginHint,
          acrValues: challenge?.acrValues,
          maxAge: challenge?.maxAge,
        },
      )
      return { reauth }
    }
    await storeAccountFlash(accountFlashFromError(error, locale))
    return { ok: false }
  }
}

async function currentAccountLoginHint() {
  const data = await identityGraphql<{ account: { username: string } }>(
    `query ReauthenticationLoginHint { account { username } }`,
  )
  return data?.account.username.trim() || undefined
}

async function requireGraphql<T>(
  query: string,
  variables?: Record<string, unknown>,
  options?: { authorization?: 'default' | 'elevated' },
) {
  const data = await identityGraphql<T>(query, variables, options)
  if (!data) {
    throw new AccountSessionExpiredError()
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
    'prepare-manage-passkeys',
    'passkey-prepare', 'passkey-begin', 'passkey-finish', 'passkey-delete',
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
