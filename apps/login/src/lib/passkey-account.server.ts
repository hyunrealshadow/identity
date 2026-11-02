import { accountOperations } from './account-operations'
import { getRequestHeader } from '@tanstack/react-start/server'

import { PASSKEY_MANAGEMENT_CONTINUATION, requiresAccountReauthentication } from './account-reauth'
import { AccountSessionExpiredError, GraphqlRequestError, identityGraphql } from './graphql.server'
import { translate } from './i18n'
import { requestLocale } from './i18n.server'
import { restartAccountSignIn, startReauthorization } from './oauth.server'
import { loadApplicationUrl } from './runtime-config.server'
import { MAX_PASSKEYS_PER_ACCOUNT } from './passkey'
import type { PasskeyOptions } from './passkey'

export async function passkeyAccountAction(input: {
  action: 'prepare' | 'begin' | 'finish' | 'delete'
  id?: string
  name?: string
  credential?: string
  recoveryEnrollmentToken?: string | null
}): Promise<{ options?: PasskeyOptions; recoveryEnrollment?: { recoveryCodes: Array<string>; enrollmentToken?: string | null }; redirect?: string; error?: string; ok?: boolean }> {
  const locale = requestLocale()
  const origin = getRequestHeader('origin')
  if (origin && origin !== new URL(loadApplicationUrl()).origin) {
    return { error: translate(locale, 'accountInvalidRequestOrigin') }
  }
  const options = { authorization: 'elevated' as const }
  try {
    if (input.action === 'prepare') {
      const result = await identityGraphql<{ prepareMfaRecoveryCodes: { recoveryCodes: Array<string>; enrollmentToken?: string | null } }>(
        accountOperations['passkey-prepare'].document, undefined, options,
      )
      if (!result) throw new AccountSessionExpiredError()
      return { recoveryEnrollment: result.prepareMfaRecoveryCodes }
    }
    if (input.action === 'begin') {
      const result = await identityGraphql<{ beginPasskeyRegistration: PasskeyOptions }>(
        accountOperations['passkey-begin'].document,
        { recoveryEnrollmentToken: input.recoveryEnrollmentToken }, options,
      )
      if (!result) throw new AccountSessionExpiredError()
      return { options: result.beginPasskeyRegistration }
    }
    if (input.action === 'finish') {
      const result = await identityGraphql<{ finishPasskeyRegistration: boolean }>(
        accountOperations['passkey-finish'].document,
        { id: input.id, name: input.name, credential: JSON.parse(input.credential ?? "null") }, options,
      )
      if (!result) throw new AccountSessionExpiredError()
      if (!result.finishPasskeyRegistration) throw new Error(translate(locale, 'passkeyFailed'))
    } else {
      const result = await identityGraphql<{ deletePasskey: boolean }>(
        accountOperations['passkey-delete'].document, { id: input.id }, options,
      )
      if (!result) throw new AccountSessionExpiredError()
      if (!result.deletePasskey) throw new Error(translate(locale, 'passkeyFailed'))
    }
    return { ok: true }
  } catch (error) {
    if (error instanceof AccountSessionExpiredError) {
      return { redirect: (await restartAccountSignIn(PASSKEY_MANAGEMENT_CONTINUATION)).toString() }
    }
    if (error instanceof GraphqlRequestError && error.errors.some(({ extensions }) => Number(extensions?.code) === 11019)) {
      return { error: translate(locale, 'passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT }) }
    }
    if (error instanceof GraphqlRequestError && requiresAccountReauthentication(error)) {
      const account = await identityGraphql<{ account: { username: string } }>('query { account { username } }')
      if (!account) return { redirect: (await restartAccountSignIn(PASSKEY_MANAGEMENT_CONTINUATION)).toString() }
      const response = await startReauthorization(PASSKEY_MANAGEMENT_CONTINUATION, 'account', {
        loginHint: account.account.username,
        acrValues: error.challenge?.acrValues ?? 'aal1',
        maxAge: error.challenge?.maxAge,
      })
      return { redirect: response.headers.get('location') ?? '/account/security' }
    }
    return { error: error instanceof Error ? error.message : translate(locale, 'passkeyFailed') }
  }
}
