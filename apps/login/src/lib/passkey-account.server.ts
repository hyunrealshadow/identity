import { getRequestHeader } from '@tanstack/react-start/server'

import { requiresAccountReauthentication } from './account-reauth'
import { GraphqlRequestError, identityGraphql } from './graphql.server'
import { translate } from './i18n'
import { requestLocale } from './i18n.server'
import { startReauthorization } from './oauth.server'
import { loadApplicationUrl } from './runtime-config.server'
import { MAX_PASSKEYS_PER_ACCOUNT } from './passkey'
import type { PasskeyOptions } from './passkey'

export async function passkeyAccountAction(input: {
  action: 'begin' | 'finish' | 'delete'
  id?: string
  name?: string
  credential?: string
}): Promise<{ options?: PasskeyOptions; redirect?: string; error?: string; ok?: boolean }> {
  const locale = requestLocale()
  const origin = getRequestHeader('origin')
  if (origin && origin !== new URL(loadApplicationUrl()).origin) {
    return { error: translate(locale, 'accountInvalidRequestOrigin') }
  }
  const options = { authorization: 'elevated' as const }
  try {
    if (input.action === 'begin') {
      const result = await identityGraphql<{ beginPasskeyRegistration: PasskeyOptions }>(
        'mutation { beginPasskeyRegistration }', undefined, options,
      )
      if (!result) throw new Error(translate(locale, 'accountAuthenticationRequired'))
      return { options: result.beginPasskeyRegistration }
    }
    if (input.action === 'finish') {
      const result = await identityGraphql<{ finishPasskeyRegistration: boolean }>(
        'mutation RegisterPasskey($id: String!, $name: String!, $credential: JSON!) { finishPasskeyRegistration(challengeId: $id, name: $name, credential: $credential) }',
        { id: input.id, name: input.name, credential: JSON.parse(input.credential ?? "null") }, options,
      )
      if (!result?.finishPasskeyRegistration) throw new Error(translate(locale, 'passkeyFailed'))
    } else {
      const result = await identityGraphql<{ deletePasskey: boolean }>(
        'mutation DeletePasskey($id: String!) { deletePasskey(id: $id) }', { id: input.id }, options,
      )
      if (!result?.deletePasskey) throw new Error(translate(locale, 'passkeyFailed'))
    }
    return { ok: true }
  } catch (error) {
    if (error instanceof GraphqlRequestError && error.errors.some(({ extensions }) => Number(extensions?.code) === 11019)) {
      return { error: translate(locale, 'passkeyLimitReached', { limit: MAX_PASSKEYS_PER_ACCOUNT }) }
    }
    if (error instanceof GraphqlRequestError && requiresAccountReauthentication(error)) {
      const account = await identityGraphql<{ viewer: { account: { username: string } } }>('query { viewer { account { username } } }')
      if (!account) return { error: translate(locale, 'accountAuthenticationRequired') }
      const response = await startReauthorization('/account/security', 'account', {
        loginHint: account.viewer.account.username,
        acrValues: error.challenge?.acrValues ?? 'aal1',
        maxAge: error.challenge?.maxAge,
      })
      return { redirect: response.headers.get('location') ?? '/account/security' }
    }
    return { error: error instanceof Error ? error.message : translate(locale, 'passkeyFailed') }
  }
}
