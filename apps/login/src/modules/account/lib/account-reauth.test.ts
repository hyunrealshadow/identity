import { describe, expect, it } from 'vitest'

import { GraphqlRequestError } from '#/lib/graphql.server'
import {
  accountReauthenticationReturnTo,
  requiresAccountReauthentication,
} from '#/modules/account/lib/account-reauth'

describe('account reauthentication', () => {
  it('does not turn a permission denial into an authentication challenge', () => {
    for (const requiredScope of ['user.write', 'password.change']) {
      expect(requiresAccountReauthentication(new GraphqlRequestError([{
        message: 'insufficient scope', extensions: { kind: 'forbidden', challenge: { error: 'insufficient_scope', scopes: [requiredScope] } },
      }]))).toBe(false)
    }
    expect(requiresAccountReauthentication(new GraphqlRequestError([{
      message: 'recent authentication required', extensions: { kind: 'unauthorized', challenge: { error: 'insufficient_user_authentication' } },
    }], { acrValues: 'aal2', maxAge: 300 }))).toBe(true)
  })

  it('returns identifier changes to their dedicated page', () => {
    expect(accountReauthenticationReturnTo('update-username')).toBe(
      '/account/identifiers',
    )
    expect(accountReauthenticationReturnTo('update-email')).toBe(
      '/account/identifiers',
    )
  })
})
