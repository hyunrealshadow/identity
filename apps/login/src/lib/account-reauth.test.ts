import { describe, expect, it } from 'vitest'

import { GraphqlRequestError } from './graphql.server'
import {
  accountReauthenticationReturnTo,
  requiresAccountReauthentication,
} from './account-reauth'

describe('account reauthentication', () => {
  it('does not turn a permission denial into an authentication challenge', () => {
    for (const requiredScope of ['account.update', 'password.change']) {
      expect(requiresAccountReauthentication(new GraphqlRequestError([{
        message: 'insufficient scope', extensions: { code: 'insufficient_scope', requiredScope },
      }]))).toBe(false)
    }
    expect(requiresAccountReauthentication(new GraphqlRequestError([{
      message: 'recent authentication required', extensions: { code: 'insufficient_user_authentication' },
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
