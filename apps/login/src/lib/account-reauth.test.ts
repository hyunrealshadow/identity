import { describe, expect, it } from 'vitest'

import { GraphqlRequestError } from './graphql.server'
import {
  MFA_SETUP_CONTINUATION,
  accountReauthenticationReturnTo,
  requiresAccountReauthentication,
} from './account-reauth'

describe('account reauthentication', () => {
  it('recognizes the account.update scope required by MFA enrollment', () => {
    const error = new GraphqlRequestError([
      {
        message: 'insufficient scope',
        extensions: { requiredScope: 'account.update' },
      },
    ])

    expect(requiresAccountReauthentication(error)).toBe(true)
  })

  it('continues initial MFA enrollment after reauthentication', () => {
    expect(accountReauthenticationReturnTo('begin-totp')).toBe(
      MFA_SETUP_CONTINUATION,
    )
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
