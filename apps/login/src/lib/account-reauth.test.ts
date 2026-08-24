import { describe, expect, it } from 'vitest'

import { GraphqlRequestError } from './graphql.server'
import {
  MFA_SETUP_CONTINUATION,
  MFA_VERIFICATION_CONTINUATION,
  MFA_DISABLE_CONTINUATION,
  PASSWORD_CHANGE_CONTINUATION,
  RECOVERY_CODES_CONTINUATION,
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

  it('returns an interrupted MFA confirmation to the verification step', () => {
    expect(accountReauthenticationReturnTo('confirm-totp')).toBe(
      MFA_VERIFICATION_CONTINUATION,
    )
  })

  it('returns MFA removal to its confirmation after reauthentication', () => {
    expect(accountReauthenticationReturnTo('prepare-disable-totp')).toBe(
      MFA_DISABLE_CONTINUATION,
    )
  })

  it('returns recovery-code regeneration to its management dialog', () => {
    expect(accountReauthenticationReturnTo('regenerate-recovery-codes')).toBe(
      RECOVERY_CODES_CONTINUATION,
    )
  })

  it('returns password changes to their form after reauthentication', () => {
    expect(accountReauthenticationReturnTo('prepare-change-password')).toBe(
      PASSWORD_CHANGE_CONTINUATION,
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
