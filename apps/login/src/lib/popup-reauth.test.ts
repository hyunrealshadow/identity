import { describe, expect, it, vi } from 'vitest'

import {
  ACCOUNT_REAUTH_MESSAGE_TYPE,
  openAccountReauthPopup,
  isAccountReauthMessage,
  safeAccountReauthReturnTo,
  verifyAccountReauthMessage,
} from './popup-reauth'

const frame = {} as MessageEventSource

function message(overrides: Record<string, unknown> = {}) {
  return {
    type: ACCOUNT_REAUTH_MESSAGE_TYPE,
    state: 'issued-state',
    returnTo: '/account/security?confirm=change-password',
    result: 'success',
    ...overrides,
  }
}

function verification(
  overrides: Partial<Parameters<typeof verifyAccountReauthMessage>[0]> = {},
) {
  return {
    data: message(),
    origin: 'https://login.example.com',
    expectedOrigin: 'https://login.example.com',
    source: frame,
    expectedSource: frame,
    expectedState: 'issued-state',
    ...overrides,
  }
}

describe('popup reauthentication messages', () => {
  it('accepts the exact origin, frame, state, and result', () => {
    expect(verifyAccountReauthMessage(verification())).toEqual(message())
  })

  it('rejects a different sender origin', () => {
    expect(verifyAccountReauthMessage(
      verification({ origin: 'https://attacker.example' }),
    )).toBeUndefined()
  })

  it('rejects a message from a different frame', () => {
    expect(verifyAccountReauthMessage(
      verification({ source: {} as MessageEventSource }),
    )).toBeUndefined()
  })

  it('rejects a different state', () => {
    expect(verifyAccountReauthMessage(
      verification({ expectedState: 'other-state' }),
    )).toBeUndefined()
  })

  it('rejects an unknown message type', () => {
    expect(verifyAccountReauthMessage(
      verification({ data: message({ type: 'other.message' }) }),
    )).toBeUndefined()
  })

  it('rejects an unknown result', () => {
    expect(verifyAccountReauthMessage(
      verification({ data: message({ result: 'approved' }) }),
    )).toBeUndefined()
  })

  it('does not trust a valid shape as a message without a state', () => {
    expect(isAccountReauthMessage(message({ state: '' }))).toBe(false)
    expect(isAccountReauthMessage(message({ returnTo: 42 }))).toBe(false)
  })

  it('only resumes safe same-origin account paths', () => {
    expect(safeAccountReauthReturnTo('/account/security?confirm=passkeys')).toBe(
      '/account/security?confirm=passkeys',
    )
    expect(safeAccountReauthReturnTo('https://attacker.example')).toBeUndefined()
    expect(safeAccountReauthReturnTo('//attacker.example')).toBeUndefined()
    expect(safeAccountReauthReturnTo('account/security')).toBeUndefined()
    expect(safeAccountReauthReturnTo(undefined)).toBeUndefined()
  })
})

describe('browser verification window', () => {
  it('centers a login-sized resizable popup on the current screen', () => {
    const open = vi.fn(() => null)
    const owner = { open, screenX: 100, screenY: 40, outerWidth: 1200, outerHeight: 900,
      screen: { availWidth: 1920, availHeight: 1080, availLeft: 0, availTop: 0 } } as unknown as Window
    openAccountReauthPopup(owner)
    expect(open).toHaveBeenCalledWith('about:blank', '_blank',
      'popup=yes,width=520,height=720,left=440,top=130,resizable=yes,scrollbars=yes')
  })
})
