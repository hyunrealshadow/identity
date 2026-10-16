import { afterEach, describe, expect, it, vi } from 'vitest'
import { authenticationOptions, registrationOptions, serializeCredential } from './passkey'

afterEach(() => vi.unstubAllGlobals())

describe('account-bound passkey browser requests', () => {
  it('refuses a discoverable request without an account allow-list', () => {
    expect(() => authenticationOptions({ challenge: 'AQID' })).toThrow()
    expect(() => authenticationOptions({ challenge: 'AQID', allowCredentials: [] })).toThrow()
  })

  it('preserves the selected account credentials and requires user verification', () => {
    const result = authenticationOptions({ challenge: '-_8', rpId: 'login.example.com', allowCredentials: [{ id: 'AQID', type: 'public-key', transports: ['internal'] }] })
    expect([...new Uint8Array(result.challenge as ArrayBuffer)]).toEqual([251, 255])
    expect(result.rpId).toBe('login.example.com')
    expect(result.userVerification).toBe('required')
    expect([...new Uint8Array(result.allowCredentials![0].id as ArrayBuffer)]).toEqual([1, 2, 3])
    expect(result.allowCredentials![0].transports).toEqual(['internal'])
  })

  it('decodes registration identifiers and preserves exclusions', () => {
    const result = registrationOptions({ challenge: 'AQID', rp: { name: 'Identity' }, user: { id: 'BAU', name: 'person', displayName: 'Person' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [{ id: 'Bgc', type: 'public-key' }] })
    expect([...new Uint8Array(result.user.id as ArrayBuffer)]).toEqual([4, 5])
    expect([...new Uint8Array(result.excludeCredentials![0].id as ArrayBuffer)]).toEqual([6, 7])
  })

  it('serializes assertion binary data without duplicate extension aliases', () => {
    const data = new Uint8Array([251, 255]).buffer
    const result = serializeCredential({ id: 'id', rawId: data, type: 'public-key', response: { clientDataJSON: data, authenticatorData: data, signature: data, userHandle: null }, getClientExtensionResults: () => ({}), authenticatorAttachment: 'platform' } as unknown as PublicKeyCredential)
    expect(result.rawId).toBe('-_8')
    expect(result.response).toMatchObject({ signature: '-_8', userHandle: null })
    expect(result).not.toHaveProperty('extensions')
    expect(result).toHaveProperty('clientExtensionResults', {})
  })
})
