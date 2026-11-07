// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  keyExpiryInstant,
  maskedSecretHint,
  settingsDraftFromClient,
  settingsForKind,
  settingsInput,
  validateSettings,
} from './client-form'

describe('client settings draft', () => {
  it('turns line lists into platforms without blanks or duplicates', () => {
    const draft = {
      ...settingsForKind('web'),
      webRedirectUris:
        ' https://app.example.com/cb \n\nhttps://app.example.com/cb\nhttp://localhost:3000/cb',
      postLogoutRedirectUris: 'https://app.example.com/bye',
    }
    expect(settingsInput(draft)).toMatchObject({
      platforms: [
        {
          platform: 'WEB',
          redirectUris: ['https://app.example.com/cb', 'http://localhost:3000/cb'],
        },
      ],
      postLogoutRedirectUris: ['https://app.example.com/bye'],
      grantTypes: ['AUTHORIZATION_CODE', 'REFRESH_TOKEN'],
    })
  })

  it('keeps every server value when editing an existing client', () => {
    const client = {
      platforms: [
        { platform: 'NATIVE', redirectUris: ['com.example.app:/cb'] },
      ],
      postLogoutRedirectUris: [],
      grantTypes: ['AUTHORIZATION_CODE' as const],
      allowPublicClientFlow: true,
      requirePushedAuthorizationRequests: true,
      skipConsent: false,
      corsEnabled: false,
    }
    const input = settingsInput(settingsDraftFromClient(client))
    expect(input.platforms).toEqual(client.platforms)
    expect(input.requirePushedAuthorizationRequests).toBe(true)
  })

  it('reports the same combinations the server rejects', () => {
    expect(validateSettings(settingsForKind('web'))).toEqual({
      webRedirectUris: 'clientsRedirectRequired',
    })
    expect(validateSettings(settingsForKind('machine'))).toEqual({})
    expect(
      validateSettings({ ...settingsForKind('machine'), grantTypes: ['REFRESH_TOKEN'] })
        .grantTypes,
    ).toBe('clientsGrantRefreshNeedsInteractive')
    expect(
      validateSettings({ ...settingsForKind('machine'), grantTypes: ['IMPLICIT'] })
        .grantTypes,
    ).toBe('clientsGrantImplicitUnsupported')
  })
})

describe('credentials', () => {
  it('masks a secret hint without the server storing a mask', () => {
    expect(maskedSecretHint('D9wk')).toBe('••••••••D9wk')
    expect(maskedSecretHint('')).toBe('••••••••')
  })

  it('keeps a key valid through the chosen day in the viewer\'s time zone', () => {
    expect(keyExpiryInstant('2027-03-01', 'Asia/Shanghai')).toBe('2027-03-01T16:00:00.000Z')
    expect(keyExpiryInstant('2027-03-01', 'UTC')).toBe('2027-03-02T00:00:00.000Z')
    expect(keyExpiryInstant('not a day', 'UTC')).toBeNull()
  })

  it('no longer sends token endpoint methods with the settings', () => {
    expect(settingsInput(settingsForKind('spa'))).not.toHaveProperty('tokenEndpointAuthMethods')
    expect(settingsInput(settingsForKind('spa')).allowPublicClientFlow).toBe(true)
  })
})
