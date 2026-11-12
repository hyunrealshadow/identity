import { describe, expect, it } from 'vitest'

import { authenticationInput, parseWholeNumber, protocolDraft, protocolInput } from './settings-form'

const protocol = {
  oauthVersion: 'OAUTH_2_0' as const,
  requirePushedAuthorizationRequests: false,
  pushedAuthorizationRequestLifetimeSeconds: 90,
  pushedAuthorizationRequestLifetimeRange: { min: 10, max: 600 },
  deviceAuthorizationRequestLifetimeSeconds: 600,
  deviceAuthorizationRequestLifetimeRange: { min: 60, max: 3600 },
  deviceAuthorizationPollingIntervalSeconds: 5,
  deviceAuthorizationPollingIntervalRange: { min: 1, max: 60 },
  dynamicRegistrationEnabled: false,
  version: 'v1',
}

describe('settings form', () => {
  it('accepts only whole numbers inside the server range', () => {
    const range = { min: 1, max: 60 }
    expect(parseWholeNumber(' 30 ', range)).toEqual({ value: 30 })
    expect(parseWholeNumber('1.5', range)).toEqual({ error: { key: 'settingsWholeNumberRequired' } })
    expect(parseWholeNumber('', range)).toEqual({ error: { key: 'settingsWholeNumberRequired' } })
    expect(parseWholeNumber('61', range)).toEqual({
      error: { key: 'settingsOutOfRange', values: { min: 1, max: 60 } },
    })
  })

  it('submits the edited section with the version it was read at', () => {
    const draft = { ...protocolDraft(protocol), deviceAuthorizationPollingIntervalSeconds: '10' }
    expect(protocolInput(protocol, draft)).toEqual({
      input: {
        oauthVersion: 'OAUTH_2_0',
        requirePushedAuthorizationRequests: false,
        pushedAuthorizationRequestLifetimeSeconds: 90,
        deviceAuthorizationRequestLifetimeSeconds: 600,
        deviceAuthorizationPollingIntervalSeconds: 10,
        dynamicRegistrationEnabled: false,
        expectedVersion: 'v1',
      },
    })
  })

  it('reports every invalid field instead of submitting', () => {
    const result = authenticationInput(
      {
        breachedPasswordCheckEnabled: true,
        passwordHashing: {
          timeCost: 3,
          timeCostRange: { min: 1, max: 10 },
          memoryCostKib: 65536,
          memoryCostKibRange: { min: 19456, max: 1048576 },
          parallelism: 4,
          parallelismRange: { min: 1, max: 16 },
        },
        version: 'v2',
      },
      { breachedPasswordCheckEnabled: true, timeCost: '0', memoryCostKib: '1024', parallelism: '4' },
    )
    expect(result).toEqual({
      errors: {
        timeCost: { key: 'settingsOutOfRange', values: { min: 1, max: 10 } },
        memoryCostKib: { key: 'settingsOutOfRange', values: { min: 19456, max: 1048576 } },
      },
    })
  })
})
