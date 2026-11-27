import { describe, expect, it } from 'vitest'

import {
  authenticationDraft,
  authenticationInput,
  parseWholeNumber,
  protocolDraft,
  protocolInput,
  sessionDraft,
  sessionInput,
} from './settings-form'

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
  accessTokenLifetimeSeconds: 3600,
  accessTokenLifetimeRange: { min: 60, max: 86400 },
  idTokenLifetimeSeconds: 3600,
  idTokenLifetimeRange: { min: 60, max: 86400 },
  refreshTokenLifetimeDays: 30,
  refreshTokenLifetimeDaysRange: { min: 1, max: 365 },
  authorizationCodeLifetimeSeconds: 600,
  authorizationCodeLifetimeRange: { min: 30, max: 600 },
  version: 'v1',
}

const session = {
  sessionLifetimeHours: 168,
  sessionLifetimeHoursRange: { min: 1, max: 2160 },
  elevatedAuthenticationLifetimeMinutes: 60,
  elevatedAuthenticationLifetimeMinutesRange: { min: 5, max: 1440 },
  recentAuthenticationLifetimeMinutes: 5,
  recentAuthenticationLifetimeMinutesRange: { min: 1, max: 60 },
  loginLifetimeMinutes: 5,
  loginLifetimeMinutesRange: { min: 1, max: 60 },
  version: 's1',
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
        accessTokenLifetimeSeconds: 3600,
        idTokenLifetimeSeconds: 3600,
        refreshTokenLifetimeDays: 30,
        authorizationCodeLifetimeSeconds: 600,
        expectedVersion: 'v1',
      },
    })
  })

  it('reports every invalid field instead of submitting', () => {
    const authentication = {
      breachedPasswordCheckEnabled: true,
      identifierEnumerationAllowed: true,
      emailSignInEnabled: false,
      passwordResetEnabled: true,
      registrationEnabled: false,
      passwordMaxAgeDays: 0,
      passwordMaxAgeDaysRange: { min: 0, max: 3650 },
      passwordHistoryCount: 0,
      passwordHistoryCountRange: { min: 0, max: 24 },
      passwordMinLength: 12,
      passwordMinLengthRange: { min: 8, max: 128 },
      maxFailedAttempts: 5,
      maxFailedAttemptsRange: { min: 3, max: 20 },
      lockoutDurationMinutes: 15,
      lockoutDurationMinutesRange: { min: 1, max: 1440 },
      passwordHashing: {
        timeCost: 3,
        timeCostRange: { min: 1, max: 10 },
        memoryCostKib: 65536,
        memoryCostKibRange: { min: 19456, max: 1048576 },
        parallelism: 4,
        parallelismRange: { min: 1, max: 16 },
      },
      version: 'v2',
    }
    const result = authenticationInput(authentication, {
      ...authenticationDraft(authentication),
      timeCost: '0',
      memoryCostKib: '1024',
    })
    expect(result).toEqual({
      errors: {
        timeCost: { key: 'settingsOutOfRange', values: { min: 1, max: 10 } },
        memoryCostKib: { key: 'settingsOutOfRange', values: { min: 19456, max: 1048576 } },
      },
    })
  })

  it('validates and builds session settings inputs', () => {
    const valid = sessionInput(session, {
      ...sessionDraft(session),
      sessionLifetimeHours: '24',
    })
    expect(valid).toEqual({
      input: {
        sessionLifetimeHours: 24,
        elevatedAuthenticationLifetimeMinutes: 60,
        recentAuthenticationLifetimeMinutes: 5,
        loginLifetimeMinutes: 5,
        expectedVersion: 's1',
      },
    })

    const invalid = sessionInput(session, {
      ...sessionDraft(session),
      sessionLifetimeHours: '0',
      loginLifetimeMinutes: '99',
    })
    expect(invalid).toEqual({
      errors: {
        sessionLifetimeHours: { key: 'settingsOutOfRange', values: { min: 1, max: 2160 } },
        loginLifetimeMinutes: { key: 'settingsOutOfRange', values: { min: 1, max: 60 } },
      },
    })
  })
})
