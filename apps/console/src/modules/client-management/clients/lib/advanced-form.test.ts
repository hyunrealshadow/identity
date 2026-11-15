// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  advancedDraftFromClient,
  advancedFieldFor,
  advancedInput,
  validateAdvanced,
  type ClientAdvancedSource,
} from './advanced-form'

const stored: ClientAdvancedSource = {
  frontchannelLogoutSessionRequired: false,
  backchannelLogoutUri: 'https://app.example.com/logout',
  backchannelLogoutSessionRequired: true,
  contacts: ['ops@example.com'],
  subjectType: 'PAIRWISE',
  sectorIdentifierUri: 'https://app.example.com/sector.json',
  defaultMaxAge: 0,
  requireAuthTime: false,
  defaultAcrValues: ['aal2'],
  idTokenSignedResponseAlgs: ['PS256', 'ES256'],
  idTokenEncryptedResponseAlgs: [],
  idTokenEncryptedResponseEncs: [],
  userinfoSignedResponseAlgs: [],
  userinfoEncryptedResponseAlgs: [],
  userinfoEncryptedResponseEncs: [],
  requestObjectSigningAlgs: ['ES256'],
  requestObjectEncryptionAlgs: [],
  requestObjectEncryptionEncs: [],
  requestUris: [],
  tokenEndpointAuthSigningAlgs: [],
}

describe('advanced client settings draft', () => {
  it('round-trips stored values, keeping algorithm order and a zero max age', () => {
    const input = advancedInput(advancedDraftFromClient(stored))
    expect(input.idTokenSignedResponseAlgs).toEqual(['PS256', 'ES256'])
    expect(input.defaultMaxAge).toBe(0)
    expect(input.backchannelLogoutSessionRequired).toBe(true)
    expect(input.defaultAcrValues).toEqual(['aal2'])
    expect(input.sectorIdentifierUri).toBe('https://app.example.com/sector.json')
    expect(input.logoUri).toBeNull()
  })

  it('clears blank text and drops the sector of a public subject', () => {
    const draft = {
      ...advancedDraftFromClient(stored),
      subjectType: 'PUBLIC' as const,
      logoUri: '   ',
      defaultMaxAge: '',
      contacts: ' a@example.com \n\na@example.com',
      defaultAcrValues: [],
    }
    const input = advancedInput(draft)
    expect(input.sectorIdentifierUri).toBeNull()
    expect(input.logoUri).toBeNull()
    expect(input.defaultMaxAge).toBeNull()
    expect(input.contacts).toEqual(['a@example.com'])
    expect(input.defaultAcrValues).toEqual([])
  })

  it('flags combinations the server would reject', () => {
    const draft = {
      ...advancedDraftFromClient(stored),
      backchannelLogoutUri: '',
      idTokenEncryptedResponseEncs: ['A128GCM'],
      defaultMaxAge: '-5',
    }
    expect(validateAdvanced(draft)).toEqual({
      backchannelLogoutUri: 'clientsLogoutUriRequired',
      idTokenEncryptedResponseAlgs: 'clientsAdvancedEncryptionAlgRequired',
      defaultMaxAge: 'clientsAdvancedMaxAgeInvalid',
    })
    expect(validateAdvanced(advancedDraftFromClient(stored))).toEqual({})
  })

  it('routes server field paths to advanced fields only', () => {
    expect(advancedFieldFor('input.advancedSettings.logoUri')).toBe('logoUri')
    expect(advancedFieldFor('advancedSettings.idTokenSignedResponseAlgs.1')).toBe(
      'idTokenSignedResponseAlgs',
    )
    expect(advancedFieldFor('advancedSettings.unknown')).toBeUndefined()
    expect(advancedFieldFor('settings.platforms')).toBeUndefined()
  })
})
