import { describe, expect, it } from 'vitest'

import { settingsForKind, type ClientKind } from './client-form'
import {
  normalizeCreateSearch,
  reachableStep,
  stepForField,
  stepsFor,
  validateStep,
  type CreateDraftShape,
} from './create-steps'

function draft(kind: ClientKind, overrides: Partial<CreateDraftShape> = {}): CreateDraftShape {
  return { kind, name: '', settings: settingsForKind(kind), ...overrides }
}

describe('client creation steps', () => {
  it('skips the redirect step only for a machine client without sign-in', () => {
    expect(stepsFor(draft('web'))).toContain('redirects')
    expect(stepsFor(draft('machine'))).not.toContain('redirects')

    const signsIn = draft('machine')
    signsIn.settings = {
      ...signsIn.settings,
      grantTypes: ['CLIENT_CREDENTIALS', 'AUTHORIZATION_CODE'],
    }
    expect(stepsFor(signsIn)).toContain('redirects')
  })

  it('checks only the fields a step owns', () => {
    const empty = draft('web')
    expect(validateStep('kind', empty)).toEqual({})
    expect(validateStep('details', empty)).toEqual({ name: 'clientsNameRequired' })
    expect(validateStep('redirects', empty)).toEqual({
      webRedirectUris: 'clientsRedirectRequired',
    })
    expect(validateStep('access', empty)).toEqual({})
    expect(Object.keys(validateStep('review', empty)).sort()).toEqual([
      'name',
      'webRedirectUris',
    ])
  })

  it('stops a jump at the first unfinished step', () => {
    expect(reachableStep('review', draft('web'))).toBe('details')
    expect(reachableStep('review', draft('web', { name: 'App' }))).toBe('redirects')

    const ready = draft('web', { name: 'App' })
    ready.settings = { ...ready.settings, webRedirectUris: 'https://app.example.test/cb' }
    expect(reachableStep('review', ready)).toBe('review')
  })

  it('falls back to the nearest earlier step when the draft has no such step', () => {
    expect(reachableStep('redirects', draft('machine', { name: 'Worker' }))).toBe('details')
  })

  it('leads server field errors back to the step that shows them', () => {
    expect(stepForField('names')).toBe('details')
    expect(stepForField('postLogoutRedirectUris')).toBe('redirects')
    expect(stepForField('grantTypes')).toBe('access')
    expect(stepForField('unknown')).toBeUndefined()
  })

  it('ignores an unknown step in the address', () => {
    expect(normalizeCreateSearch({ step: 'access' })).toEqual({ step: 'access' })
    expect(normalizeCreateSearch({ step: 'finish' })).toEqual({})
    expect(normalizeCreateSearch({ step: 3 })).toEqual({})
  })
})
