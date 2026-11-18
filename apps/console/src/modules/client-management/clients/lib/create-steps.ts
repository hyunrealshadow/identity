import type { MessageKey } from '#/lib/i18n'

import {
  validateSettings,
  type ClientKind,
  type ClientSettingsDraft,
  type ClientSettingsField,
} from './client-form'

export type CreateStep = 'kind' | 'details' | 'redirects' | 'access' | 'review'

export const CREATE_STEPS: readonly CreateStep[] = [
  'kind',
  'details',
  'redirects',
  'access',
  'review',
]

export interface CreateSearch {
  step?: CreateStep
}

export function normalizeCreateSearch(input: Record<string, unknown>): CreateSearch {
  const step = input.step
  return typeof step === 'string' && (CREATE_STEPS as readonly string[]).includes(step)
    ? { step: step as CreateStep }
    : {}
}

export interface CreateDraftShape {
  kind: ClientKind
  name: string
  settings: ClientSettingsDraft
}

/**
 * The steps a draft walks through. A machine client has no redirect step
 * unless it also signs users in with the authorization code flow, which needs
 * a redirect address.
 */
export function stepsFor(draft: CreateDraftShape): readonly CreateStep[] {
  const redirects =
    draft.kind !== 'machine' ||
    draft.settings.grantTypes.includes('AUTHORIZATION_CODE')
  return CREATE_STEPS.filter((step) => step !== 'redirects' || redirects)
}

export type CreateField = ClientSettingsField | 'name'

const STEP_FIELDS: Record<CreateStep, readonly CreateField[]> = {
  kind: [],
  details: ['name'],
  redirects: ['webRedirectUris', 'nativeRedirectUris', 'postLogoutRedirectUris'],
  access: ['grantTypes'],
  review: [],
}

/** Checks for the fields one step owns; the review step checks everything. */
export function validateStep(
  step: CreateStep,
  draft: CreateDraftShape,
): Partial<Record<CreateField, MessageKey>> {
  const all: Partial<Record<CreateField, MessageKey>> = {
    ...(draft.name.trim() === '' ? { name: 'clientsNameRequired' as const } : {}),
    ...validateSettings(draft.settings),
  }
  if (step === 'review') return all
  return Object.fromEntries(
    Object.entries(all).filter(([field]) =>
      STEP_FIELDS[step].includes(field as CreateField),
    ),
  )
}

/**
 * The first step a person must finish before reaching `target`, or `target`
 * itself when every earlier step is valid. A step the draft no longer has
 * falls back to the nearest one before it.
 */
export function reachableStep(target: CreateStep, draft: CreateDraftShape): CreateStep {
  const steps = stepsFor(draft)
  const wanted = steps.includes(target)
    ? target
    : (steps.filter((step) => CREATE_STEPS.indexOf(step) < CREATE_STEPS.indexOf(target)).at(-1) ??
      steps[0])
  for (const step of steps) {
    if (step === wanted) return step
    if (Object.keys(validateStep(step, draft)).length > 0) return step
  }
  return wanted
}

/** The step that shows a field, so a server error can lead back to it. */
export function stepForField(field: string): CreateStep | undefined {
  if (['name', 'names', 'description', 'descriptions'].includes(field)) return 'details'
  for (const step of CREATE_STEPS) {
    if (STEP_FIELDS[step].includes(field as CreateField)) return step
  }
  return undefined
}
