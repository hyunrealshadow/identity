import type {
  ClientAdvancedSettingsInput,
  ClientSubjectType,
} from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'
import { uriLines } from './client-form'

/** Upper bound for the default maximum authentication age (mirrors the server). */
export const MAX_DEFAULT_MAX_AGE_SECONDS = 31_536_000

/**
 * Advanced OpenID Connect metadata as edited. Text fields hold what the
 * administrator typed; URI and contact lists are one entry per line. An empty
 * algorithm list keeps the provider default; a selection keeps the provider's
 * published order, which the runtime treats as its preference.
 */
export interface ClientAdvancedDraft {
  frontchannelLogoutUri: string
  frontchannelLogoutSessionRequired: boolean
  backchannelLogoutUri: string
  backchannelLogoutSessionRequired: boolean
  logoUri: string
  clientUri: string
  policyUri: string
  tosUri: string
  contacts: string
  subjectType: ClientSubjectType
  sectorIdentifierUri: string
  defaultMaxAge: string
  requireAuthTime: boolean
  defaultAcrValues: string[]
  idTokenSignedResponseAlgs: string[]
  idTokenEncryptedResponseAlgs: string[]
  idTokenEncryptedResponseEncs: string[]
  userinfoSignedResponseAlgs: string[]
  userinfoEncryptedResponseAlgs: string[]
  userinfoEncryptedResponseEncs: string[]
  requestObjectSigningAlgs: string[]
  requestObjectEncryptionAlgs: string[]
  requestObjectEncryptionEncs: string[]
  requestUris: string
  tokenEndpointAuthSigningAlgs: string[]
  initiateLoginUri: string
}

export type ClientAdvancedField = keyof ClientAdvancedDraft

export interface ClientAdvancedSource {
  frontchannelLogoutUri?: string | null
  frontchannelLogoutSessionRequired: boolean
  backchannelLogoutUri?: string | null
  backchannelLogoutSessionRequired: boolean
  logoUri?: string | null
  clientUri?: string | null
  policyUri?: string | null
  tosUri?: string | null
  contacts: readonly string[]
  subjectType: ClientSubjectType
  sectorIdentifierUri?: string | null
  defaultMaxAge?: number | null
  requireAuthTime: boolean
  defaultAcrValues: readonly string[]
  idTokenSignedResponseAlgs: readonly string[]
  idTokenEncryptedResponseAlgs: readonly string[]
  idTokenEncryptedResponseEncs: readonly string[]
  userinfoSignedResponseAlgs: readonly string[]
  userinfoEncryptedResponseAlgs: readonly string[]
  userinfoEncryptedResponseEncs: readonly string[]
  requestObjectSigningAlgs: readonly string[]
  requestObjectEncryptionAlgs: readonly string[]
  requestObjectEncryptionEncs: readonly string[]
  requestUris: readonly string[]
  tokenEndpointAuthSigningAlgs: readonly string[]
  initiateLoginUri?: string | null
}

export function advancedDraftFromClient(source: ClientAdvancedSource): ClientAdvancedDraft {
  const text = (value: string | null | undefined) => value ?? ''
  return {
    frontchannelLogoutUri: text(source.frontchannelLogoutUri),
    frontchannelLogoutSessionRequired: source.frontchannelLogoutSessionRequired,
    backchannelLogoutUri: text(source.backchannelLogoutUri),
    backchannelLogoutSessionRequired: source.backchannelLogoutSessionRequired,
    logoUri: text(source.logoUri),
    clientUri: text(source.clientUri),
    policyUri: text(source.policyUri),
    tosUri: text(source.tosUri),
    contacts: source.contacts.join('\n'),
    subjectType: source.subjectType,
    sectorIdentifierUri: text(source.sectorIdentifierUri),
    defaultMaxAge:
      source.defaultMaxAge === null || source.defaultMaxAge === undefined
        ? ''
        : String(source.defaultMaxAge),
    requireAuthTime: source.requireAuthTime,
    defaultAcrValues: [...source.defaultAcrValues],
    idTokenSignedResponseAlgs: [...source.idTokenSignedResponseAlgs],
    idTokenEncryptedResponseAlgs: [...source.idTokenEncryptedResponseAlgs],
    idTokenEncryptedResponseEncs: [...source.idTokenEncryptedResponseEncs],
    userinfoSignedResponseAlgs: [...source.userinfoSignedResponseAlgs],
    userinfoEncryptedResponseAlgs: [...source.userinfoEncryptedResponseAlgs],
    userinfoEncryptedResponseEncs: [...source.userinfoEncryptedResponseEncs],
    requestObjectSigningAlgs: [...source.requestObjectSigningAlgs],
    requestObjectEncryptionAlgs: [...source.requestObjectEncryptionAlgs],
    requestObjectEncryptionEncs: [...source.requestObjectEncryptionEncs],
    requestUris: source.requestUris.join('\n'),
    tokenEndpointAuthSigningAlgs: [...source.tokenEndpointAuthSigningAlgs],
    initiateLoginUri: text(source.initiateLoginUri),
  }
}

function optional(value: string): string | null {
  const trimmed = value.trim()
  return trimmed === '' ? null : trimmed
}

function wholeNumber(value: string): number | null {
  const trimmed = value.trim()
  if (trimmed === '') return null
  return /^\d+$/u.test(trimmed) ? Number(trimmed) : Number.NaN
}

/** The whole advanced unit, as the server replaces it. */
export function advancedInput(draft: ClientAdvancedDraft): ClientAdvancedSettingsInput {
  const maxAge = wholeNumber(draft.defaultMaxAge)
  return {
    frontchannelLogoutUri: optional(draft.frontchannelLogoutUri),
    frontchannelLogoutSessionRequired: draft.frontchannelLogoutSessionRequired,
    backchannelLogoutUri: optional(draft.backchannelLogoutUri),
    backchannelLogoutSessionRequired: draft.backchannelLogoutSessionRequired,
    logoUri: optional(draft.logoUri),
    clientUri: optional(draft.clientUri),
    policyUri: optional(draft.policyUri),
    tosUri: optional(draft.tosUri),
    contacts: uriLines(draft.contacts),
    subjectType: draft.subjectType,
    // Pairwise is the only reason to register a sector.
    sectorIdentifierUri:
      draft.subjectType === 'PAIRWISE' ? optional(draft.sectorIdentifierUri) : null,
    defaultMaxAge: maxAge !== null && Number.isFinite(maxAge) ? maxAge : null,
    requireAuthTime: draft.requireAuthTime,
    defaultAcrValues: [...draft.defaultAcrValues],
    idTokenSignedResponseAlgs: [...draft.idTokenSignedResponseAlgs],
    idTokenEncryptedResponseAlgs: [...draft.idTokenEncryptedResponseAlgs],
    idTokenEncryptedResponseEncs: [...draft.idTokenEncryptedResponseEncs],
    userinfoSignedResponseAlgs: [...draft.userinfoSignedResponseAlgs],
    userinfoEncryptedResponseAlgs: [...draft.userinfoEncryptedResponseAlgs],
    userinfoEncryptedResponseEncs: [...draft.userinfoEncryptedResponseEncs],
    requestObjectSigningAlgs: [...draft.requestObjectSigningAlgs],
    requestObjectEncryptionAlgs: [...draft.requestObjectEncryptionAlgs],
    requestObjectEncryptionEncs: [...draft.requestObjectEncryptionEncs],
    requestUris: uriLines(draft.requestUris),
    tokenEndpointAuthSigningAlgs: [...draft.tokenEndpointAuthSigningAlgs],
    initiateLoginUri: optional(draft.initiateLoginUri),
  }
}

/**
 * Interaction-level checks that mirror the server. The server remains
 * authoritative, including the sector document and supported algorithms.
 */
export function validateAdvanced(
  draft: ClientAdvancedDraft,
): Partial<Record<ClientAdvancedField, MessageKey>> {
  const errors: Partial<Record<ClientAdvancedField, MessageKey>> = {}
  const maxAge = wholeNumber(draft.defaultMaxAge)
  if (maxAge !== null && !(maxAge >= 0 && maxAge <= MAX_DEFAULT_MAX_AGE_SECONDS)) {
    errors.defaultMaxAge = 'clientsAdvancedMaxAgeInvalid'
  }
  if (draft.frontchannelLogoutSessionRequired && !optional(draft.frontchannelLogoutUri)) {
    errors.frontchannelLogoutUri = 'clientsLogoutUriRequired'
  }
  if (draft.backchannelLogoutSessionRequired && !optional(draft.backchannelLogoutUri)) {
    errors.backchannelLogoutUri = 'clientsLogoutUriRequired'
  }
  const pairs = [
    ['idTokenEncryptedResponseAlgs', 'idTokenEncryptedResponseEncs'],
    ['userinfoEncryptedResponseAlgs', 'userinfoEncryptedResponseEncs'],
    ['requestObjectEncryptionAlgs', 'requestObjectEncryptionEncs'],
  ] as const
  for (const [alg, enc] of pairs) {
    if (draft[enc].length > 0 && draft[alg].length === 0) {
      errors[alg] = 'clientsAdvancedEncryptionAlgRequired'
    }
  }
  return errors
}

const FIELD_NAMES = new Set<string>(
  Object.keys(
    advancedDraftFromClient({
      frontchannelLogoutSessionRequired: false,
      backchannelLogoutSessionRequired: false,
      contacts: [],
      subjectType: 'PUBLIC',
      requireAuthTime: false,
      defaultAcrValues: [],
      requestUris: [],
      idTokenSignedResponseAlgs: [],
      idTokenEncryptedResponseAlgs: [],
      idTokenEncryptedResponseEncs: [],
      userinfoSignedResponseAlgs: [],
      userinfoEncryptedResponseAlgs: [],
      userinfoEncryptedResponseEncs: [],
      requestObjectSigningAlgs: [],
      requestObjectEncryptionAlgs: [],
      requestObjectEncryptionEncs: [],
      tokenEndpointAuthSigningAlgs: [],
    }),
  ),
)

/** Map a server field path (`advancedSettings.logoUri`) onto its form field. */
export function advancedFieldFor(path: string): ClientAdvancedField | undefined {
  const match = /^(?:input\.)?advancedSettings\.([A-Za-z]+)/u.exec(path)
  const name = match?.[1]
  return name && FIELD_NAMES.has(name) ? (name as ClientAdvancedField) : undefined
}
