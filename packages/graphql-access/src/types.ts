export type AccessAuthentication =
  | 'SESSION'
  | 'AAL2'
  | 'RECENT'
  | 'RECENT_AAL2'
  | 'ACCOUNT_SECURITY'

export interface AccessPolicy {
  scopes: readonly string[]
  authentication: AccessAuthentication
  maxAge?: number
  elevatedMaxAge?: number
  userOnly: boolean
  runtime: boolean
}

export interface SchemaField {
  name: string
  returnType: string
  policies: readonly AccessPolicy[]
}

export type SchemaTypeKind = 'OBJECT' | 'INTERFACE' | 'UNION'

export interface SchemaType {
  kind: SchemaTypeKind
  interfaces: readonly string[]
  possibleTypes: readonly string[]
  fields: Readonly<Record<string, SchemaField>>
}

export interface SchemaMetadata {
  queryTypeName: string
  mutationTypeName: string | null
  types: Readonly<Record<string, SchemaType>>
}

export interface PreflightContext {
  scopes: readonly string[]
  acr?: string
  /** Seconds since the Unix epoch, as carried by the OIDC `auth_time` claim. */
  authTime?: number
  user?: boolean
  mfaEnabled?: boolean
  /** Seconds since the Unix epoch. Defaults to the current wall clock. */
  now?: number
}

export type PreflightStatus = 'allowed' | 'forbidden' | 'reauthentication' | 'unknown'

export interface PreflightResult {
  status: PreflightStatus
  requiredScopes: string[]
  acrValues?: string
  maxAge?: number
}
