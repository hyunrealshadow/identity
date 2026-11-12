export interface BusinessErrorResponse {
  error: {
    code: number
    message: string
    fields?: Array<FieldErrorResponse>
  }
}

export interface FieldErrorResponse {
  field: string
  code: number
  message: string
}

/** JWA signing algorithms Identity can create a key for. */
export type SigningAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'ES256K'
  | 'EdDSA'

/** Keys Identity generates. */
export type KeyAlgorithm =
  | 'RSA_2048'
  | 'RSA_3072'
  | 'RSA_4096'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'ECDSA_P521'
  | 'ECDSA_SECP256K1'
  | 'ED25519'
  | 'ED448'
  | 'X25519'
  | 'X448'

export interface SigningAlgorithmOption {
  /** Submitted as `signing_algorithm`. */
  signing_algorithm: SigningAlgorithm
  /** Submitted as `key_algorithm`. */
  key_algorithm: KeyAlgorithm
  /** The key as an operator reads it, such as `ECDSA P-256`. */
  key_name: string
}

export interface InstallationStatusResponse {
  installed: boolean
  /** Present while uninstalled: algorithms the first signing key can use. */
  signing_algorithms?: SigningAlgorithmOption[]
}

export interface InstallResponse {
  status: 'installed'
}

export interface AccountItem {
  id: string
  name: string
  email: string
  picture?: string
  last_active_at?: string
}

export interface ActiveAccountsResponse {
  accounts: Array<AccountItem>
  csrf_token: string
  sessions: Array<string>
}

export interface UserDisplayInfo {
  name: string
  email: string
  picture?: string
}

export interface LoginClientDisplay {
  name: string
  logo_uri?: string | null
  policy_uri?: string | null
  tos_uri?: string | null
}

export interface LoginStatusResponse {
  client?: LoginClientDisplay
  id: string
  status: string
  user?: UserDisplayInfo
  preferred_credential_type?: string
  credential_types: Array<string>
  prompt: string
  requires_reauthentication: boolean
  login_hint?: string
  challenge_uri?: string
  ui_locales?: Array<string>
  continue_uri?: string
}

export interface RestartLoginResponse {
  id: string
}

export interface SwitchLoginResponse {
  id: string
}

export interface IdentifierResponse {
  id: string
  status: string
  preferred_credential_type?: string
  credential_types: Array<string>
  user: UserDisplayInfo
}

export interface SelectAccountResponse {
  status: 'ok'
  continue_uri: string
  sessions: Array<string>
}

export interface ChallengeResponse {
  preferred_credential_type?: string
  status: 'authenticated' | 'mfa_required'
  continue_uri?: string
  sessions?: Array<string>
}

export interface ScopeDisplay {
  code: string
  name: string
  names: Record<string, string>
  descriptions?: Record<string, string>
  description: string
  essential: boolean
  previously_granted?: boolean
}

export interface ConsentAccount {
  name: string
  email: string
  picture?: string
}

export interface ConsentPageData {
  login_id: string
  account: ConsentAccount
  client_name: string
  logo_uri?: string
  client_uri?: string
  scopes: Array<ScopeDisplay>
  csrf_token: string
  ui_locales?: Array<string>
}

export interface DeviceVerificationPageData {
  login_id: string
  user_code: string
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'consumed'
  consent_required: boolean
  client_name: string
  logo_uri?: string
  client_uri?: string
  scopes: Array<ScopeDisplay>
  csrf_token: string
  ui_locales?: Array<string>
  /** Session answering the request: the account the decision is recorded against. */
  account: ConsentAccount
}

export interface ConsentApiResponse {
  status: 'approved' | 'denied'
  continue_uri?: string
  error?: string
}

export interface EnhancedNavigationResponse {
  redirect: string
}
