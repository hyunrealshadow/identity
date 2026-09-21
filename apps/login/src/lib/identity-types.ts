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

export interface InstallationStatusResponse {
  installed: boolean
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

export interface LoginStatusResponse {
  id: string
  status: string
  user?: UserDisplayInfo
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
  credential_types: Array<string>
  user: UserDisplayInfo
}

export interface SelectAccountResponse {
  status: 'ok'
  continue_uri: string
  sessions: Array<string>
}

export interface ChallengeResponse {
  status: 'authenticated' | 'mfa_required'
  continue_uri?: string
  sessions?: Array<string>
}

export interface ScopeDisplay {
  name: string
  description: string
  essential: boolean
}

export interface ConsentPageData {
  login_id: string
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
  account: {
    name: string
    email: string
    picture?: string
  }
}

export interface ConsentApiResponse {
  status: 'approved' | 'denied'
  continue_uri?: string
  error?: string
}

export interface EnhancedNavigationResponse {
  redirect: string
}
