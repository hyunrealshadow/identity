export interface BusinessErrorResponse {
  error: {
    code: number
    message: string
  }
}

export interface AccountItem {
  id: string
  name: string
  email: string
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
}

export interface LoginStatusResponse {
  id: string
  status: string
  user?: UserDisplayInfo
  prompt: string
  ui_locales?: Array<string>
  continue_uri?: string
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
  client_uri?: string
  scopes: Array<ScopeDisplay>
  csrf_token: string
  ui_locales?: Array<string>
}

export interface ConsentApiResponse {
  status: 'approved' | 'denied'
  continue_uri?: string
  error?: string
}

export interface EnhancedNavigationResponse {
  redirect: string
}
