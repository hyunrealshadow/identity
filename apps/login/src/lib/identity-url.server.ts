import { configuredApplicationUrl } from './application-origins.server'

const DEFAULT_IDENTITY_URL = 'https://localhost:5150'

function configuredUrl(name: string, fallback: string, allowHttp: boolean) {
  const url = new URL(process.env[name] ?? fallback)
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new Error(`${name} must use HTTPS${allowHttp ? ' or HTTP' : ''}`)
  }
  return url
}

export function publicIdentityApiUrl() {
  const installed = configuredApplicationUrl('domain')
  if (installed) return new URL(installed)
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Identity public address is unavailable until installation completes')
  }
  return new URL(DEFAULT_IDENTITY_URL)
}

export function backchannelIdentityApiUrl() {
  if (!process.env.IDENTITY_BACKCHANNEL_API_URL) return publicIdentityApiUrl()
  return configuredUrl(
    'IDENTITY_BACKCHANNEL_API_URL',
    DEFAULT_IDENTITY_URL,
    process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP === 'true',
  )
}

export function backchannelIdentityGraphqlUrl() {
  if (!process.env.IDENTITY_BACKCHANNEL_GRAPHQL_URL) {
    return backchannelIdentityApiUrl()
  }
  return configuredUrl(
    'IDENTITY_BACKCHANNEL_GRAPHQL_URL',
    DEFAULT_IDENTITY_URL,
    process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP === 'true',
  )
}
