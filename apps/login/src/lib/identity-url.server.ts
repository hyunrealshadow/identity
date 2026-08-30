const DEFAULT_IDENTITY_URL = 'https://localhost:5150'

function configuredUrl(name: string, fallback: string, allowHttp: boolean) {
  const url = new URL(process.env[name] ?? fallback)
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new Error(
      `${name} must use HTTPS${allowHttp ? ' or HTTP' : ''}`,
    )
  }
  return url
}

export function publicIdentityApiUrl() {
  return configuredUrl('IDENTITY_API_URL', DEFAULT_IDENTITY_URL, false)
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
