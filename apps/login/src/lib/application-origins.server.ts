export interface ApplicationOrigins {
  domain?: string | null
  login_domain?: string | null
  console_domain?: string | null
}

let applications: ApplicationOrigins = {}

export function applyApplicationOrigins(value: ApplicationOrigins | undefined) {
  applications = value ?? {}
}

export function configuredApplicationOrigin(kind: keyof ApplicationOrigins) {
  const value = configuredApplicationUrl(kind)
  return value ? new URL(value).origin : undefined
}

export function configuredApplicationUrl(kind: keyof ApplicationOrigins) {
  const value = applications[kind]
  return trustedHttpsUrl(
    kind === 'domain' && value && !value.includes('://')
      ? `https://${value}`
      : value,
  )
}

export function trustedHttpsOrigin(value: unknown): string | undefined {
  const url = trustedHttpsUrl(value)
  return url ? new URL(url).origin : undefined
}

function trustedHttpsUrl(value: unknown): string | undefined {
  if (typeof value !== 'string') return
  try {
    const url = new URL(value)
    if (
      url.protocol !== 'https:' ||
      url.hostname.includes('*') ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      return
    return url.toString()
  } catch {
    return
  }
}
