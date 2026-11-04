import type { LocationRewrite } from '@tanstack/react-router'

/** Console deployment prefix without a trailing slash, for example `/console`. */
export const BASE_PATH = import.meta.env.BASE_URL.replace(/\/+$/, '')

/** Canonical Console home address. The prefix itself never carries a trailing slash. */
export const BASE_HREF = BASE_PATH || '/'

export function isWithinBasePath(pathname: string): boolean {
  return !BASE_PATH || pathname === BASE_PATH || pathname.startsWith(`${BASE_PATH}/`)
}

/**
 * Maps browser paths to router paths. Unlike the router's built-in basepath,
 * the home route is written as `/console` rather than `/console/`.
 */
export const basePathRewrite: LocationRewrite = {
  input: ({ url }) => {
    if (!BASE_PATH) return url
    if (url.pathname === BASE_PATH || url.pathname === `${BASE_PATH}/`) {
      url.pathname = '/'
    } else if (url.pathname.startsWith(`${BASE_PATH}/`)) {
      url.pathname = url.pathname.slice(BASE_PATH.length)
    }
    return url
  },
  output: ({ url }) => {
    if (!BASE_PATH) return url
    url.pathname = url.pathname === '/' ? BASE_PATH : `${BASE_PATH}${url.pathname}`
    return url
  },
}
