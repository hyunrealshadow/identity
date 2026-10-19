import { BROWSER_LOCALE_VALUE } from './account-locale'

/** The absence of a URL preference means browser language negotiation. */
export function withUiLocales(href: string, preference?: string) {
  const url = new URL(href, 'https://identity.invalid')
  if (preference && preference !== BROWSER_LOCALE_VALUE) {
    url.searchParams.set('ui_locales', preference)
  } else {
    url.searchParams.delete('ui_locales')
  }
  return href.startsWith('/') && !href.startsWith('//')
    ? `${url.pathname}${url.search}${url.hash}`
    : url.href
}
