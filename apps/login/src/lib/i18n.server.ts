import { getRequestHeader } from '@tanstack/react-start/server'

import { resolveLocale } from './i18n'

export function requestLocale(uiLocales?: readonly string[]) {
  return resolveLocale({
    uiLocales,
    acceptLanguage: getRequestHeader('accept-language'),
  })
}

export function formLocale(request: Request, value: FormDataEntryValue | null) {
  return resolveLocale({
    uiLocales: typeof value === 'string' ? value.split(' ') : undefined,
    acceptLanguage: request.headers.get('accept-language'),
  })
}
