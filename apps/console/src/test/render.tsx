import { render, type RenderOptions } from '@testing-library/react'
import type { ReactElement, ReactNode } from 'react'

import { LocaleProvider, type Locale } from '#/lib/i18n'

export function LocaleTestProvider({
  locale = 'en-US',
  children,
}: {
  locale?: Locale
  children: ReactNode
}) {
  // Explicit provider injection keeps fixtures independent of production
  // account-preference resolution and stale browser storage.
  return <LocaleProvider initialLocale={locale}>{children}</LocaleProvider>
}

export function renderWithLocale(
  ui: ReactElement,
  options: { locale?: Locale } & Omit<RenderOptions, 'wrapper'> = {},
) {
  const { locale = 'en-US', ...renderOptions } = options
  return render(ui, {
    ...renderOptions,
    wrapper: ({ children }) => <LocaleTestProvider locale={locale}>{children}</LocaleTestProvider>,
  })
}
