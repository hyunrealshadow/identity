import { QueryClientProvider } from '@tanstack/react-query'
import {
  render,
  renderHook,
  type RenderHookOptions,
  type RenderOptions,
} from '@testing-library/react'
import type { ReactElement, ReactNode } from 'react'
import { useState } from 'react'

import { createQueryClient } from '#/lib/graphql/query-client'
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
    wrapper: ({ children }) => (
      <QueryTestProvider>
        <LocaleTestProvider locale={locale}>{children}</LocaleTestProvider>
      </QueryTestProvider>
    ),
  })
}

/** Fresh query client per test: cached reads never leak between fixtures. */
export function QueryTestProvider({ children }: { children: ReactNode }) {
  const [client] = useState(() => {
    const created = createQueryClient()
    created.setDefaultOptions({
      queries: { retry: false, staleTime: 0, gcTime: Infinity },
      mutations: { retry: false },
    })
    return created
  })
  return (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

export function renderHookWithLocale<TResult, TProps>(
  hook: (props: TProps) => TResult,
  options: { locale?: Locale } & Omit<RenderHookOptions<TProps>, 'wrapper'> = {},
) {
  const { locale = 'en-US', ...hookOptions } = options
  return renderHook(hook, {
    ...hookOptions,
    wrapper: ({ children }) => (
      <QueryTestProvider>
        <LocaleTestProvider locale={locale}>{children}</LocaleTestProvider>
      </QueryTestProvider>
    ),
  })
}
