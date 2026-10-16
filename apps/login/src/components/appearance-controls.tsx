import { Button, Dropdown, Label } from '@heroui/react'
import { useRouterState } from '@tanstack/react-router'
import { Check, ChevronDown, Monitor, Moon, Sun } from 'lucide-react'
import { useEffect, useState } from 'react'

import {
  applyTheme,
  isThemePreference,
  storedThemePreference,
  THEME_STORAGE_KEY,
  type ThemePreference,
} from '#/lib/appearance'
import { translate, type Locale } from '#/lib/i18n'
import { BROWSER_LOCALE_VALUE } from '#/lib/account-locale'

type LanguagePreference = Locale | typeof BROWSER_LOCALE_VALUE

export function AppearanceControls({ locale }: { locale: Locale }) {
  const pageTheme = useRouterState({
    select: (state) => {
      for (const match of [...state.matches].reverse()) {
        const data = match.loaderData as { theme?: unknown } | undefined
        if (isThemePreference(data?.theme)) return data.theme
      }
      return 'system' as const
    },
  })
  const currentHref = useRouterState({ select: (state) => state.location.href })
  const uiLocales = useRouterState({
    select: (state) => {
      for (const match of [...state.matches].reverse()) {
        const data = match.loaderData as { uiLocales?: string } | undefined
        if (typeof data?.uiLocales === 'string') return data.uiLocales
      }
      return ''
    },
  })
  const [theme, setTheme] = useState<ThemePreference>(pageTheme)
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  const languagePreference = new URL(currentHref, 'https://identity.invalid')
    .searchParams.get('ui_locales') ?? uiLocales
  const followsBrowser = !languagePreference || languagePreference === BROWSER_LOCALE_VALUE
  const languageLabel = followsBrowser ? t('accountLocaleBrowser') : locale === 'zh-CN' ? '简体中文' : 'English'

  function hrefWithLocale(nextLocale: LanguagePreference) {
    const url = new URL(currentHref, 'https://identity.invalid')
    // Keep an explicit browser choice instead of restoring the flow's ui_locales.
    url.searchParams.set('ui_locales', nextLocale)
    return `${url.pathname}${url.search}${url.hash}`
  }

  useEffect(() => {
    const saved = storedThemePreference(localStorage.getItem(THEME_STORAGE_KEY))
    setTheme(saved)
    applyTheme(saved)
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const followSystem = () => {
      if (storedThemePreference(localStorage.getItem(THEME_STORAGE_KEY)) !== 'system') return
      applyTheme('system')
    }
    media.addEventListener('change', followSystem)
    return () => media.removeEventListener('change', followSystem)
  }, [])

  function changeLocale(nextLocale: LanguagePreference) {
    window.location.assign(hrefWithLocale(nextLocale))
  }

  function changeTheme(next: ThemePreference) {
    if (next === 'system') {
      localStorage.removeItem(THEME_STORAGE_KEY)
      document.cookie = `${THEME_STORAGE_KEY}=; Path=/; Max-Age=0; SameSite=Lax; Secure`
    } else {
      localStorage.setItem(THEME_STORAGE_KEY, next)
      document.cookie = `${THEME_STORAGE_KEY}=${next}; Path=/; Max-Age=31536000; SameSite=Lax; Secure`
    }
    applyTheme(next)
    setTheme(next)
  }

  const themeOptions = [
    { id: 'system', label: t('accountThemeSystem'), icon: Monitor },
    { id: 'light', label: t('accountThemeLight'), icon: Sun },
    { id: 'dark', label: t('accountThemeDark'), icon: Moon },
  ] as const
  const ThemeIcon = themeOptions.find((option) => option.id === theme)?.icon ?? Monitor

  return (
    <>
      <div className="js-only absolute right-4 top-4 z-10 flex items-center gap-1 rounded-field border border-border bg-surface/90 p-1 shadow-sm backdrop-blur sm:right-6 sm:top-6">
        <Dropdown>
          <Button
            variant="ghost"
            aria-label={`${t('language')}: ${languageLabel}`}
            className="h-8 min-h-8 gap-1 px-2 text-xs font-medium"
          >
            {languageLabel}
            <ChevronDown className="size-3.5 text-muted" aria-hidden="true" />
          </Button>
          <Dropdown.Popover placement="bottom end" className="min-w-32">
            <Dropdown.Menu
              aria-label={t('language')}
              onAction={(key) => {
                if (key === BROWSER_LOCALE_VALUE || key === 'en-US' || key === 'zh-CN') changeLocale(key)
              }}
            >
              <Dropdown.Item id={BROWSER_LOCALE_VALUE} textValue={t('accountLocaleBrowser')}>
                <Label>{t('accountLocaleBrowser')}</Label>
                {followsBrowser ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
              </Dropdown.Item>
              <Dropdown.Item id="en-US" textValue="English">
                <Label>English</Label>
                {!followsBrowser && locale === 'en-US' ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
              </Dropdown.Item>
              <Dropdown.Item id="zh-CN" textValue="简体中文">
                <Label>简体中文</Label>
                {!followsBrowser && locale === 'zh-CN' ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
              </Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
        <span className="h-4 w-px bg-separator" aria-hidden="true" />
        <Dropdown>
          <Button
            isIconOnly
            variant="ghost"
            aria-label={`${t('accountTheme')}: ${themeOptions.find((option) => option.id === theme)?.label}`}
            className="size-8 min-w-8"
          >
            <ThemeIcon className="size-4 shrink-0 text-muted" aria-hidden="true" />
          </Button>
          <Dropdown.Popover placement="bottom end" className="min-w-40">
            <Dropdown.Menu
              aria-label={t('accountTheme')}
              onAction={(key) => {
                if (typeof key === 'string' && isThemePreference(key)) changeTheme(key)
              }}
            >
              {themeOptions.map(({ id, label, icon: Icon }) => (
                <Dropdown.Item key={id} id={id} textValue={label}>
                  <Icon className="size-4 shrink-0 text-muted" aria-hidden="true" />
                  <Label>{label}</Label>
                  {theme === id ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
                </Dropdown.Item>
              ))}
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
      </div>

      <div className="no-js-only absolute right-4 top-4 z-10 flex items-start gap-1 sm:right-6 sm:top-6">
        <details name="appearance-preference" className="relative rounded-field border border-border bg-surface/95 shadow-sm">
          <summary className="flex h-10 cursor-pointer list-none items-center gap-1 px-3 text-xs font-medium [&::-webkit-details-marker]:hidden">
            {languageLabel}
            <span aria-hidden="true">▾</span>
          </summary>
          <div className="absolute right-0 mt-1 grid min-w-32 gap-1 rounded-field border border-border bg-surface p-1 shadow-lg">
            <a className="flex items-center gap-2 rounded-field px-3 py-2 text-xs hover:bg-surface-secondary" href={hrefWithLocale(BROWSER_LOCALE_VALUE)}>
              <span>{t('accountLocaleBrowser')}</span>
              {followsBrowser ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
            </a>
            <a className="flex items-center gap-2 rounded-field px-3 py-2 text-xs hover:bg-surface-secondary" href={hrefWithLocale('en-US')}>
              <span>English</span>
              {!followsBrowser && locale === 'en-US' ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
            </a>
            <a className="flex items-center gap-2 rounded-field px-3 py-2 text-xs hover:bg-surface-secondary" href={hrefWithLocale('zh-CN')}>
              <span>简体中文</span>
              {!followsBrowser && locale === 'zh-CN' ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
            </a>
          </div>
        </details>
        <details name="appearance-preference" className="relative rounded-field border border-border bg-surface/95 shadow-sm">
          <summary className="flex size-10 cursor-pointer list-none items-center justify-center [&::-webkit-details-marker]:hidden" aria-label={t('accountTheme')}>
            <ThemeIcon className="size-4 text-muted" aria-hidden="true" />
          </summary>
          <div className="absolute right-0 mt-1 grid min-w-40 gap-1 rounded-field border border-border bg-surface p-1 shadow-lg">
            {themeOptions.map(({ id, label, icon: Icon }) => (
              <form key={id} action="/appearance" method="post">
                <input type="hidden" name="theme" value={id} />
                <input type="hidden" name="return_to" value={currentHref} />
                <button type="submit" className="flex w-full cursor-pointer items-center gap-2 rounded-field px-3 py-2 text-left text-xs hover:bg-surface-secondary">
                  <Icon className="size-4 text-muted" aria-hidden="true" />
                  <span>{label}</span>
                  {theme === id ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
                </button>
              </form>
            ))}
          </div>
        </details>
      </div>
    </>
  )
}
