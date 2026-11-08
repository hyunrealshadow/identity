import { Button } from '@identity/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import { Separator } from '@identity/ui/components/separator'
import { useRouterState } from '@tanstack/react-router'
import { Check, ChevronDown, Monitor, Moon, Sun } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import {
  applyTheme,
  isThemePreference,
  storedThemePreference,
  THEME_STORAGE_KEY,
  type ThemePreference,
} from '#/lib/appearance'
import { translate, type Locale } from '#/lib/i18n'
import { BROWSER_LOCALE_VALUE } from '#/lib/account-locale'
import { withUiLocales } from '#/lib/ui-locale'

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
  // Menus open below the whole control, not below the inner button: the pill's
  // padding would otherwise let the popup start inside its border.
  const controlsRef = useRef<HTMLDivElement>(null)
  const [theme, setTheme] = useState<ThemePreference>(pageTheme)
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  const languagePreference = new URL(currentHref, 'https://identity.invalid')
    .searchParams.get('ui_locales')
  const followsBrowser = !languagePreference || languagePreference === BROWSER_LOCALE_VALUE
  const languageLabel = followsBrowser ? t('accountLocaleBrowser') : locale === 'zh-CN' ? '简体中文' : 'English'

  function hrefWithLocale(nextLocale: LanguagePreference) {
    return withUiLocales(currentHref, nextLocale)
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
    <div className="flex shrink-0 items-center justify-end gap-1">
      <div ref={controlsRef} className="js-only flex items-center gap-1 rounded-lg border bg-card/90 p-1 shadow-xs backdrop-blur">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={(
              <Button
                variant="ghost"
                size="sm"
                aria-label={`${t('language')}: ${languageLabel}`}
                className="gap-1 px-2 text-xs"
              />
            )}
          >
            {languageLabel}
            <ChevronDown className="size-3.5 text-muted-foreground" aria-hidden="true" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" anchor={() => controlsRef.current} className="min-w-36">
            <DropdownMenuRadioGroup
              aria-label={t('language')}
              value={followsBrowser ? BROWSER_LOCALE_VALUE : locale}
              onValueChange={(key) => {
                if (key === BROWSER_LOCALE_VALUE || key === 'en-US' || key === 'zh-CN') changeLocale(key)
              }}
            >
              <DropdownMenuRadioItem value={BROWSER_LOCALE_VALUE}>{t('accountLocaleBrowser')}</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="en-US">English</DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="zh-CN">简体中文</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>
        <Separator orientation="vertical" className="data-vertical:h-4 data-vertical:self-center" />
        <DropdownMenu>
          <DropdownMenuTrigger
            render={(
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`${t('accountTheme')}: ${themeOptions.find((option) => option.id === theme)?.label}`}
              />
            )}
          >
            <ThemeIcon className="text-muted-foreground" aria-hidden="true" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" anchor={() => controlsRef.current} className="min-w-36">
            <DropdownMenuRadioGroup
              aria-label={t('accountTheme')}
              value={theme}
              onValueChange={(key) => {
                if (typeof key === 'string' && isThemePreference(key)) changeTheme(key)
              }}
            >
              {themeOptions.map(({ id, label, icon: Icon }) => (
                <DropdownMenuRadioItem key={id} value={id}>
                  <Icon className="text-muted-foreground" aria-hidden="true" />
                  {label}
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="no-js-only relative flex items-center gap-1 rounded-lg border bg-card/90 p-1 shadow-xs">
        <details name="appearance-preference">
          <summary className="flex h-8 cursor-pointer list-none items-center gap-1 rounded-md px-2 text-xs font-medium hover:bg-muted [&::-webkit-details-marker]:hidden">
            {languageLabel}
            <ChevronDown className="size-3.5 text-muted-foreground" aria-hidden="true" />
          </summary>
          <div className="appearance-menu absolute -inset-x-px top-full z-50 mt-1 grid rounded-md bg-popover p-1 text-popover-foreground shadow-md ring-1 ring-foreground/10">
            <a className="relative flex cursor-pointer items-center gap-2 rounded-sm py-1.5 pr-8 pl-2 text-sm hover:bg-accent hover:text-accent-foreground" href={hrefWithLocale(BROWSER_LOCALE_VALUE)}>
              <span>{t('accountLocaleBrowser')}</span>
              {followsBrowser ? <Check className="pointer-events-none absolute right-2 size-4" aria-hidden="true" /> : null}
            </a>
            <a className="relative flex cursor-pointer items-center gap-2 rounded-sm py-1.5 pr-8 pl-2 text-sm hover:bg-accent hover:text-accent-foreground" href={hrefWithLocale('en-US')}>
              <span>English</span>
              {!followsBrowser && locale === 'en-US' ? <Check className="pointer-events-none absolute right-2 size-4" aria-hidden="true" /> : null}
            </a>
            <a className="relative flex cursor-pointer items-center gap-2 rounded-sm py-1.5 pr-8 pl-2 text-sm hover:bg-accent hover:text-accent-foreground" href={hrefWithLocale('zh-CN')}>
              <span>简体中文</span>
              {!followsBrowser && locale === 'zh-CN' ? <Check className="pointer-events-none absolute right-2 size-4" aria-hidden="true" /> : null}
            </a>
          </div>
        </details>
        <Separator orientation="vertical" className="data-vertical:h-4 data-vertical:self-center" />
        <details name="appearance-preference">
          <summary className="flex size-8 cursor-pointer list-none items-center justify-center rounded-md hover:bg-muted [&::-webkit-details-marker]:hidden" aria-label={t('accountTheme')}>
            <ThemeIcon className="size-4 text-muted-foreground" aria-hidden="true" />
          </summary>
          <div className="appearance-menu absolute -inset-x-px top-full z-50 mt-1 grid rounded-md bg-popover p-1 text-popover-foreground shadow-md ring-1 ring-foreground/10">
            {themeOptions.map(({ id, label, icon: Icon }) => (
              <form key={id} action="/appearance" method="post">
                <input type="hidden" name="theme" value={id} />
                <input type="hidden" name="return_to" value={currentHref} />
                <button type="submit" className="relative flex w-full cursor-pointer items-center gap-2 rounded-sm py-1.5 pr-8 pl-2 text-left text-sm hover:bg-accent hover:text-accent-foreground">
                  <Icon className="size-4 text-muted-foreground" aria-hidden="true" />
                  <span>{label}</span>
                  {theme === id ? <Check className="pointer-events-none absolute right-2 size-4" aria-hidden="true" /> : null}
                </button>
              </form>
            ))}
          </div>
        </details>
      </div>
    </div>
  )
}
