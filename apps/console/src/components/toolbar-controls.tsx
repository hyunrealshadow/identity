import { Button } from '@identity/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import {
  Check,
  ChevronDown,
  ExternalLink,
  Languages,
  LogOut,
  Monitor,
  Moon,
  Sun,
} from 'lucide-react'
import { useEffect, useState } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { useLocale, useTranslator, type LocalePreference } from '#/lib/i18n'
import {
  applyTheme,
  isThemePreference,
  storedThemePreference,
  THEME_STORAGE_KEY,
  type ThemePreference,
} from '#/lib/theme'

export function LanguageMenu() {
  const t = useTranslator()
  const { locale, preference, setLocale } = useLocale()

  const label =
    preference === 'browser'
      ? t('languageBrowser')
      : locale === 'zh-CN'
        ? t('languageChinese')
        : t('languageEnglish')

  function choose(next: string) {
    if (next === 'browser' || next === 'en-US' || next === 'zh-CN') {
      setLocale(next as LocalePreference)
    }
  }

  const items: Array<{ id: LocalePreference; label: string }> = [
    { id: 'browser', label: t('languageBrowser') },
    { id: 'en-US', label: t('languageEnglish') },
    { id: 'zh-CN', label: t('languageChinese') },
  ]

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            aria-label={`${t('language')}: ${label}`}
            className="gap-1 px-2"
          />
        }
      >
        <Languages className="size-4 text-muted-foreground" aria-hidden="true" />
        <span className="hidden sm:inline">{label}</span>
        <ChevronDown className="hidden size-3.5 text-muted-foreground sm:inline" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-48">
        {items.map(({ id, label: itemLabel }) => (
          <DropdownMenuItem key={id} onClick={() => choose(id)}>
            {itemLabel}
            {preference === id ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function ThemeMenu() {
  const t = useTranslator()
  const [theme, setThemeState] = useState<ThemePreference>(() => {
    try {
      return storedThemePreference(window.localStorage.getItem(THEME_STORAGE_KEY))
    } catch {
      return 'system'
    }
  })
  const options = [
    { id: 'system' as const, label: t('themeSystem'), icon: Monitor },
    { id: 'light' as const, label: t('themeLight'), icon: Sun },
    { id: 'dark' as const, label: t('themeDark'), icon: Moon },
  ]
  const currentLabel = options.find((option) => option.id === theme)?.label ?? t('themeSystem')
  const Icon = options.find((option) => option.id === theme)?.icon ?? Monitor

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  function choose(value: string) {
    if (!isThemePreference(value)) return
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, value)
    } catch {
      // The preference still applies for this page when storage is unavailable.
    }
    setThemeState(value)
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={`${t('theme')}: ${currentLabel}`}
          />
        }
      >
        <Icon className="size-4 text-muted-foreground" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-48">
        {options.map(({ id, label, icon: OptionIcon }) => (
          <DropdownMenuItem key={id} onClick={() => choose(id)}>
            <OptionIcon className="size-4 text-muted-foreground" aria-hidden="true" />
            {label}
            {theme === id ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function AccountMenu({
  name,
  email,
  picture,
  accountUrl,
  onSignOut,
}: {
  name: string
  email: string
  picture?: string | null
  accountUrl: string
  onSignOut: () => void
}) {
  const t = useTranslator()
  const label = t('accountMenuFor', { name })
  const avatarLabel = t('accountAvatarLabel', { name })

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            aria-label={label}
            className="h-10 max-w-64 gap-2 px-1.5"
          />
        }
      >
        <AccountAvatar name={name} picture={picture} label={avatarLabel} />
        <span className="hidden min-w-0 text-start sm:block">
          <span className="block truncate text-sm font-medium">{name}</span>
          <span className="block truncate text-xs font-normal text-muted-foreground">{email}</span>
        </span>
        <ChevronDown className="hidden size-3.5 text-muted-foreground sm:block" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-56">
        <DropdownMenuItem render={<a href={accountUrl} />}>
          <ExternalLink className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('accountCenter')}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onClick={onSignOut}>
          <LogOut className="size-4" aria-hidden="true" />
          {t('signOut')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
