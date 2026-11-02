import {
  Button,
  Dropdown,
  Label,
  useTheme,
} from '@heroui/react'
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
import { useEffect } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { useLocale, useTranslator, type LocalePreference } from '#/lib/i18n'

function isThemePreference(value: string): value is 'system' | 'light' | 'dark' {
  return value === 'system' || value === 'light' || value === 'dark'
}

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
    <Dropdown>
      <Button
        variant="ghost"
        size="sm"
        aria-label={`${t('language')}: ${label}`}
        className="gap-1 px-2"
      >
        <Languages className="size-4 text-muted" aria-hidden="true" />
        <span className="hidden sm:inline">{label}</span>
        <ChevronDown className="hidden size-3.5 text-muted sm:inline" aria-hidden="true" />
      </Button>
      <Dropdown.Popover placement="bottom end" className="min-w-48">
        <Dropdown.Menu aria-label={t('language')} onAction={(key) => choose(String(key))}>
          {items.map(({ id, label: itemLabel }) => (
            <Dropdown.Item key={id} id={id} textValue={itemLabel}>
              <Label>{itemLabel}</Label>
              {preference === id ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  )
}

export function ThemeMenu() {
  const t = useTranslator()
  const { theme, setTheme } = useTheme()
  const current = isThemePreference(theme) ? theme : 'system'
  const options = [
    { id: 'system' as const, label: t('themeSystem'), icon: Monitor },
    { id: 'light' as const, label: t('themeLight'), icon: Sun },
    { id: 'dark' as const, label: t('themeDark'), icon: Moon },
  ]
  const currentLabel = options.find((option) => option.id === current)?.label ?? t('themeSystem')
  const Icon = options.find((option) => option.id === current)?.icon ?? Monitor

  useEffect(() => {
    if (!isThemePreference(theme)) setTheme('system')
  }, [setTheme, theme])

  return (
    <Dropdown>
      <Button
        isIconOnly
        variant="ghost"
        size="sm"
        aria-label={`${t('theme')}: ${currentLabel}`}
      >
        <Icon className="size-4 text-muted" aria-hidden="true" />
      </Button>
      <Dropdown.Popover placement="bottom end" className="min-w-48">
        <Dropdown.Menu
          aria-label={t('theme')}
          onAction={(key) => {
            if (typeof key === 'string' && isThemePreference(key)) setTheme(key)
          }}
        >
          {options.map(({ id, label, icon: OptionIcon }) => (
            <Dropdown.Item key={id} id={id} textValue={label}>
              <OptionIcon className="size-4 text-muted" aria-hidden="true" />
              <Label>{label}</Label>
              {current === id ? <Check className="ms-auto size-4" aria-hidden="true" /> : null}
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
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
    <Dropdown>
      <Button
        variant="ghost"
        size="sm"
        aria-label={label}
        className="h-10 max-w-64 gap-2 px-1.5"
      >
        <AccountAvatar name={name} picture={picture} label={avatarLabel} size="sm" />
        <span className="hidden min-w-0 text-start sm:block">
          <span className="block truncate text-sm font-medium">{name}</span>
          <span className="block truncate text-xs font-normal text-muted">{email}</span>
        </span>
        <ChevronDown className="hidden size-3.5 text-muted sm:block" aria-hidden="true" />
      </Button>
      <Dropdown.Popover placement="bottom end" className="min-w-56">
        <Dropdown.Menu
          aria-label={label}
          onAction={(key) => {
            if (key === 'signout') onSignOut()
          }}
        >
          <Dropdown.Item id="account-center" href={accountUrl} textValue={t('accountCenter')}>
            <ExternalLink className="size-4 text-muted" aria-hidden="true" />
            <Label>{t('accountCenter')}</Label>
          </Dropdown.Item>
          <Dropdown.Item id="signout" textValue={t('signOut')} className="text-danger">
            <LogOut className="size-4" aria-hidden="true" />
            <Label>{t('signOut')}</Label>
          </Dropdown.Item>
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  )
}
