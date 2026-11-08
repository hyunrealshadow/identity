import { Button } from '@identity/ui/components/button'
import { DatePickerField } from '@identity/ui/components/date-picker'
import { Field, FieldLabel } from '@identity/ui/components/field'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'
import { useAccountTimeZone } from '#/lib/time-zone'
import { createFileRoute } from '@tanstack/react-router'

import { TimeZoneSelect } from '#/components/time-zone-select'
import { AccountActionForm } from '#/components/account-action-form'
import {
  PageHeading,
  ProfileField,
  SettingsCard,
} from '#/components/account-settings'
import { BROWSER_LOCALE_VALUE } from '#/lib/account-locale'
import type { ThemePreference } from '#/lib/appearance'
import { translate } from '#/lib/i18n'
import { useAccount } from './route'

export const Route = createFileRoute('/account/profile')({
  component: ProfilePage,
})

function ProfilePage() {
  const { locale, data, flash } = useAccount()
  const account = data.account
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  return (
    <>
      <PageHeading
        title={t('accountProfile')}
        description={t('accountProfileDescription')}
      />
      <AccountActionForm
        action="update-profile"
        requestFailedMessage={t('accountRequestFailed')}
        className="grid gap-4"
      >
        <SettingsCard title={t('accountBasicInformation')}>
          <div className="grid gap-4 sm:grid-cols-2">
            <ProfileField
              name="given_name"
              label={t('accountGivenName')}
              value={account.givenName}
              error={flash.fields?.given_name}
            />
            <ProfileField
              name="family_name"
              label={t('accountFamilyName')}
              value={account.familyName}
              error={flash.fields?.family_name}
            />
            <ProfileField
              name="nickname"
              label={t('accountNickname')}
              value={account.nickname}
              error={flash.fields?.nickname}
            />
            <ProfileDatePicker
              account={account}
              error={flash.fields?.birthdate}
              t={t}
            />
            <div className="sm:col-span-2">
              <ProfileField
                name="website"
                label={t('accountWebsite')}
                value={account.website}
                error={flash.fields?.website}
                type="url"
              />
            </div>
          </div>
        </SettingsCard>
        <SettingsCard title={t('accountPreferences')}>
          <div className="grid gap-4 sm:grid-cols-2">
            <ProfileLocaleSelect account={account} t={t} />
            <ProfileThemeSelect account={account} t={t} />
            <TimeZoneSelect
              locale={locale}
              value={account.zoneInfo}
              error={flash.fields?.zone_info}
              t={t}
            />
          </div>
        </SettingsCard>
        <div className="flex justify-end">
          <Button type="submit">{t('accountSaveProfile')}</Button>
        </div>
      </AccountActionForm>
    </>
  )
}

type Account = ReturnType<typeof useAccount>['data']['account']
type Translator = (key: Parameters<typeof translate>[1]) => string

function ProfileDatePicker({
  account,
  error,
  t,
}: {
  account: Account
  error?: string
  t: Translator
}) {
  const timeZone = useAccountTimeZone(account.zoneInfo)
  const { locale } = useAccount()
  return (
    <DatePickerField
      name="birthdate"
      label={t('accountBirthdate')}
      defaultValue={account.birthdate}
      error={error}
      placeholder={t('accountDatePlaceholder')}
      clearLabel={t('accountDateClear')}
      timeZone={timeZone}
      locale={locale}
    />
  )
}

function PreferenceSelect({
  name,
  label,
  defaultValue,
  options,
}: {
  name: string
  label: string
  defaultValue: string
  options: Array<{ value: string; label: string }>
}) {
  const id = `profile-${name}`
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Select name={name} defaultValue={defaultValue} items={options}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </Field>
  )
}

function ProfileLocaleSelect({
  account,
  t,
}: {
  account: Account
  t: Translator
}) {
  return (
    <PreferenceSelect
      name="locale"
      label={t('accountLocale')}
      defaultValue={account.locale ?? BROWSER_LOCALE_VALUE}
      options={[
        { value: BROWSER_LOCALE_VALUE, label: t('accountLocaleBrowser') },
        { value: 'en-US', label: 'English (United States)' },
        { value: 'zh-CN', label: '中文（简体）' },
      ]}
    />
  )
}

function ProfileThemeSelect({
  account,
  t,
}: {
  account: Account
  t: Translator
}) {
  const preference: ThemePreference =
    account.theme === 'light' || account.theme === 'dark'
      ? account.theme
      : 'system'
  return (
    <PreferenceSelect
      name="theme"
      label={t('accountTheme')}
      defaultValue={preference}
      options={[
        { value: 'system', label: t('accountThemeSystem') },
        { value: 'light', label: t('accountThemeLight') },
        { value: 'dark', label: t('accountThemeDark') },
      ]}
    />
  )
}
