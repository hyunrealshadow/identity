import { Button, Label, ListBox, Select } from '@heroui/react'
import { DatePickerField } from '@identity/ui/date-picker-field'
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
      clearLabel={t('accountDateClear')}
      timeZone={timeZone}
      locale={locale}
    />
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
    <Select
      fullWidth
      name="locale"
      defaultValue={account.locale ?? BROWSER_LOCALE_VALUE}
      placeholder={t('accountLocaleBrowser')}
    >
      <Label>{t('accountLocale')}</Label>
      <Select.Trigger>
        <Select.Value />
        <Select.Indicator />
      </Select.Trigger>
      <Select.Popover>
        <ListBox>
          <ListBox.Item
            id={BROWSER_LOCALE_VALUE}
            textValue={t('accountLocaleBrowser')}
          >
            {t('accountLocaleBrowser')}
            <ListBox.ItemIndicator />
          </ListBox.Item>
          <ListBox.Item id="en-US" textValue="English (United States)">
            English (United States)
            <ListBox.ItemIndicator />
          </ListBox.Item>
          <ListBox.Item id="zh-CN" textValue="中文（简体）">
            中文（简体）
            <ListBox.ItemIndicator />
          </ListBox.Item>
        </ListBox>
      </Select.Popover>
    </Select>
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
    <Select fullWidth name="theme" defaultValue={preference}>
      <Label>{t('accountTheme')}</Label>
      <Select.Trigger>
        <Select.Value />
        <Select.Indicator />
      </Select.Trigger>
      <Select.Popover>
        <ListBox>
          <ListBox.Item id="system" textValue={t('accountThemeSystem')}>
            {t('accountThemeSystem')}
            <ListBox.ItemIndicator />
          </ListBox.Item>
          <ListBox.Item id="light" textValue={t('accountThemeLight')}>
            {t('accountThemeLight')}
            <ListBox.ItemIndicator />
          </ListBox.Item>
          <ListBox.Item id="dark" textValue={t('accountThemeDark')}>
            {t('accountThemeDark')}
            <ListBox.ItemIndicator />
          </ListBox.Item>
        </ListBox>
      </Select.Popover>
    </Select>
  )
}
