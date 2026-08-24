import { Button, Calendar, DateField, DatePicker, FieldError, Label, ListBox, Select } from '@heroui/react'
import { parseDate } from '@internationalized/date'
import { createFileRoute } from '@tanstack/react-router'

import { AccountActionForm } from '#/components/account-action-form'
import { PageHeading, ProfileField, SettingsCard } from '#/components/account-settings'
import { BROWSER_LOCALE_VALUE } from '#/lib/account-locale'
import type { ThemePreference } from '#/lib/appearance'
import { translate } from '#/lib/i18n'
import { useAccount } from './route'

export const Route = createFileRoute('/account/profile')({ component: ProfilePage })

function ProfilePage() {
  const { locale, data, flash } = useAccount()
  const account = data.viewer.account
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  return (
    <>
      <PageHeading title={t('accountProfile')} description={t('accountProfileDescription')} />
      <SettingsCard title={t('accountProfile')} description={t('accountProfileFieldsDescription')}>
        <AccountActionForm action="update-profile" requestFailedMessage={t('accountRequestFailed')} className="grid gap-4 sm:grid-cols-2">
          <ProfileField name="given_name" label={t('accountGivenName')} value={account.givenName} error={flash.fields?.given_name} />
          <ProfileField name="family_name" label={t('accountFamilyName')} value={account.familyName} error={flash.fields?.family_name} />
          <div className="sm:col-span-2"><ProfileField name="nickname" label={t('accountNickname')} value={account.nickname} error={flash.fields?.nickname} /></div>
          <div className="sm:col-span-2"><ProfileField name="website" label={t('accountWebsite')} value={account.website} error={flash.fields?.website} type="url" /></div>
          <ProfileDatePicker account={account} error={flash.fields?.birthdate} t={t} />
          <ProfileLocaleSelect account={account} t={t} />
          <ProfileThemeSelect account={account} t={t} />
          <div className="flex justify-end sm:col-span-2"><Button type="submit">{t('accountSaveProfile')}</Button></div>
        </AccountActionForm>
      </SettingsCard>
    </>
  )
}

type Account = ReturnType<typeof useAccount>['data']['viewer']['account']
type Translator = (key: Parameters<typeof translate>[1]) => string

function ProfileDatePicker({ account, error, t }: { account: Account; error?: string; t: Translator }) {
  return <DatePicker className="w-full" name="birthdate" defaultValue={parseOptionalDate(account.birthdate)} isInvalid={Boolean(error)}><Label>{t('accountBirthdate')}</Label><DateField.Group fullWidth><DateField.Input>{(segment) => <DateField.Segment segment={segment} />}</DateField.Input><DateField.Suffix><DatePicker.Trigger><DatePicker.TriggerIndicator /></DatePicker.Trigger></DateField.Suffix></DateField.Group><FieldError>{error}</FieldError><DatePicker.Popover><Calendar aria-label={t('accountBirthdate')}><Calendar.Header><Calendar.YearPickerTrigger><Calendar.YearPickerTriggerHeading /><Calendar.YearPickerTriggerIndicator /></Calendar.YearPickerTrigger><Calendar.NavButton slot="previous" /><Calendar.NavButton slot="next" /></Calendar.Header><Calendar.Grid><Calendar.GridHeader>{(day) => <Calendar.HeaderCell>{day}</Calendar.HeaderCell>}</Calendar.GridHeader><Calendar.GridBody>{(date) => <Calendar.Cell date={date} />}</Calendar.GridBody></Calendar.Grid><Calendar.YearPickerGrid><Calendar.YearPickerGridBody>{({ year }) => <Calendar.YearPickerCell year={year} />}</Calendar.YearPickerGridBody></Calendar.YearPickerGrid></Calendar></DatePicker.Popover></DatePicker>
}

function ProfileLocaleSelect({ account, t }: { account: Account; t: Translator }) {
  return <Select fullWidth name="locale" defaultValue={account.locale ?? BROWSER_LOCALE_VALUE} placeholder={t('accountLocaleBrowser')}><Label>{t('accountLocale')}</Label><Select.Trigger><Select.Value /><Select.Indicator /></Select.Trigger><Select.Popover><ListBox><ListBox.Item id={BROWSER_LOCALE_VALUE} textValue={t('accountLocaleBrowser')}>{t('accountLocaleBrowser')}<ListBox.ItemIndicator /></ListBox.Item><ListBox.Item id="en-US" textValue="English (United States)">English (United States)<ListBox.ItemIndicator /></ListBox.Item><ListBox.Item id="zh-CN" textValue="中文（简体）">中文（简体）<ListBox.ItemIndicator /></ListBox.Item></ListBox></Select.Popover></Select>
}

function ProfileThemeSelect({ account, t }: { account: Account; t: Translator }) {
  const preference: ThemePreference = account.theme === 'light' || account.theme === 'dark' ? account.theme : 'system'
  return <Select fullWidth name="theme" defaultValue={preference}><Label>{t('accountTheme')}</Label><Select.Trigger><Select.Value /><Select.Indicator /></Select.Trigger><Select.Popover><ListBox><ListBox.Item id="system" textValue={t('accountThemeSystem')}>{t('accountThemeSystem')}<ListBox.ItemIndicator /></ListBox.Item><ListBox.Item id="light" textValue={t('accountThemeLight')}>{t('accountThemeLight')}<ListBox.ItemIndicator /></ListBox.Item><ListBox.Item id="dark" textValue={t('accountThemeDark')}>{t('accountThemeDark')}<ListBox.ItemIndicator /></ListBox.Item></ListBox></Select.Popover></Select>
}

function parseOptionalDate(value?: string) {
  if (!value) return undefined
  try {
    return parseDate(value)
  } catch {
    return undefined
  }
}
