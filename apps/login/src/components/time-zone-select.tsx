import { Button } from '@identity/ui/components/button'
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
  ComboboxTrigger,
  ComboboxValue,
} from '@identity/ui/components/combobox'
import { Field, FieldError, FieldLabel } from '@identity/ui/components/field'
import { useEffect, useId, useMemo, useState } from 'react'

import type { Locale } from '#/lib/i18n'
import { translate } from '#/lib/i18n'
import {
  BROWSER_TIME_ZONE_VALUE,
  UTC_TIME_ZONE,
  browserTimeZone,
  initialTimeZoneValues,
  timeZoneSelectionValue,
  timeZoneValues,
} from '#/lib/time-zone'
import {
  matchesTimeZone,
  timeZoneOptions,
  type TimeZoneOption,
} from '#/lib/time-zone-options'

type Translator = (key: Parameters<typeof translate>[1]) => string
type SelectOption = TimeZoneOption & { detail: string }
export function TimeZoneSelect({
  value,
  error,
  t,
  locale,
}: {
  value?: string
  error?: string
  t: Translator
  locale: Locale
}) {
  const initial = useMemo(() => timeZoneSelectionValue(value), [value])
  const [selection, setSelection] = useState(initial)
  const [catalog, setCatalog] = useState<TimeZoneOption[]>(() =>
    initialTimeZoneValues(initial).map((id) => ({
      id,
      name: id,
      offset: '',
      offsetMinutes: 0,
      searchText: id,
    })),
  )
  const [localZone, setLocalZone] = useState<string>()
  const [open, setOpen] = useState(false)
  const triggerId = useId()
  const errorId = `${triggerId}-error`

  useEffect(() => {
    setSelection(initial)
  }, [initial])
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const zone = browserTimeZone()
      const date = new Date()
      setLocalZone(zone)
      const next = timeZoneOptions(
        [...new Set([...timeZoneValues(initial), zone])],
        locale,
        date,
      )
      setCatalog((previous) =>
        previous.length === next.length &&
        previous.every((option, index) => option === next[index])
          ? previous
          : next,
      )
    }, 0)
    return () => window.clearTimeout(timer)
  }, [initial, locale, open])

  const browserLabel = t('accountTimeZoneBrowser')
  const localLabel = t('accountTimeZoneLocal')
  const options = useMemo<SelectOption[]>(() => {
    const local = catalog.find((option) => option.id === localZone)
    const browser: SelectOption = {
      id: BROWSER_TIME_ZONE_VALUE,
      name: browserLabel,
      detail: local ? `${local.name} - ${local.id}` : '',
      offset: local?.offset ?? '',
      offsetMinutes: local?.offsetMinutes ?? 0,
      searchText: `${browserLabel} ${local?.searchText ?? ''}`,
    }
    const pinned = [localZone, UTC_TIME_ZONE].filter(
      (id, index, all): id is string =>
        Boolean(id) && all.indexOf(id) === index,
    )
    const ordered = [
      ...pinned.flatMap((id) => catalog.filter((option) => option.id === id)),
      ...catalog.filter((option) => !pinned.includes(option.id)),
    ]
    return [
      browser,
      ...ordered.map((option) => ({
        ...option,
        detail:
          option.id === localZone ? `${option.id} - ${localLabel}` : option.id,
      })),
    ]
  }, [browserLabel, catalog, localLabel, localZone])
  const selected = options.find((option) => option.id === selection)

  return (
    <Field data-invalid={error ? true : undefined}>
      <FieldLabel htmlFor={triggerId}>{t('accountTimeZone')}</FieldLabel>
      <Combobox
        name="zone_info"
        items={options}
        value={selected ?? null}
        itemToStringLabel={(option: SelectOption) => option.name}
        itemToStringValue={(option: SelectOption) => option.id}
        isItemEqualToValue={(option: SelectOption, current: SelectOption) => option.id === current.id}
        filter={(option: SelectOption, query) => matchesTimeZone(option.searchText, query)}
        onValueChange={(option: SelectOption | null) => {
          if (option) setSelection(option.id)
        }}
        onOpenChange={setOpen}
      >
        <ComboboxTrigger
          id={triggerId}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? errorId : undefined}
          render={<Button variant="outline" className="w-full justify-between font-normal" />}
        >
          <ComboboxValue>
            {() => (
              <span className="flex min-w-0 items-center gap-2" title={selected?.name}>
                <span className="truncate">{selected?.name}</span>
                {selection !== BROWSER_TIME_ZONE_VALUE ? (
                  <span className="shrink-0 text-xs text-muted-foreground">{selected?.offset}</span>
                ) : null}
              </span>
            )}
          </ComboboxValue>
        </ComboboxTrigger>
        <ComboboxContent aria-label={t('accountTimeZone')}>
          <ComboboxInput
            showTrigger={false}
            aria-label={t('accountTimeZoneSearch')}
            placeholder={t('accountTimeZoneSearch')}
          />
          <ComboboxEmpty>{t('accountTimeZoneEmpty')}</ComboboxEmpty>
          <ComboboxList>
            {(option: SelectOption) => (
              <ComboboxItem key={option.id} value={option} className="items-center">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{option.name}</div>
                  <div className="truncate text-xs text-muted-foreground">{option.detail}</div>
                </div>
                <span className="shrink-0 font-mono text-xs text-muted-foreground">{option.offset}</span>
              </ComboboxItem>
            )}
          </ComboboxList>
        </ComboboxContent>
      </Combobox>
      {error ? <FieldError id={errorId}>{error}</FieldError> : null}
    </Field>
  )
}
