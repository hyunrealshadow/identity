import {
  Autocomplete,
  FieldError,
  Label,
  ListBox,
  ListLayout,
  SearchField,
  Virtualizer,
} from '@heroui/react'
import { useEffect, useMemo, useState } from 'react'

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
const TIME_ZONE_LAYOUT = { rowHeight: 56 }

function renderTimeZone(option: SelectOption) {
  return (
    <ListBox.Item
      id={option.id}
      textValue={option.searchText}
      className="h-14 min-h-0 pe-8"
    >
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium">{option.name}</div>
        <div className="truncate text-xs text-muted">{option.detail}</div>
      </div>
      <span className="shrink-0 font-mono text-xs text-muted">
        {option.offset}
      </span>
      <ListBox.ItemIndicator />
    </ListBox.Item>
  )
}

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
  const [query, setQuery] = useState('')

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
    <Autocomplete
      fullWidth
      name="zone_info"
      value={selection}
      isInvalid={Boolean(error)}
      onChange={(key) => {
        if (typeof key === 'string') setSelection(key)
      }}
      onOpenChange={(isOpen) => {
        setOpen(isOpen)
        setQuery('')
      }}
    >
      <Label>{t('accountTimeZone')}</Label>
      <Autocomplete.Trigger>
        <Autocomplete.Value>
          {() => (
            <span
              className="flex min-w-0 items-center gap-2"
              title={selected?.name}
            >
              <span className="truncate">{selected?.name}</span>
              {selection !== BROWSER_TIME_ZONE_VALUE ? (
                <span className="shrink-0 text-xs text-muted">
                  {selected?.offset}
                </span>
              ) : null}
            </span>
          )}
        </Autocomplete.Value>
        <Autocomplete.Indicator />
      </Autocomplete.Trigger>
      <Autocomplete.Popover aria-label={t('accountTimeZone')}>
        <Autocomplete.Filter
          filter={matchesTimeZone}
          inputValue={query}
          onInputChange={setQuery}
        >
          <SearchField
            autoFocus
            aria-label={t('accountTimeZoneSearch')}
            value={query}
            onChange={setQuery}
            variant="secondary"
          >
            <SearchField.Group>
              <SearchField.SearchIcon />
              <SearchField.Input placeholder={t('accountTimeZoneSearch')} />
              <SearchField.ClearButton
                aria-label={t('accountTimeZoneClearSearch')}
              />
            </SearchField.Group>
          </SearchField>
          <Virtualizer layout={ListLayout} layoutOptions={TIME_ZONE_LAYOUT}>
            <ListBox
              className="max-h-72 overflow-y-auto"
              items={options}
              renderEmptyState={() => (
                <p className="p-4 text-sm text-muted">
                  {t('accountTimeZoneEmpty')}
                </p>
              )}
            >
              {renderTimeZone}
            </ListBox>
          </Virtualizer>
        </Autocomplete.Filter>
      </Autocomplete.Popover>
      <FieldError>{error}</FieldError>
    </Autocomplete>
  )
}
