import { Button } from '@identity/ui/components/button'
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from '@identity/ui/components/combobox'
import { Field, FieldLabel } from '@identity/ui/components/field'
import { memo, useId, useMemo } from 'react'

import { useLocale, useTranslator } from '#/lib/i18n'
import {
  translationLocaleOptions,
  type TranslationLocaleOption,
} from '#/lib/translation-locales'

function matchesLanguage(option: TranslationLocaleOption, query: string) {
  const value = query.trim().toLocaleLowerCase()
  if (!value) return true
  return (
    option.search.toLocaleLowerCase().includes(value) ||
    option.label.toLocaleLowerCase().includes(value)
  )
}

/** Mounted only while choosing a language; text edits do not rebuild its collection. */
export const TranslationLanguagePicker = memo(
  function TranslationLanguagePicker({
    usedLocalesKey,
    onSelect,
    onCancel,
  }: {
    usedLocalesKey: string
    onSelect: (tag: string) => void
    onCancel: () => void
  }) {
    const t = useTranslator()
    const { locale } = useLocale()
    const inputId = useId()
    const options = useMemo(() => {
      const used = new Set(usedLocalesKey.split('\0'))
      return translationLocaleOptions(locale).filter(
        (option) => !used.has(option.tag),
      )
    }, [locale, usedLocalesKey])

    return (
      <div>
        <Field>
          <FieldLabel htmlFor={inputId}>{t('localizedChooseLanguage')}</FieldLabel>
          <Combobox
            items={options}
            value={null}
            itemToStringLabel={(option: TranslationLocaleOption) => option.label}
            itemToStringValue={(option: TranslationLocaleOption) => option.tag}
            filter={matchesLanguage}
            onValueChange={(option: TranslationLocaleOption | null) => {
              if (option) onSelect(option.tag)
            }}
          >
            <ComboboxInput
              id={inputId}
              showTrigger={false}
              aria-label={t('localizedChooseLanguage')}
              placeholder={t('localizedSearchLanguages')}
              autoComplete="off"
            />
            <ComboboxContent>
              <ComboboxEmpty>{t('localizedNoLanguages')}</ComboboxEmpty>
              <ComboboxList>
                {(option: TranslationLocaleOption) => (
                  <ComboboxItem key={option.tag} value={option}>
                    <span className="truncate" title={option.label}>
                      {option.label}
                    </span>
                  </ComboboxItem>
                )}
              </ComboboxList>
            </ComboboxContent>
          </Combobox>
        </Field>
        <Button type="button" size="sm" variant="ghost" className="mt-2" onClick={onCancel}>
          {t('localizedCancel')}
        </Button>
      </div>
    )
  },
)
