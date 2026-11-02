import {
  Button,
  ComboBox,
  Input,
  Label,
  ListBox,
  ListLayout,
  Virtualizer,
} from '@heroui/react'
import { memo, useMemo } from 'react'
import { useFilter } from 'react-aria'

import { useLocale, useTranslator } from '#/lib/i18n'
import {
  translationLocaleOptions,
  type TranslationLocaleOption,
} from '#/lib/translation-locales'

const LANGUAGE_LAYOUT = { rowHeight: 40 }

function renderLanguage(option: TranslationLocaleOption) {
  return (
    <ListBox.Item
      id={option.tag}
      textValue={option.search}
      className="h-10 min-h-0 transition-none"
    >
      <span className="truncate" title={option.label}>
        {option.label}
      </span>
      <ListBox.ItemIndicator />
    </ListBox.Item>
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
    const { contains } = useFilter({ sensitivity: 'base' })
    const options = useMemo(() => {
      const used = new Set(usedLocalesKey.split('\0'))
      return translationLocaleOptions(locale).filter(
        (option) => !used.has(option.tag),
      )
    }, [locale, usedLocalesKey])

    return (
      <>
        <ComboBox
          defaultItems={options}
          menuTrigger="input"
          selectedKey={null}
          onSelectionChange={(key) => {
            if (typeof key === 'string') onSelect(key)
          }}
          allowsCustomValue={false}
          allowsEmptyCollection
          defaultFilter={contains}
          autoFocus
          fullWidth
        >
          <Label>{t('localizedChooseLanguage')}</Label>
          <ComboBox.InputGroup>
            <Input
              placeholder={t('localizedSearchLanguages')}
              autoComplete="off"
            />
            <ComboBox.Trigger />
          </ComboBox.InputGroup>
          <ComboBox.Popover className="w-(--trigger-width) overflow-hidden">
            <Virtualizer layout={ListLayout} layoutOptions={LANGUAGE_LAYOUT}>
              <ListBox
                className="block max-h-64 overflow-y-auto p-0"
                renderEmptyState={() => (
                  <p className="p-3 text-sm text-muted">
                    {t('localizedNoLanguages')}
                  </p>
                )}
              >
                {renderLanguage}
              </ListBox>
            </Virtualizer>
          </ComboBox.Popover>
        </ComboBox>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          className="mt-2"
          onPress={onCancel}
        >
          {t('localizedCancel')}
        </Button>
      </>
    )
  },
)
