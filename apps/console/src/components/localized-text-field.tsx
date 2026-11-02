import {
  Button,
  Description,
  FieldError,
  Input,
  Label,
  ListBox,
  Select,
  TextArea,
  TextField,
} from '@heroui/react'
import { Plus, Undo2, X } from 'lucide-react'
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

import { TranslationLanguagePicker } from '#/components/translation-language-picker'
import { useLocale, useTranslator } from '#/lib/i18n'
import {
  translationLocaleLabel,
  translationLocales,
} from '#/lib/translation-locales'
import {
  MAX_TRANSLATIONS,
  canonicalTranslationLocale,
  type LocalizedValues,
} from '#/lib/localized-values'

export interface LocalizedTextFieldProps {
  name: string
  label: string
  defaultValue: string
  onDefaultValueChange: (value: string) => void
  value: LocalizedValues
  onChange: (value: LocalizedValues) => void
  multiline?: boolean
  isRequired?: boolean
  isDisabled?: boolean
  isReadOnly?: boolean
  maxLength?: number
  error?: string
  description?: string
}

interface RemovedTranslation {
  locale: string
  value: string
}

function hasLocale(values: LocalizedValues, locale: string): boolean {
  return Object.prototype.hasOwnProperty.call(values, locale)
}

function optionLocales(
  values: LocalizedValues,
  uiLocale: string | undefined,
): string[] {
  const locales = Object.keys(values)
  if (locales.length === 0) locales.push(uiLocale ?? 'en-US')
  return locales.sort((left, right) => left.localeCompare(right))
}

function pickLocale(
  values: LocalizedValues,
  uiLocale: string | undefined,
): string {
  const locales = Object.keys(values)
  if (uiLocale && values[uiLocale]?.trim()) return uiLocale
  const filledLocale = locales.find((tag) => values[tag]?.trim())
  if (filledLocale) return filledLocale
  if (uiLocale && locales.includes(uiLocale)) return uiLocale
  return locales[0] ?? uiLocale ?? 'en-US'
}

export function LocalizedTextField({
  name,
  label,
  defaultValue,
  onDefaultValueChange,
  value,
  onChange,
  multiline = false,
  isRequired = false,
  isDisabled = false,
  isReadOnly = false,
  maxLength,
  error,
  description,
}: LocalizedTextFieldProps): ReactNode {
  const t = useTranslator()
  const { locale } = useLocale()
  const labelId = useId()
  const addPanelId = useId()

  const canonicalUiLocale = useMemo(
    () => canonicalTranslationLocale(locale),
    [locale],
  )
  const locales = useMemo(
    () => optionLocales(value, canonicalUiLocale),
    [canonicalUiLocale, value],
  )

  const [activeLocale, setActiveLocale] = useState(() =>
    pickLocale(value, canonicalUiLocale),
  )
  const [addOpen, setAddOpen] = useState(false)
  const [removed, setRemoved] = useState<RemovedTranslation | null>(null)
  const [touched, setTouched] = useState(false)
  const [focusSequence, setFocusSequence] = useState(0)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const textAreaRef = useRef<HTMLTextAreaElement | null>(null)
  const addButtonRef = useRef<HTMLButtonElement | null>(null)

  const existingCount = Object.keys(value).length
  const atMax = existingCount >= MAX_TRANSLATIONS
  const filled = useMemo(
    () => Object.values(value).filter((text) => text.trim() !== '').length,
    [value],
  )

  const externalError = error?.trim() ? error : undefined
  const requiredMissing = isRequired && !defaultValue.trim()
  const shownError =
    externalError ??
    (requiredMissing && touched ? t('localizedDefaultRequired') : undefined)
  const invalid = Boolean(shownError)
  const activeValue = value[activeLocale] ?? ''
  const hasActiveTranslation = hasLocale(value, activeLocale)
  const usedLocalesKey = Object.keys(value).sort().join('\0')
  const selectionState = useRef({
    value,
    onChange,
    isDisabled,
    isReadOnly,
    atMax,
  })
  useLayoutEffect(() => {
    selectionState.current = { value, onChange, isDisabled, isReadOnly, atMax }
  }, [value, onChange, isDisabled, isReadOnly, atMax])

  useEffect(() => {
    if (locales.includes(activeLocale)) return
    setActiveLocale(pickLocale(value, canonicalUiLocale))
  }, [activeLocale, canonicalUiLocale, locales, value])

  useEffect(() => {
    if (isDisabled || isReadOnly || atMax) {
      setAddOpen(false)
    }
  }, [atMax, isDisabled, isReadOnly])

  useEffect(() => {
    if (focusSequence === 0) return
    const editor = multiline ? textAreaRef.current : inputRef.current
    editor?.focus()
  }, [focusSequence, multiline])

  function openTranslationChooser() {
    if (isDisabled || isReadOnly || atMax) return
    setAddOpen((open) => !open)
  }

  const closeTranslationChooser = useCallback(() => setAddOpen(false), [])
  const cancelTranslationChooser = useCallback(() => {
    setAddOpen(false)
    addButtonRef.current?.focus()
  }, [])
  const addTranslation = useCallback((tag: string) => {
    // Stable picker callbacks read the latest committed draft, including edits
    // made while the chooser is open, without rebuilding the language list.
    const current = selectionState.current
    if (current.isDisabled || current.isReadOnly || current.atMax) return
    if (hasLocale(current.value, tag) || !translationLocales.includes(tag))
      return
    current.onChange({ ...current.value, [tag]: '' })
    setActiveLocale(tag)
    setRemoved((previous) => (previous?.locale === tag ? null : previous))
    setAddOpen(false)
    setFocusSequence((sequence) => sequence + 1)
  }, [])

  function removeActiveTranslation() {
    if (isDisabled || isReadOnly || !hasActiveTranslation) return
    const removedValue = value[activeLocale] ?? ''
    const next = { ...value }
    delete next[activeLocale]
    const remaining = Object.keys(next)
    const fallback =
      canonicalUiLocale && remaining.includes(canonicalUiLocale)
        ? canonicalUiLocale
        : (remaining[0] ?? canonicalUiLocale ?? 'en-US')

    setRemoved({ locale: activeLocale, value: removedValue })
    setTouched(true)
    closeTranslationChooser()
    onChange(next)
    setActiveLocale(fallback)
    setFocusSequence((sequence) => sequence + 1)
  }

  function undoRemoval() {
    if (!removed || isDisabled || isReadOnly) return
    if (!hasLocale(value, removed.locale) && atMax) return
    if (!hasLocale(value, removed.locale)) {
      onChange({ ...value, [removed.locale]: removed.value })
    }
    setActiveLocale(removed.locale)
    setTouched(true)
    setRemoved(null)
    setFocusSequence((sequence) => sequence + 1)
  }

  return (
    <div
      role="group"
      data-localized-field={name}
      aria-labelledby={labelId}
      aria-invalid={invalid || undefined}
      aria-required={isRequired || undefined}
      aria-disabled={isDisabled || undefined}
      className="flex min-w-0 flex-col gap-2"
    >
      <span id={labelId} className="text-sm font-medium">
        {label}
      </span>
      <div className="grid min-w-0 gap-4 md:grid-cols-2">
        <TextField
          name={name === 'names' ? 'name' : 'description'}
          value={defaultValue}
          onChange={(next) => {
            setTouched(true)
            onDefaultValueChange(next)
          }}
          isRequired={isRequired}
          isDisabled={isDisabled}
          isReadOnly={isReadOnly}
          isInvalid={invalid}
          fullWidth
        >
          <Label className="flex h-10 items-center">
            {t('localizedDefault')}
          </Label>
          {multiline ? (
            <TextArea rows={4} maxLength={maxLength} fullWidth />
          ) : (
            <Input maxLength={maxLength} />
          )}
          {shownError ? <FieldError>{shownError}</FieldError> : null}
          {description ? <Description>{description}</Description> : null}
        </TextField>
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex min-h-10 min-w-0 flex-wrap items-center gap-2 sm:h-10 sm:flex-nowrap">
            <span className="shrink-0 text-sm font-medium">
              {t('localizedTranslations')}
            </span>
            <div className="w-full min-w-0 sm:ms-auto sm:w-auto">
              <div
                className="w-full min-w-0 max-w-full sm:w-56"
                title={translationLocaleLabel(activeLocale, locale)}
              >
                <Select
                  value={activeLocale}
                  onChange={(key) => {
                    if (typeof key === 'string' || typeof key === 'number') {
                      setActiveLocale(String(key))
                    }
                  }}
                  isDisabled={isDisabled}
                  fullWidth
                >
                  <Label className="sr-only">{t('localizedLanguage')}</Label>
                  <Select.Trigger type="button" className="min-w-0">
                    <Select.Value className="truncate" />
                    <Select.Indicator />
                  </Select.Trigger>
                  <Select.Popover>
                    <ListBox>
                      {locales.map((tag) => {
                        const optionLabel = translationLocaleLabel(tag, locale)
                        return (
                          <ListBox.Item
                            key={tag}
                            id={tag}
                            textValue={optionLabel}
                          >
                            {optionLabel}
                          </ListBox.Item>
                        )
                      })}
                    </ListBox>
                  </Select.Popover>
                </Select>
              </div>
            </div>
          </div>

          <TextField
            name={`${name}.${activeLocale}`}
            value={activeValue}
            onChange={(next) => {
              setTouched(true)
              onChange({ ...value, [activeLocale]: next })
            }}
            isDisabled={isDisabled}
            isReadOnly={isReadOnly}
            fullWidth
          >
            <Label className="sr-only">
              {t('localizedTranslationInLocale', {
                label,
                locale: activeLocale,
              })}
            </Label>
            {multiline ? (
              <TextArea
                ref={textAreaRef}
                rows={4}
                maxLength={maxLength}
                fullWidth
              />
            ) : (
              <Input ref={inputRef} maxLength={maxLength} />
            )}
          </TextField>

          {atMax && !isReadOnly ? (
            <p className="text-xs text-muted">
              {t('localizedMaxTranslations', { max: MAX_TRANSLATIONS })}
            </p>
          ) : null}

          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            <span
              className="shrink-0 text-xs tabular-nums text-muted"
              title={t('localizedTranslationsFilled', {
                filled,
                total: locales.length,
              })}
            >
              {filled}/{locales.length}
              <span className="sr-only">
                {t('localizedTranslationsFilled', {
                  filled,
                  total: locales.length,
                })}
              </span>
            </span>
            {!isReadOnly ? (
              <Button
                ref={addButtonRef}
                type="button"
                size="sm"
                variant="ghost"
                className="h-8 shrink-0 gap-1 px-2"
                isDisabled={isDisabled || atMax}
                aria-label={
                  atMax
                    ? t('localizedMaxTranslations', { max: MAX_TRANSLATIONS })
                    : t('localizedAddTranslation')
                }
                aria-expanded={addOpen}
                aria-controls={addPanelId}
                onPress={openTranslationChooser}
              >
                <Plus className="size-4" aria-hidden="true" />
                <span className="hidden sm:inline">
                  {t('localizedAddTranslation')}
                </span>
              </Button>
            ) : null}

            {!isReadOnly ? (
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="h-7 shrink-0 gap-1 px-2 text-danger"
                  isDisabled={isDisabled || !hasActiveTranslation}
                  aria-label={t('localizedRemoveTranslationFor', {
                    locale: activeLocale,
                  })}
                  onPress={removeActiveTranslation}
                >
                  <X className="size-3.5" aria-hidden="true" />
                  <span className="hidden sm:inline">
                    {t('localizedRemoveTranslation')}
                  </span>
                </Button>
                {removed ? (
                  <div className="flex min-w-0 flex-wrap items-center gap-1 text-xs text-muted">
                    <span role="status" className="min-w-0 break-words">
                      {t('localizedTranslationRemoved', {
                        locale: removed.locale,
                      })}
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      className="h-7 shrink-0 gap-1 px-2"
                      isDisabled={
                        isDisabled ||
                        (atMax && !hasLocale(value, removed.locale))
                      }
                      onPress={undoRemoval}
                    >
                      <Undo2 className="size-3.5" aria-hidden="true" />
                      {t('localizedUndoRemove')}
                    </Button>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
          {addOpen && !isDisabled && !isReadOnly && !atMax ? (
            <div
              id={addPanelId}
              className="rounded-field border border-border bg-surface-secondary p-3"
              onKeyDown={(event) => {
                if (event.key === 'Enter') event.preventDefault()
                if (event.key === 'Escape' && !event.defaultPrevented) {
                  event.preventDefault()
                  closeTranslationChooser()
                  addButtonRef.current?.focus()
                }
              }}
            >
              <TranslationLanguagePicker
                usedLocalesKey={usedLocalesKey}
                onSelect={addTranslation}
                onCancel={cancelTranslationChooser}
              />
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
