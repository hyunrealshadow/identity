import { Button } from '@identity/ui/components/button'
import { Field, FieldDescription, FieldError, FieldLabel } from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'
import { Textarea } from '@identity/ui/components/textarea'
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
  const defaultInputId = `${labelId}-default`
  const translationInputId = `${labelId}-translation`

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
        <Field data-invalid={invalid || undefined}>
          <FieldLabel htmlFor={defaultInputId} className="flex h-10 items-center">
            {t('localizedDefault')}
          </FieldLabel>
          {multiline ? (
            <Textarea
              id={defaultInputId}
              name={name === 'names' ? 'name' : 'description'}
              rows={4}
              maxLength={maxLength}
              value={defaultValue}
              required={isRequired}
              disabled={isDisabled}
              readOnly={isReadOnly}
              aria-invalid={invalid || undefined}
              onChange={(event) => {
                setTouched(true)
                onDefaultValueChange(event.target.value)
              }}
            />
          ) : (
            <Input
              id={defaultInputId}
              name={name === 'names' ? 'name' : 'description'}
              maxLength={maxLength}
              value={defaultValue}
              required={isRequired}
              disabled={isDisabled}
              readOnly={isReadOnly}
              aria-invalid={invalid || undefined}
              onChange={(event) => {
                setTouched(true)
                onDefaultValueChange(event.target.value)
              }}
            />
          )}
          {shownError ? <FieldError>{shownError}</FieldError> : null}
          {description ? <FieldDescription>{description}</FieldDescription> : null}
        </Field>
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
                  onValueChange={(next) => { if (next) setActiveLocale(next) }}
                  disabled={isDisabled}
                >
                  <SelectTrigger
                    type="button"
                    aria-label={t('localizedLanguage')}
                    className="w-full min-w-0"
                  >
                    <SelectValue className="truncate" />
                  </SelectTrigger>
                  <SelectContent>
                    {locales.map((tag) => (
                      <SelectItem key={tag} value={tag}>
                        {translationLocaleLabel(tag, locale)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <Field>
            <FieldLabel className="sr-only" htmlFor={translationInputId}>
              {t('localizedTranslationInLocale', {
                label,
                locale: activeLocale,
              })}
            </FieldLabel>
            {multiline ? (
              <Textarea
                id={translationInputId}
                ref={textAreaRef}
                name={`${name}.${activeLocale}`}
                rows={4}
                maxLength={maxLength}
                value={activeValue}
                disabled={isDisabled}
                readOnly={isReadOnly}
                onChange={(event) => {
                  setTouched(true)
                  onChange({ ...value, [activeLocale]: event.target.value })
                }}
              />
            ) : (
              <Input
                id={translationInputId}
                ref={inputRef}
                name={`${name}.${activeLocale}`}
                maxLength={maxLength}
                value={activeValue}
                disabled={isDisabled}
                readOnly={isReadOnly}
                onChange={(event) => {
                  setTouched(true)
                  onChange({ ...value, [activeLocale]: event.target.value })
                }}
              />
            )}
          </Field>

          {atMax && !isReadOnly ? (
            <p className="text-xs text-muted-foreground">
              {t('localizedMaxTranslations', { max: MAX_TRANSLATIONS })}
            </p>
          ) : null}

          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            <span
              className="shrink-0 text-xs tabular-nums text-muted-foreground"
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
                disabled={isDisabled || atMax}
                aria-label={
                  atMax
                    ? t('localizedMaxTranslations', { max: MAX_TRANSLATIONS })
                    : t('localizedAddTranslation')
                }
                aria-expanded={addOpen}
                aria-controls={addPanelId}
                onClick={openTranslationChooser}
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
                  className="h-7 shrink-0 gap-1 px-2 text-destructive"
                  disabled={isDisabled || !hasActiveTranslation}
                  aria-label={t('localizedRemoveTranslationFor', {
                    locale: activeLocale,
                  })}
                  onClick={removeActiveTranslation}
                >
                  <X className="size-3.5" aria-hidden="true" />
                  <span className="hidden sm:inline">
                    {t('localizedRemoveTranslation')}
                  </span>
                </Button>
                {removed ? (
                  <div className="flex min-w-0 flex-wrap items-center gap-1 text-xs text-muted-foreground">
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
                      disabled={
                        isDisabled ||
                        (atMax && !hasLocale(value, removed.locale))
                      }
                      onClick={undoRemoval}
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
              className="rounded-lg border border-border bg-muted p-3"
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
