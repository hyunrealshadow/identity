import * as React from "react"
import { cn } from "cn"
import { enUS, zhCN, type Locale as DateFnsLocale } from "date-fns/locale"
import { CalendarIcon, XIcon } from "lucide-react"

import { Calendar } from "@identity/ui/components/calendar"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from "@identity/ui/components/field"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@identity/ui/components/input-group"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@identity/ui/components/popover"

export interface DatePickerFieldProps {
  name: string
  label: string
  /** Date-only value as `YYYY-MM-DD`; it never shifts with the time zone. */
  value?: string
  defaultValue?: string
  onChange?: (value: string) => void
  /** Time zone that decides which calendar day is "today". */
  timeZone: string
  locale: string
  /** Defaults to the locale's numeric date pattern, such as `YYYY/MM/DD`. */
  placeholder?: string
  clearLabel: string
  /** Accessible name of the button that opens the calendar. */
  calendarLabel: string
  description?: string
  error?: string
  required?: boolean
  disabled?: boolean
  className?: string
}

const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/

function parseDateOnly(value: string) {
  const match = DATE_PATTERN.exec(value)
  if (!match) return undefined
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]))
  return date.getMonth() === Number(match[2]) - 1 ? date : undefined
}

function formatDateOnly(date: Date) {
  const year = String(date.getFullYear()).padStart(4, "0")
  const month = String(date.getMonth() + 1).padStart(2, "0")
  const day = String(date.getDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

function todayIn(timeZone: string) {
  try {
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date())
    return parseDateOnly(parts) ?? new Date()
  } catch {
    return new Date()
  }
}

function dateFnsLocale(locale: string): DateFnsLocale {
  return locale.toLowerCase().startsWith("zh") ? zhCN : enUS
}

function numericDateFormat(locale: string) {
  return new Intl.DateTimeFormat(locale, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  })
}

type DatePart = "year" | "month" | "day"

/** Year, month and day in the order the locale writes them. */
function datePartOrder(locale: string): DatePart[] {
  return numericDateFormat(locale)
    .formatToParts(new Date(2000, 0, 31))
    .map((part) => part.type)
    .filter((type): type is DatePart => type === "year" || type === "month" || type === "day")
}

/** Placeholder such as `YYYY/MM/DD` or `MM/DD/YYYY`, taken from the locale. */
function datePattern(locale: string) {
  const tokens: Partial<Record<string, string>> = { year: "YYYY", month: "MM", day: "DD" }
  return numericDateFormat(locale)
    .formatToParts(new Date(2000, 0, 31))
    .map((part) => tokens[part.type] ?? part.value)
    .join("")
}

/**
 * Reads a typed day in the locale's numeric order. Text that starts with a
 * four-digit year is always read as year-month-day, so `YYYY-MM-DD` works
 * everywhere.
 */
function parseTypedDate(text: string, locale: string) {
  const numbers = text.trim().match(/\d+/g)
  if (!numbers || numbers.length !== 3) return undefined
  const order: DatePart[] =
    numbers[0].length === 4 ? ["year", "month", "day"] : datePartOrder(locale)
  if (order.length !== 3) return undefined
  const parts = Object.fromEntries(order.map((type, index) => [type, numbers[index]]))
  if (parts.year?.length !== 4) return undefined
  return parseDateOnly(
    `${parts.year}-${parts.month.padStart(2, "0")}-${parts.day.padStart(2, "0")}`
  )
}

/**
 * Date-only field: a typed date input with a calendar popover, backed by a
 * hidden input that posts the selected day as `YYYY-MM-DD`.
 */
function DatePickerField({
  name,
  label,
  value,
  defaultValue,
  onChange,
  timeZone,
  locale,
  placeholder,
  clearLabel,
  calendarLabel,
  description,
  error,
  required = false,
  disabled = false,
  className,
}: DatePickerFieldProps) {
  const id = React.useId()
  const [localValue, setLocalValue] = React.useState(defaultValue ?? "")
  const [open, setOpen] = React.useState(false)
  const currentValue = value ?? localValue
  const selected = parseDateOnly(currentValue)
  const today = React.useMemo(() => todayIn(timeZone), [timeZone])
  const formatted = React.useCallback(
    (date: Date | undefined) => (date ? numericDateFormat(locale).format(date) : ""),
    [locale]
  )
  const [text, setText] = React.useState(() => formatted(selected))
  const [month, setMonth] = React.useState<Date>(selected ?? today)

  // Show the committed value whenever it changes from outside the text box.
  React.useEffect(() => {
    setText(formatted(parseDateOnly(currentValue)))
  }, [currentValue, formatted])

  const clearable = !!selected && !required

  function change(next: string) {
    if (value === undefined) setLocalValue(next)
    onChange?.(next)
  }

  function select(date: Date | undefined) {
    const next = date ? formatDateOnly(date) : ""
    if (date) setMonth(date)
    setText(formatted(date))
    if (next !== currentValue) change(next)
  }

  function typed(nextText: string) {
    setText(nextText)
    const date = parseTypedDate(nextText, locale)
    if (date) {
      setMonth(date)
      const next = formatDateOnly(date)
      if (next !== currentValue) change(next)
    }
  }

  function commitText() {
    if (!text.trim()) {
      if (currentValue) change("")
      return
    }
    // Unrecognised text never replaces the last valid day.
    if (!parseTypedDate(text, locale)) setText(formatted(selected))
  }

  function clear() {
    select(undefined)
    // The clear control disappears with the value; keep focus on the field.
    document.getElementById(id)?.focus()
  }

  return (
    <Field data-invalid={error ? true : undefined} className={cn("min-w-0", className)}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <input type="hidden" name={name} value={currentValue} />
      <InputGroup>
        <InputGroupAddon align="inline-start">
          <Popover open={open} onOpenChange={setOpen}>
            <PopoverTrigger
              render={
                <InputGroupButton
                  size="icon-xs"
                  disabled={disabled}
                  aria-label={calendarLabel}
                />
              }
            >
              <CalendarIcon aria-hidden="true" />
            </PopoverTrigger>
            <PopoverContent
              className="w-auto overflow-hidden p-0"
              align="start"
              alignOffset={-8}
              sideOffset={10}
            >
              <Calendar
                mode="single"
                captionLayout="dropdown"
                locale={dateFnsLocale(locale)}
                selected={selected}
                month={month}
                onMonthChange={setMonth}
                endMonth={new Date(today.getFullYear() + 10, 11)}
                required={required}
                onSelect={(date: Date | undefined) => {
                  select(date)
                  setOpen(false)
                }}
              />
            </PopoverContent>
          </Popover>
        </InputGroupAddon>
        <InputGroupInput
          id={id}
          value={text}
          placeholder={placeholder ?? datePattern(locale)}
          disabled={disabled}
          autoComplete="off"
          aria-invalid={error ? true : undefined}
          aria-required={required || undefined}
          aria-describedby={error ? `${id}-error` : undefined}
          onChange={(event) => typed(event.target.value)}
          onBlur={commitText}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault()
              setOpen(true)
            }
          }}
        />
        {clearable ? (
          <InputGroupAddon align="inline-end">
            <InputGroupButton
              size="icon-xs"
              disabled={disabled}
              aria-label={clearLabel}
              onClick={clear}
              className="text-muted-foreground"
            >
              <XIcon aria-hidden="true" />
            </InputGroupButton>
          </InputGroupAddon>
        ) : null}
      </InputGroup>
      {description ? <FieldDescription>{description}</FieldDescription> : null}
      {error ? <FieldError id={`${id}-error`}>{error}</FieldError> : null}
    </Field>
  )
}

export { DatePickerField }
