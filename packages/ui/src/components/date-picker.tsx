import * as React from "react"
import { cn } from "cn"
import { enUS, zhCN, type Locale as DateFnsLocale } from "date-fns/locale"
import { CalendarIcon, XIcon } from "lucide-react"

import { Button } from "@identity/ui/components/button"
import { Calendar } from "@identity/ui/components/calendar"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from "@identity/ui/components/field"
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
  placeholder: string
  clearLabel: string
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

/**
 * Date-only field: a popover calendar backed by a hidden input that posts the
 * selected day as `YYYY-MM-DD`.
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
  const label_ = selected
    ? new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(selected)
    : placeholder

  function change(next: string) {
    if (value === undefined) setLocalValue(next)
    onChange?.(next)
  }

  return (
    <Field data-invalid={error ? true : undefined} className={cn("min-w-0", className)}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <input type="hidden" name={name} value={currentValue} />
      <div className="flex min-w-0 gap-1">
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger
            render={
              <Button
                id={id}
                variant="outline"
                disabled={disabled}
                aria-invalid={error ? true : undefined}
                aria-required={required || undefined}
                aria-describedby={error ? `${id}-error` : undefined}
                aria-label={`${label}: ${label_}`}
                className={cn(
                  "min-w-0 flex-1 justify-start font-normal",
                  !selected && "text-muted-foreground"
                )}
              />
            }
          >
            <CalendarIcon aria-hidden="true" />
            <span className="truncate">{label_}</span>
          </PopoverTrigger>
          <PopoverContent className="w-auto p-0" align="start">
            <Calendar
              mode="single"
              captionLayout="dropdown"
              locale={dateFnsLocale(locale)}
              selected={selected}
              defaultMonth={selected ?? today}
              endMonth={new Date(today.getFullYear() + 10, 11)}
              required={required}
              onSelect={(date: Date | undefined) => {
                change(date ? formatDateOnly(date) : "")
                setOpen(false)
              }}
            />
          </PopoverContent>
        </Popover>
        {selected && !required ? (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            disabled={disabled}
            aria-label={clearLabel}
            onClick={() => change("")}
          >
            <XIcon aria-hidden="true" />
          </Button>
        ) : null}
      </div>
      {description ? <FieldDescription>{description}</FieldDescription> : null}
      {error ? <FieldError id={`${id}-error`}>{error}</FieldError> : null}
    </Field>
  )
}

export { DatePickerField }
