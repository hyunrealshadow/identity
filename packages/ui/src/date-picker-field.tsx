import {
  Button,
  Calendar,
  DateField,
  DatePicker,
  Description,
  FieldError,
  Label,
} from '@heroui/react'
import { parseDate, today } from '@internationalized/date'
import { useState } from 'react'
import { I18nProvider } from 'react-aria'

export interface DatePickerFieldProps {
  name: string
  label: string
  value?: string
  defaultValue?: string
  onChange?: (value: string) => void
  timeZone: string
  locale: string
  clearLabel: string
  description?: string
  error?: string
  isRequired?: boolean
  isDisabled?: boolean
}

export function DatePickerField({
  name,
  label,
  value,
  defaultValue,
  timeZone,
  locale,
  clearLabel,
  onChange,
  description,
  error,
  isRequired = false,
  isDisabled = false,
}: DatePickerFieldProps) {
  const [localValue, setLocalValue] = useState(defaultValue ?? '')
  const currentValue = value ?? localValue
  function change(next: string) {
    if (value === undefined) setLocalValue(next)
    onChange?.(next)
  }
  const [open, setOpen] = useState(false)
  const date = (() => {
    try {
      return currentValue ? parseDate(currentValue) : null
    } catch {
      return null
    }
  })()

  return (
    <I18nProvider locale={locale}>
      <DatePicker
        className="min-w-0 w-full"
        name={name}
        value={date}
        onChange={(next) => change(next?.toString() ?? '')}
        placeholderValue={today(timeZone)}
        granularity="day"
        isOpen={open}
        onOpenChange={setOpen}
        isRequired={isRequired}
        isDisabled={isDisabled}
        isInvalid={Boolean(error)}
      >
        <Label>{label}</Label>
        <DateField.Group fullWidth>
          <DateField.Input>
            {(segment) => <DateField.Segment segment={segment} />}
          </DateField.Input>
          <DateField.Suffix>
            <DatePicker.Trigger>
              <DatePicker.TriggerIndicator />
            </DatePicker.Trigger>
          </DateField.Suffix>
        </DateField.Group>
        {description ? <Description>{description}</Description> : null}
        {error ? <FieldError>{error}</FieldError> : null}
        <DatePicker.Popover className="identity-date-picker-popover">
          <Calendar aria-label={label}>
            <Calendar.Header>
              <Calendar.YearPickerTrigger>
                <Calendar.YearPickerTriggerHeading />
                <Calendar.YearPickerTriggerIndicator />
              </Calendar.YearPickerTrigger>
              <Calendar.NavButton slot="previous" />
              <Calendar.NavButton slot="next" />
            </Calendar.Header>
            <Calendar.Grid>
              <Calendar.GridHeader>
                {(day) => <Calendar.HeaderCell>{day}</Calendar.HeaderCell>}
              </Calendar.GridHeader>
              <Calendar.GridBody>
                {(day) => <Calendar.Cell date={day} />}
              </Calendar.GridBody>
            </Calendar.Grid>
            <Calendar.YearPickerGrid>
              <Calendar.YearPickerGridBody>
                {({ year }) => <Calendar.YearPickerCell year={year} />}
              </Calendar.YearPickerGridBody>
            </Calendar.YearPickerGrid>
          </Calendar>
          <div className="flex justify-end border-t border-separator p-2">
            <Button
              variant="tertiary"
              size="sm"
              onPress={() => {
                change('')
                setOpen(false)
              }}
            >
              {clearLabel}
            </Button>
          </div>
        </DatePicker.Popover>
      </DatePicker>
    </I18nProvider>
  )
}
