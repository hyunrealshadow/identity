import {
  DatePickerField as BaseDatePickerField,
  type DatePickerFieldProps as BaseDatePickerFieldProps,
} from './components/date-picker'

export interface DatePickerFieldProps
  extends Omit<BaseDatePickerFieldProps, 'required' | 'disabled' | 'placeholder'> {
  placeholder?: string
  isRequired?: boolean
  isDisabled?: boolean
}

/**
 * Account form adapter: the shared date field with the account-center's
 * `isRequired`/`isDisabled` naming.
 */
export function DatePickerField({
  placeholder,
  isRequired = false,
  isDisabled = false,
  ...props
}: DatePickerFieldProps) {
  return (
    <BaseDatePickerField
      {...props}
      placeholder={placeholder}
      required={isRequired}
      disabled={isDisabled}
    />
  )
}
