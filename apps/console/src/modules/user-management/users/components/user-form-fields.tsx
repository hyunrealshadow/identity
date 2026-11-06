import {
  Description,
  FieldError,
  Input,
  Label,
  ListBox,
  Select,
  TextArea,
  TextField,
} from '@heroui/react'

import {
  USER_PROFILE_DATE_FIELDS,
  USER_PROFILE_LABEL_KEYS,
  USER_PROFILE_MULTILINE_FIELDS,
} from '#/modules/user-management/users/lib/user-field-meta'
import {
  USER_PROFILE_FIELDS,
  type UserProfileDraft,
  type UserProfileField,
} from '#/modules/user-management/users/lib/user-form'
import { useTranslator } from '#/lib/i18n'
import { DatePickerField } from '#/components/date-picker-field'

export interface SelectOption {
  id: string
  label: string
}

export function UserTextField({
  name,
  label,
  value,
  onChange,
  type = 'text',
  autoComplete,
  placeholder,
  description,
  error,
  isRequired = false,
  isDisabled = false,
  maxLength,
  inputMode,
}: {
  name: string
  label: string
  value: string
  onChange: (value: string) => void
  type?: 'text' | 'email' | 'password' | 'url'
  autoComplete?: string
  placeholder?: string
  description?: string
  error?: string
  isRequired?: boolean
  isDisabled?: boolean
  maxLength?: number
  inputMode?: 'text' | 'email' | 'numeric'
}) {
  return (
    <TextField
      name={name}
      value={value}
      onChange={onChange}
      type={type}
      isRequired={isRequired}
      isDisabled={isDisabled}
      isInvalid={Boolean(error)}
      fullWidth
    >
      <Label>{label}</Label>
      <Input
        type={type}
        autoComplete={autoComplete}
        placeholder={placeholder}
        maxLength={maxLength}
        inputMode={inputMode}
      />
      {description ? <Description>{description}</Description> : null}
      {error ? <FieldError>{error}</FieldError> : null}
    </TextField>
  )
}

export function UserTextAreaField({
  name,
  label,
  value,
  onChange,
  placeholder,
  description,
  error,
  isRequired = false,
  isDisabled = false,
  maxLength,
  rows = 4,
  hideLabel = false,
}: {
  name: string
  label: string
  value: string
  onChange: (value: string) => void
  placeholder?: string
  description?: string
  error?: string
  isRequired?: boolean
  isDisabled?: boolean
  maxLength?: number
  rows?: number
  /** Keep the label for assistive technology when the row shows it already. */
  hideLabel?: boolean
}) {
  return (
    <TextField
      name={name}
      value={value}
      onChange={onChange}
      isRequired={isRequired}
      isDisabled={isDisabled}
      isInvalid={Boolean(error)}
      fullWidth
    >
      <Label className={hideLabel ? 'sr-only' : undefined}>{label}</Label>
      <TextArea
        rows={rows}
        placeholder={placeholder}
        maxLength={maxLength}
        fullWidth
      />
      {description ? <Description>{description}</Description> : null}
      {error ? <FieldError>{error}</FieldError> : null}
    </TextField>
  )
}

export function UserSelectField({
  name,
  label,
  value,
  onChange,
  options,
  description,
  error,
  isDisabled = false,
  hideLabel = false,
  size,
}: {
  name: string
  label: string
  value: string
  onChange: (value: string) => void
  options: ReadonlyArray<SelectOption>
  description?: string
  error?: string
  isDisabled?: boolean
  /** Keep the label for assistive technology when the row shows it already. */
  hideLabel?: boolean
  /** One step below the default trigger height, for inline toolbar controls. */
  size?: 'sm'
}) {
  return (
    <div className="min-w-0">
      <Select
        name={name}
        selectedKey={value}
        onSelectionChange={(key) => {
          if (key !== null) onChange(String(key))
        }}
        isDisabled={isDisabled}
        isInvalid={Boolean(error)}
        fullWidth
      >
        <Label className={hideLabel ? 'sr-only' : undefined}>{label}</Label>
        <Select.Trigger className={size === 'sm' ? 'min-h-8 py-1' : undefined}>
          <Select.Value />
          <Select.Indicator />
        </Select.Trigger>
        <Select.Popover>
          <ListBox>
            {options.map((option) => (
              <ListBox.Item
                key={option.id}
                id={option.id}
                textValue={option.label}
              >
                {option.label}
              </ListBox.Item>
            ))}
          </ListBox>
        </Select.Popover>
      </Select>
      {description ? (
        <p className="mt-1 text-xs leading-5 text-muted">{description}</p>
      ) : null}
      {error ? (
        <p role="alert" className="mt-1 text-xs leading-5 text-danger">
          {error}
        </p>
      ) : null}
    </div>
  )
}

export function UserProfileFields({
  draft,
  onChange,
  errors,
  isDisabled = false,
  fields = USER_PROFILE_FIELDS,
}: {
  draft: UserProfileDraft
  onChange: (field: UserProfileField, value: string) => void
  errors: Record<string, string>
  isDisabled?: boolean
  fields?: ReadonlyArray<UserProfileField>
}) {
  const t = useTranslator()

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {fields.map((field) => {
        const label = t(USER_PROFILE_LABEL_KEYS[field])
        const error = errors[field]
        const common = {
          name: `profile.${field}`,
          label,
          value: draft[field],
          onChange: (value: string) => onChange(field, value),
          error,
          isDisabled,
        }

        if (USER_PROFILE_MULTILINE_FIELDS.includes(field)) {
          return (
            <div key={field} className="sm:col-span-2">
              <UserTextAreaField {...common} rows={4} />
            </div>
          )
        }

        if (USER_PROFILE_DATE_FIELDS.includes(field)) {
          return <DatePickerField key={field} {...common} />
        }

        return <UserTextField key={field} {...common} />
      })}
    </div>
  )
}
