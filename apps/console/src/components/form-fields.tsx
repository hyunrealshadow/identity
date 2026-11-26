import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'
import { Textarea } from '@identity/ui/components/textarea'
import { useId } from 'react'

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
  hideLabel = false,
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
  /** Keep the label for assistive technology when the placeholder explains the field. */
  hideLabel?: boolean
}) {
  const id = useId()
  const descriptionId = `${id}-description`
  const errorId = `${id}-error`
  const describedBy =
    [
      description ? descriptionId : undefined,
      error ? errorId : undefined,
    ]
      .filter(Boolean)
      .join(' ') || undefined

  return (
    <Field data-invalid={error ? true : undefined}>
      <FieldLabel htmlFor={id} className={hideLabel ? 'sr-only' : undefined}>
        {label}
      </FieldLabel>
      <Input
        id={id}
        name={name}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        type={type}
        autoComplete={autoComplete}
        placeholder={placeholder}
        maxLength={maxLength}
        inputMode={inputMode}
        required={isRequired}
        disabled={isDisabled}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
      />
      {description ? (
        <FieldDescription id={descriptionId}>{description}</FieldDescription>
      ) : null}
      {error ? <FieldError id={errorId}>{error}</FieldError> : null}
    </Field>
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
  const id = useId()
  const descriptionId = `${id}-description`
  const errorId = `${id}-error`
  const describedBy =
    [
      description ? descriptionId : undefined,
      error ? errorId : undefined,
    ]
      .filter(Boolean)
      .join(' ') || undefined

  return (
    <Field data-invalid={error ? true : undefined}>
      <FieldLabel htmlFor={id} className={hideLabel ? 'sr-only' : undefined}>
        {label}
      </FieldLabel>
      <Textarea
        id={id}
        name={name}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        rows={rows}
        placeholder={placeholder}
        maxLength={maxLength}
        required={isRequired}
        disabled={isDisabled}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
      />
      {description ? (
        <FieldDescription id={descriptionId}>{description}</FieldDescription>
      ) : null}
      {error ? <FieldError id={errorId}>{error}</FieldError> : null}
    </Field>
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
  const id = useId()
  const descriptionId = `${id}-description`
  const errorId = `${id}-error`
  const describedBy =
    [
      description ? descriptionId : undefined,
      error ? errorId : undefined,
    ]
      .filter(Boolean)
      .join(' ') || undefined
  const items = options.map((option) => ({
    value: option.id,
    label: option.label,
  }))

  return (
    <div className="min-w-0">
      <Field data-invalid={error ? true : undefined}>
        <FieldLabel htmlFor={id} className={hideLabel ? 'sr-only' : undefined}>
          {label}
        </FieldLabel>
        <Select
          name={name}
          value={value}
          onValueChange={(next: string | null) => {
            if (next !== null) onChange(String(next))
          }}
          items={items}
          disabled={isDisabled}
        >
          <SelectTrigger
            id={id}
            size={size === 'sm' ? 'sm' : 'default'}
            className="w-full"
            aria-invalid={error ? true : undefined}
            aria-describedby={describedBy}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {options.map((option) => (
              <SelectItem key={option.id} value={option.id}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {description ? (
          <FieldDescription id={descriptionId}>{description}</FieldDescription>
        ) : null}
        {error ? <FieldError id={errorId}>{error}</FieldError> : null}
      </Field>
    </div>
  )
}
