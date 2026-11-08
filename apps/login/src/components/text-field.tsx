import { Field, FieldDescription, FieldError, FieldLabel } from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import { cn } from '@identity/ui/lib/utils'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from '@identity/ui/components/input-group'
import { Eye, EyeOff } from 'lucide-react'
import { useEffect, useId, useRef, useState, type ComponentProps, type ReactNode } from 'react'

import { useFieldValidationError } from '#/components/progressive-form'

type NativeInputProps = Omit<ComponentProps<'input'>, 'id' | 'name' | 'children'>

interface TextFieldProps extends NativeInputProps {
  name: string
  label: ReactNode
  /** Field error; falls back to the enclosing ProgressiveForm's server error. */
  error?: string
  description?: ReactNode
  fieldClassName?: string
  /** Show/hide labels for a password field's visibility toggle. */
  reveal?: { show: string; hide: string }
}

/**
 * Labelled native input. The error stays in the server-rendered markup so the
 * no-JavaScript response still explains a rejected value; after hydration it
 * also becomes the input's custom validity until the value is edited.
 */
export function TextField({
  name,
  label,
  error,
  description,
  fieldClassName,
  reveal,
  type,
  onInput,
  className,
  ...inputProps
}: TextFieldProps) {
  const id = useId()
  const errorId = `${id}-error`
  const descriptionId = `${id}-description`
  const contextError = useFieldValidationError(name)
  const message = error ?? contextError
  const inputRef = useRef<HTMLInputElement>(null)
  const [revealed, setRevealed] = useState(false)

  useEffect(() => {
    inputRef.current?.setCustomValidity(message ?? '')
  }, [message])

  const describedBy = [
    description ? descriptionId : undefined,
    message ? errorId : undefined,
  ].filter(Boolean).join(' ') || undefined
  const controlProps = {
    ...inputProps,
    // A field error colors its label and message, not the entered value.
    className: cn('text-foreground', className),
    ref: inputRef,
    id,
    name,
    type: reveal && revealed ? 'text' : type,
    'aria-invalid': message ? true : undefined,
    'aria-describedby': describedBy,
    onInput: (event: Parameters<NonNullable<NativeInputProps['onInput']>>[0]) => {
      event.currentTarget.setCustomValidity('')
      onInput?.(event)
    },
  }

  return (
    <Field data-invalid={message ? true : undefined} className={fieldClassName}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      {reveal ? (
        <InputGroup>
          <InputGroupInput {...controlProps} />
          <InputGroupAddon align="inline-end">
            <InputGroupButton
              size="icon-xs"
              aria-label={revealed ? reveal.hide : reveal.show}
              aria-controls={id}
              aria-pressed={revealed}
              className="js-only"
              onClick={() => setRevealed((value) => !value)}
            >
              {revealed ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
            </InputGroupButton>
          </InputGroupAddon>
        </InputGroup>
      ) : (
        <Input {...controlProps} />
      )}
      {description ? <FieldDescription id={descriptionId}>{description}</FieldDescription> : null}
      {message ? <FieldError id={errorId}>{message}</FieldError> : null}
    </Field>
  )
}
