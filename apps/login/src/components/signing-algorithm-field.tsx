import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from '@identity/ui/components/field'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'
import { useId, useState } from 'react'

import { useFieldValidationError } from '#/components/progressive-form'
import type { SigningAlgorithmOption } from '#/lib/identity-types'

/** One option: an algorithm with one key it signs with (EdDSA has two). */
function optionId(option: SigningAlgorithmOption): string {
  return `${option.signing_algorithm}:${option.key_algorithm}`
}

function AlgorithmText({ option }: { option: SigningAlgorithmOption }) {
  return (
    <span className="flex min-w-0 items-baseline gap-2">
      <span className="font-medium">{option.signing_algorithm}</span>
      <span className="truncate text-xs text-muted-foreground">{option.key_name}</span>
    </span>
  )
}

/**
 * The signing algorithm of the first key, led by its JWA name with the key
 * behind it after, as in the Console. Submits `signing_algorithm` and
 * `key_algorithm` as the two enum values of the chosen option.
 */
export function SigningAlgorithmField({
  label,
  description,
  options,
  defaultValue,
}: {
  label: string
  description?: string
  options: readonly SigningAlgorithmOption[]
  /** The {@link optionId} selected first, such as `ES256:ECDSA_P256`. */
  defaultValue: string
}) {
  const id = useId()
  const errorId = `${id}-error`
  const descriptionId = `${id}-description`
  const message = useFieldValidationError('signing_algorithm')
  const byId = new Map(options.map((option) => [optionId(option), option]))
  const [choice, setChoice] = useState(defaultValue)
  const selected = byId.get(choice) ?? options[0]
  const describedBy =
    [description ? descriptionId : undefined, message ? errorId : undefined]
      .filter(Boolean)
      .join(' ') || undefined

  return (
    <Field data-invalid={message ? true : undefined}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      {selected ? (
        <>
          <input type="hidden" name="signing_algorithm" value={selected.signing_algorithm} />
          <input type="hidden" name="key_algorithm" value={selected.key_algorithm} />
        </>
      ) : null}
      <Select
        value={selected ? optionId(selected) : ''}
        onValueChange={(next: string | null) => {
          if (next !== null) setChoice(String(next))
        }}
        items={options.map((option) => ({
          value: optionId(option),
          label: `${option.signing_algorithm} ${option.key_name}`,
        }))}
      >
        <SelectTrigger
          id={id}
          className="w-full"
          aria-invalid={message ? true : undefined}
          aria-describedby={describedBy}
        >
          <SelectValue>
            {(value: string | null) => {
              const option = value ? byId.get(value) : undefined
              return option ? <AlgorithmText option={option} /> : null
            }}
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={optionId(option)} value={optionId(option)}>
              <AlgorithmText option={option} />
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {description ? <FieldDescription id={descriptionId}>{description}</FieldDescription> : null}
      {message ? <FieldError id={errorId}>{message}</FieldError> : null}
    </Field>
  )
}
