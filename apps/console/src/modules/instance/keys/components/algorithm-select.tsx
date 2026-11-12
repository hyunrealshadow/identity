import { Field, FieldLabel } from '@identity/ui/components/field'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'
import { useId } from 'react'

import type { ConsoleSigningKeyAlgorithmsQuery } from '#/generated/graphql'

export type SigningKeyOption = ConsoleSigningKeyAlgorithmsQuery['signingKeyAlgorithms'][number]

/** One option: an algorithm with one key it signs with (EdDSA has two). */
export function optionId(option: Pick<SigningKeyOption, 'algorithm' | 'keyAlgorithm'>): string {
  return `${option.algorithm}:${option.keyAlgorithm}`
}

function AlgorithmText({ option }: { option: SigningKeyOption }) {
  return (
    <span className="flex min-w-0 items-baseline gap-2">
      <span className="font-medium">{option.algorithm}</span>
      <span className="truncate text-xs text-muted-foreground">{option.keyName}</span>
    </span>
  )
}

/** A JWA signing algorithm, with the key it generates after it. */
export function AlgorithmSelect({
  label,
  value,
  onChange,
  options,
  isDisabled = false,
}: {
  label: string
  /** The chosen option's {@link optionId}. */
  value: string
  onChange: (option: SigningKeyOption) => void
  options: readonly SigningKeyOption[]
  isDisabled?: boolean
}) {
  const id = useId()
  const byId = new Map(options.map((option) => [optionId(option), option]))
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Select
        value={value}
        onValueChange={(next: string | null) => {
          const option = next ? byId.get(String(next)) : undefined
          if (option) onChange(option)
        }}
        items={options.map((option) => ({
          value: optionId(option),
          label: `${option.algorithm} ${option.keyName}`,
        }))}
        disabled={isDisabled}
      >
        <SelectTrigger id={id} className="w-full">
          <SelectValue>
            {(selected: string | null) => {
              const option = selected ? byId.get(selected) : undefined
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
    </Field>
  )
}
