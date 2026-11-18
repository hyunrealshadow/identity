import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
  FieldTitle,
} from '@identity/ui/components/field'
import { RadioGroup, RadioGroupItem } from '@identity/ui/components/radio-group'
import { AppWindow, Globe, Server, Smartphone, type LucideIcon } from 'lucide-react'

import { useTranslator, type MessageKey } from '#/lib/i18n'
import type { ClientKind } from '../../lib/client-form'

export const CLIENT_KINDS: ReadonlyArray<{
  id: ClientKind
  label: MessageKey
  hint: MessageKey
  icon: LucideIcon
}> = [
  { id: 'web', label: 'clientsKindWeb', hint: 'clientsKindWebHint', icon: Globe },
  { id: 'spa', label: 'clientsKindSpa', hint: 'clientsKindSpaHint', icon: AppWindow },
  { id: 'native', label: 'clientsKindNative', hint: 'clientsKindNativeHint', icon: Smartphone },
  { id: 'machine', label: 'clientsKindMachine', hint: 'clientsKindMachineHint', icon: Server },
]

export function CreateKindStep({
  kind,
  onChange,
  isDisabled,
}: {
  kind: ClientKind
  onChange: (kind: ClientKind) => void
  isDisabled: boolean
}) {
  const t = useTranslator()
  return (
    <RadioGroup
      name="client-kind"
      aria-label={t('clientsKind')}
      value={kind}
      disabled={isDisabled}
      onValueChange={(value: string) => onChange(value as ClientKind)}
      className="grid gap-3 sm:grid-cols-2"
    >
      {CLIENT_KINDS.map((entry) => {
        const Icon = entry.icon
        return (
          <FieldLabel key={entry.id} htmlFor={`client-kind-${entry.id}`} className="bg-card">
            <Field orientation="horizontal">
              <span
                className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground"
                aria-hidden="true"
              >
                <Icon className="size-4" />
              </span>
              <FieldContent>
                <FieldTitle>{t(entry.label)}</FieldTitle>
                <FieldDescription>{t(entry.hint)}</FieldDescription>
              </FieldContent>
              <RadioGroupItem value={entry.id} id={`client-kind-${entry.id}`} />
            </Field>
          </FieldLabel>
        )
      })}
    </RadioGroup>
  )
}
