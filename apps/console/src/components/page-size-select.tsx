import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'

import { useTranslator } from '#/lib/i18n'
import { PAGE_SIZE_OPTIONS } from '#/lib/page-size'

export function PageSizeSelect({
  value,
  onChange,
  disabled = false,
}: {
  value: number
  onChange: (size: number) => void
  disabled?: boolean
}) {
  const t = useTranslator()
  const items = PAGE_SIZE_OPTIONS.map((size) => ({
    value: String(size),
    label: t('tablePageSizeOption', { count: size }),
  }))
  return (
    <Select
      value={String(value)}
      items={items}
      disabled={disabled}
      onValueChange={(next: string | null) => {
        if (next !== null) onChange(Number(next))
      }}
    >
      <SelectTrigger size="sm" className="w-28" aria-label={t('tablePageSize')}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {items.map((item) => (
          <SelectItem key={item.value} value={item.value}>
            {item.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
