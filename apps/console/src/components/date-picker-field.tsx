import {
  DatePickerField as SharedDatePickerField,
  type DatePickerFieldProps,
} from '@identity/ui/date-picker-field'
import { useLocale, useTranslator } from '#/lib/i18n'

export function DatePickerField(
  props: Omit<DatePickerFieldProps, 'timeZone' | 'clearLabel' | 'locale'>,
) {
  const { timeZone, locale } = useLocale()
  const t = useTranslator()
  return (
    <SharedDatePickerField
      {...props}
      timeZone={timeZone}
      locale={locale}
      clearLabel={t('dateClear')}
    />
  )
}
