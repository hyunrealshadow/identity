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
import { UserTextAreaField, UserTextField } from '#/components/form-fields'

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
