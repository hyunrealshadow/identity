import { LocalizedTextField } from '#/components/localized-text-field'
import { SettingsGroup, SettingsRow } from '#/components/settings-section'
import { useTranslator } from '#/lib/i18n'
import type { LocalizedDraft } from '#/lib/localized-values'

export function CreateDetailsStep({
  text,
  onChange,
  nameError,
  descriptionError,
  isDisabled,
}: {
  text: LocalizedDraft
  onChange: (text: LocalizedDraft) => void
  nameError?: string
  descriptionError?: string
  isDisabled: boolean
}) {
  const t = useTranslator()
  return (
    <SettingsGroup>
      <SettingsRow>
        <LocalizedTextField
          name="names"
          label={t('localizedName')}
          defaultValue={text.name}
          onDefaultValueChange={(name) => onChange({ ...text, name })}
          value={text.names}
          onChange={(names) => onChange({ ...text, names })}
          isDisabled={isDisabled}
          isRequired
          maxLength={256}
          error={nameError}
        />
      </SettingsRow>
      <SettingsRow>
        <LocalizedTextField
          name="descriptions"
          label={t('localizedDescription')}
          defaultValue={text.description}
          onDefaultValueChange={(description) => onChange({ ...text, description })}
          value={text.descriptions}
          onChange={(descriptions) => onChange({ ...text, descriptions })}
          isDisabled={isDisabled}
          multiline
          maxLength={1024}
          error={descriptionError}
        />
      </SettingsRow>
    </SettingsGroup>
  )
}
