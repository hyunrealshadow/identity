import { AuthenticationContextClass } from '@identity/graphql-access'
import {
  Combobox,
  ComboboxChip,
  ComboboxChips,
  ComboboxChipsInput,
  ComboboxCollection,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxGroup,
  ComboboxItem,
  ComboboxLabel,
  ComboboxList,
  ComboboxSeparator,
  ComboboxValue,
  useComboboxAnchor,
} from '@identity/ui/components/combobox'
import { Skeleton } from '@identity/ui/components/skeleton'
import { cn } from '@identity/ui/lib/utils'
import { Link } from '@tanstack/react-router'
import { GripVertical } from 'lucide-react'
import { useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'

import {
  SettingsNumberInput,
  SettingsRow,
  SettingsSelect,
  SettingsSwitch,
} from '#/components/settings-section'
import type { ClientSubjectType } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { fieldAffordance } from '#/lib/graphql/affordances'
import { keyScope } from '#/lib/key-scope'
import {
  UserTextAreaField,
  UserTextField,
} from '#/components/form-fields'
import type { ClientKeyCoverage } from '../hooks/use-client-key-coverage'
import type { ClientMetadataOptions } from '../hooks/use-client-metadata-options'
import {
  MAX_DEFAULT_MAX_AGE_SECONDS,
  type ClientAdvancedDraft,
  type ClientAdvancedField,
} from '../lib/advanced-form'

export interface AdvancedFieldsProps {
  draft: ClientAdvancedDraft
  onChange: (next: ClientAdvancedDraft) => void
  errors: Partial<Record<ClientAdvancedField, string>>
  isDisabled?: boolean
}

interface OptionProps extends AdvancedFieldsProps {
  /** `null` while the provider's supported values load. */
  options: ClientMetadataOptions | null
  /** The client whose credentials back some choices. */
  clientId?: string
  /** What the client's credentials serve; `null` when unknown or unreadable. */
  clientKeys?: ClientKeyCoverage | null
}

/** Where a missing key is fixed: instance keys or the client's credentials. */
type KeyManagement = 'signing-keys' | 'encryption-keys' | 'client-credentials'

/** What a row says when no selected value has a key, and who can fix it. */
interface MissingKey {
  /** The consequence, followed by a link for someone who can fix it. */
  message: MessageKey
  /** The consequence and whom to ask, for everyone else. */
  contact: MessageKey
  manage: KeyManagement
}

type ListField = {
  [K in ClientAdvancedField]: ClientAdvancedDraft[K] extends string[] ? K : never
}[ClientAdvancedField]

type TextField = {
  [K in ClientAdvancedField]: ClientAdvancedDraft[K] extends string ? K : never
}[ClientAdvancedField]

type FlagField = {
  [K in ClientAdvancedField]: ClientAdvancedDraft[K] extends boolean ? K : never
}[ClientAdvancedField]

function RowError({ children }: { children?: string }) {
  return children ? (
    <p role="alert" className="mt-2 text-xs leading-5 text-destructive">
      {children}
    </p>
  ) : null
}

type AlgorithmFamily = { id: string; label?: string; pattern: RegExp }

/**
 * JOSE algorithm families, in the order the picker lists them. Family names
 * are standard algorithm names and stay untranslated; anything else (levels,
 * `none`, `dir`) falls into an unlabelled or "other" group.
 */
const ALGORITHM_FAMILIES: readonly AlgorithmFamily[] = [
  { id: 'rsa', label: 'RSA', pattern: /^(RS\d+|RSA1_5|RSA-OAEP(-\d+)?)$/ },
  { id: 'rsa-pss', label: 'RSA-PSS', pattern: /^PS\d+$/ },
  { id: 'ecdsa', label: 'ECDSA', pattern: /^ES\d+K?$/ },
  { id: 'eddsa', label: 'EdDSA', pattern: /^(EdDSA|Ed25519|Ed448)$/ },
  { id: 'hmac', label: 'HMAC', pattern: /^HS\d+$/ },
  { id: 'ecdh', label: 'ECDH-ES', pattern: /^ECDH-ES(\+A\d+KW)?$/ },
  { id: 'aes-kw', label: 'AES Key Wrap', pattern: /^A\d+(GCM)?KW$/ },
  { id: 'pbes2', label: 'PBES2', pattern: /^PBES2-/ },
  { id: 'aes-cbc', label: 'AES-CBC-HMAC', pattern: /^A\d+CBC-HS\d+$/ },
  { id: 'aes-gcm', label: 'AES-GCM', pattern: /^A\d+GCM$/ },
]

interface ChoiceGroup {
  value: string
  label?: string
  items: string[]
}

function groupChoices(choices: readonly string[], otherLabel: string): ChoiceGroup[] {
  const groups = new Map<string, ChoiceGroup>()
  for (const choice of choices) {
    const family = ALGORITHM_FAMILIES.find((candidate) => candidate.pattern.test(choice))
    const key = family?.id ?? 'other'
    const group = groups.get(key) ?? { value: key, label: family?.label, items: [] }
    group.items.push(choice)
    groups.set(key, group)
  }
  const ordered = [
    ...ALGORITHM_FAMILIES.flatMap(({ id }) => groups.get(id) ?? []),
    ...(groups.get('other') ? [groups.get('other') as ChoiceGroup] : []),
  ]
  // A list with no algorithm family at all (levels) needs no headings.
  if (ordered.length === 1 && ordered[0].value === 'other') return ordered
  return ordered.map((group) =>
    group.value === 'other' ? { ...group, label: otherLabel } : group,
  )
}

function ActiveKeyDot({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center">
      <span aria-hidden="true" className="size-1.5 rounded-full bg-success" />
      <span className="sr-only">{label}</span>
    </span>
  )
}

/** Moves `value` to `index` within `values`. */
function moveTo(values: readonly string[], value: string, index: number): string[] {
  const rest = values.filter((item) => item !== value)
  return [...rest.slice(0, index), value, ...rest.slice(index)]
}

/**
 * Reordering for chips whose order the runtime follows. A pointer (mouse,
 * pen or touch) drags a chip over another once it has moved a few pixels, so
 * a plain click and the remove button keep working. From the keyboard, a
 * focused chip moves with Alt and the arrow keys; Base UI already uses plain
 * arrows to move focus between chips and Backspace to remove one.
 */
function useChipReorder({
  values,
  enabled,
  onReorder,
  announce,
}: {
  values: readonly string[]
  enabled: boolean
  onReorder: (next: string[]) => void
  announce: (value: string, position: number) => void
}) {
  const drag = useRef<{ value: string; x: number; y: number; active: boolean } | null>(null)
  const [dragging, setDragging] = useState<string | null>(null)

  const finish = () => {
    drag.current = null
    setDragging(null)
  }

  const chipProps = (value: string) => {
    if (!enabled) return {}
    return {
      'data-chip-value': value,
      'aria-keyshortcuts': 'Alt+ArrowLeft Alt+ArrowRight',
      onPointerDown(event: PointerEvent<HTMLDivElement>) {
        if (event.button !== 0) return
        if ((event.target as Element).closest('[data-slot=combobox-chip-remove]')) return
        // Keeps the press from opening the list or selecting text.
        event.preventDefault()
        event.currentTarget.setPointerCapture(event.pointerId)
        drag.current = { value, x: event.clientX, y: event.clientY, active: false }
      },
      onPointerMove(event: PointerEvent<HTMLDivElement>) {
        const current = drag.current
        if (!current) return
        if (!current.active) {
          if (Math.hypot(event.clientX - current.x, event.clientY - current.y) < 5) return
          current.active = true
          setDragging(current.value)
        }
        const target = document
          .elementFromPoint(event.clientX, event.clientY)
          ?.closest<HTMLElement>('[data-chip-value]')?.dataset.chipValue
        if (!target || target === current.value) return
        const index = values.indexOf(target)
        if (index < 0) return
        onReorder(moveTo(values, current.value, index))
      },
      onPointerUp(event: PointerEvent<HTMLDivElement>) {
        const current = drag.current
        if (current?.active) announce(current.value, values.indexOf(current.value) + 1)
        if (event.currentTarget.hasPointerCapture(event.pointerId)) {
          event.currentTarget.releasePointerCapture(event.pointerId)
        }
        finish()
      },
      onPointerCancel: finish,
      // Runs before Base UI's own chip key handling, which would otherwise
      // treat Alt+Arrow as focus movement.
      onKeyDownCapture(event: KeyboardEvent<HTMLDivElement>) {
        if (!event.altKey || (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight')) return
        event.preventDefault()
        event.stopPropagation()
        const from = values.indexOf(value)
        const to = from + (event.key === 'ArrowLeft' ? -1 : 1)
        if (from < 0 || to < 0 || to >= values.length) return
        onReorder(moveTo(values, value, to))
        announce(value, to + 1)
      },
    }
  }

  return { chipProps, dragging }
}

/**
 * An algorithm (or level) choice picked from the provider's supported values.
 * An empty selection stores nothing, so the provider's default behaviour
 * applies, which `autoHint` describes. In an `ordered` row the runtime tries
 * the selection in turn, so new values join the end and chips can be
 * reordered; other rows are sets and keep the provider's order. A stored
 * value the provider no longer supports stays selectable for removal and is
 * marked. With `keyed`, values backed by a usable key (the provider's, or
 * the client's registered credentials) are marked; a selected value without
 * one stays valid, because keys come and go, but the runtime skips it, and
 * `missingKey` says what fails when none is left. `keyed` is omitted while
 * coverage is unknown, which then claims nothing. `resolves` rows name the
 * algorithm the runtime would pick now.
 */
function ChoiceRow({
  field,
  label,
  description,
  supported,
  labels,
  keyed,
  resolves = false,
  ordered = false,
  keyless,
  missingKey,
  clientId,
  autoHint,
  draft,
  onChange,
  errors,
  isDisabled = false,
}: AdvancedFieldsProps & {
  field: ListField
  label: MessageKey
  description?: MessageKey
  supported: readonly string[] | undefined
  labels?: Partial<Record<string, MessageKey>>
  /** Values the provider holds an active key for. */
  keyed?: readonly string[]
  /** Whether the runtime issues with the first selected value that has a key. */
  resolves?: boolean
  /** Whether the runtime follows the selection's order, which is then editable. */
  ordered?: boolean
  /** Values usable without any key, such as an unsigned request object. */
  keyless?: readonly string[]
  missingKey?: MissingKey
  /** The client whose credentials page fixes a `client-credentials` gap. */
  clientId?: string
  autoHint: MessageKey
}) {
  const t = useTranslator()
  const anchor = useComboboxAnchor()
  const selected = draft[field]
  const available = supported ?? []
  const retired = selected.filter((value) => !available.includes(value))
  const choices = [...available, ...retired]
  const groups = groupChoices(choices, t('clientsAlgorithmGroupOther'))
  const display = (value: string) => (labels?.[value] ? t(labels[value]) : value)
  const technical = (value: string) => !labels?.[value]
  const hasKey = (value: string) => keyed?.includes(value) ?? false
  const usable = (value: string) => hasKey(value) || (keyless?.includes(value) ?? false)
  const effective = keyed ? selected.find(usable) : undefined
  const unusable = keyed !== undefined && selected.length > 0 && effective === undefined
  const permissions = useWorkspace().data?.effectivePermissions
  const keys = keyScope(permissions)
  // Only someone who can fix the gap is sent to fix it: a new signing key, a
  // rotated encryption key, or a public key registered for the client.
  const canManage =
    missingKey?.manage === 'signing-keys'
      ? keys.create
      : missingKey?.manage === 'encryption-keys'
        ? keys.rotate
        : missingKey?.manage === 'client-credentials'
          ? Boolean(clientId) && fieldAffordance(permissions, 'mutation', 'addClientPublicKey')
          : false
  const linkClass = 'font-medium text-link'
  const manageLink =
    missingKey?.manage === 'client-credentials' && clientId ? (
      <Link to="/clients/$clientId/credentials" params={{ clientId }} className={linkClass}>
        {t('clientsAlgorithmManageCredentials')}
      </Link>
    ) : missingKey?.manage === 'signing-keys' ? (
      <Link to="/settings/signing-keys" className={linkClass}>
        {t('clientsAlgorithmManageKeys')}
      </Link>
    ) : missingKey?.manage === 'encryption-keys' ? (
      <Link to="/settings/encryption-keys" className={linkClass}>
        {t('clientsAlgorithmManageKeys')}
      </Link>
    ) : null

  const status = unusable ? (
    <span className="block text-warning">
      {!missingKey ? (
        t('clientsAlgorithmNoKeyedSelection')
      ) : canManage && manageLink ? (
        <>
          {t(missingKey.message)} {manageLink}
        </>
      ) : (
        t(missingKey.contact)
      )}
    </span>
  ) : resolves && effective ? (
    <span className="flex items-center gap-1.5">
      <span aria-hidden="true" className="size-1.5 rounded-full bg-success" />
      {t('clientsAlgorithmEffective', { algorithm: effective })}
    </span>
  ) : null
  // Reordering is offered in words as well as by the grip, so it is found
  // without hovering a chip first.
  const reorderable = ordered && !isDisabled && selected.length > 1
  const rowHint = description ? t(description) : undefined
  const hint =
    selected.length === 0
      ? t(autoHint)
      : reorderable
        ? rowHint
          ? t('clientsAlgorithmReorderableHint', { hint: rowHint })
          : t('clientsAlgorithmReorderHint')
        : rowHint
  const [announcement, setAnnouncement] = useState('')
  const reorder = useChipReorder({
    values: selected,
    enabled: reorderable,
    onReorder: (next) => onChange({ ...draft, [field]: next }),
    announce: (value, position) =>
      setAnnouncement(t('clientsAlgorithmMoved', { algorithm: display(value), position })),
  })

  return (
    <SettingsRow
      label={t(label)}
      description={
        hint || status ? (
          <>
            {hint ? <span className="block">{hint}</span> : null}
            {status}
          </>
        ) : undefined
      }
      action={
        <div className="flex justify-end">
          {!supported && choices.length === 0 ? (
            <Skeleton aria-busy="true" className="h-9 w-40 rounded-md" />
          ) : choices.length === 0 ? (
            <p className="text-right text-xs text-muted-foreground">
              {t('clientsAlgorithmNoneAvailable')}
            </p>
          ) : (
            <Combobox<string, true>
              multiple
              autoHighlight
              items={groups}
              value={selected}
              onValueChange={(next, details) => {
                // Escape on a closed list clears every chip; in a settings form
                // a stray key press must not discard the whole selection.
                if (details.reason === 'escape-key') return
                onChange({
                  ...draft,
                  [field]: ordered
                    ? next.filter((value) => choices.includes(value))
                    : choices.filter((choice) => next.includes(choice)),
                })
              }}
              itemToStringLabel={display}
              disabled={isDisabled}
            >
              <ComboboxChips
                ref={anchor}
                // Empty, it matches the row's other 160px controls; chips widen
                // it up to a limit and then wrap.
                className="w-fit max-w-56 min-w-40 sm:max-w-80"
              >
                <ComboboxValue>
                  {(values: string[]) => (
                    <>
                      {values.map((value) => {
                        const isRetired = retired.includes(value)
                        const missingKey = keyed !== undefined && !isRetired && !hasKey(value)
                        return (
                          <ComboboxChip
                            key={value}
                            {...reorder.chipProps(value)}
                            title={reorderable ? t('clientsAlgorithmReorderHint') : undefined}
                            className={cn(
                              missingKey && 'text-muted-foreground',
                              isRetired && 'text-warning',
                              reorderable && 'cursor-grab touch-none pl-0.5 active:cursor-grabbing',
                              reorder.dragging === value && 'opacity-50',
                            )}
                          >
                            {reorderable ? (
                              <GripVertical
                                aria-hidden="true"
                                className="size-3 shrink-0 text-muted-foreground"
                              />
                            ) : null}
                            {keyed && hasKey(value) ? (
                              <ActiveKeyDot label={t('clientsAlgorithmHasActiveKey')} />
                            ) : null}
                            <span className={technical(value) ? 'font-mono' : undefined}>
                              {display(value)}
                            </span>
                            {missingKey ? (
                              <span className="sr-only">{t('clientsAlgorithmNoActiveKey')}</span>
                            ) : null}
                            {isRetired ? (
                              <span className="sr-only">{t('clientsAlgorithmUnavailable')}</span>
                            ) : null}
                          </ComboboxChip>
                        )
                      })}
                      <ComboboxChipsInput
                        aria-label={t(label)}
                        // No intrinsic width, so the field sizes to its chips.
                        className="w-0 min-w-10"
                        placeholder={
                          values.length > 0
                            ? t('clientsAlgorithmAdd')
                            : t('clientsAlgorithmAutomatic')
                        }
                      />
                    </>
                  )}
                </ComboboxValue>
              </ComboboxChips>
              <ComboboxContent anchor={anchor} className="w-auto min-w-56">
                <ComboboxEmpty>{t('clientsAlgorithmNoMatch')}</ComboboxEmpty>
                <ComboboxList>
                  {(group: ChoiceGroup, index: number) => (
                    <ComboboxGroup key={group.value} items={group.items}>
                      {index > 0 && group.label ? <ComboboxSeparator /> : null}
                      {group.label ? <ComboboxLabel>{group.label}</ComboboxLabel> : null}
                      <ComboboxCollection>
                        {(value: string) => (
                          <ComboboxItem key={value} value={value}>
                            <span className={technical(value) ? 'font-mono text-xs' : undefined}>
                              {display(value)}
                            </span>
                            {retired.includes(value) ? (
                              <span className="ml-auto text-xs text-warning">
                                {t('clientsAlgorithmUnavailable')}
                              </span>
                            ) : keyed && hasKey(value) ? (
                              <span className="ml-auto flex items-center gap-1.5 text-xs text-muted-foreground">
                                <span aria-hidden="true" className="size-1.5 rounded-full bg-success" />
                                {t('clientsAlgorithmHasActiveKey')}
                              </span>
                            ) : null}
                          </ComboboxItem>
                        )}
                      </ComboboxCollection>
                    </ComboboxGroup>
                  )}
                </ComboboxList>
              </ComboboxContent>
            </Combobox>
          )}
        </div>
      }
    >
      <span role="status" aria-live="polite" className="sr-only">
        {announcement}
      </span>
      {errors[field] ? <RowError>{errors[field]}</RowError> : null}
    </SettingsRow>
  )
}

function UriRow({
  field,
  label,
  description,
  placeholder,
  draft,
  onChange,
  errors,
  isDisabled = false,
}: AdvancedFieldsProps & {
  field: TextField
  label: MessageKey
  description: MessageKey
  placeholder: string
}) {
  const t = useTranslator()
  return (
    <SettingsRow label={t(label)} description={t(description)}>
      <UserTextField
        name={field}
        label={t(label)}
        hideLabel
        type="url"
        placeholder={placeholder}
        value={draft[field]}
        onChange={(value) => onChange({ ...draft, [field]: value })}
        error={errors[field]}
        isDisabled={isDisabled}
      />
    </SettingsRow>
  )
}

function SwitchRow({
  field,
  label,
  description,
  draft,
  onChange,
  isDisabled = false,
}: Omit<AdvancedFieldsProps, 'errors'> & {
  field: FlagField
  label: MessageKey
  description: MessageKey
}) {
  const t = useTranslator()
  return (
    <SettingsRow
      label={t(label)}
      description={t(description)}
      action={
        <SettingsSwitch
          label={t(label)}
          isSelected={draft[field]}
          onChange={(value) => onChange({ ...draft, [field]: value })}
          isDisabled={isDisabled}
        />
      }
    />
  )
}

/** Links and contacts shown to users on sign-in and consent pages. */
export function ApplicationLinkRows(props: AdvancedFieldsProps) {
  const t = useTranslator()
  const { draft, onChange, errors, isDisabled = false } = props
  return (
    <>
      <UriRow
        {...props}
        field="logoUri"
        label="clientsLogoUri"
        description="clientsLogoUriHint"
        placeholder="https://app.example.com/logo.png"
      />
      <UriRow
        {...props}
        field="clientUri"
        label="clientsClientUri"
        description="clientsClientUriHint"
        placeholder="https://app.example.com"
      />
      <UriRow
        {...props}
        field="policyUri"
        label="clientsPolicyUri"
        description="clientsPolicyUriHint"
        placeholder="https://app.example.com/privacy"
      />
      <UriRow
        {...props}
        field="tosUri"
        label="clientsTosUri"
        description="clientsTosUriHint"
        placeholder="https://app.example.com/terms"
      />
      <SettingsRow label={t('clientsContacts')} description={t('clientsContactsHint')}>
        <UserTextAreaField
          name="contacts"
          label={t('clientsContacts')}
          hideLabel
          placeholder="ops@example.com"
          value={draft.contacts}
          onChange={(contacts) => onChange({ ...draft, contacts })}
          error={errors.contacts}
          isDisabled={isDisabled}
          rows={2}
        />
      </SettingsRow>
    </>
  )
}

/** Front-channel and back-channel logout notifications. */
export function LogoutChannelRows(props: AdvancedFieldsProps) {
  return (
    <>
      <UriRow
        {...props}
        field="frontchannelLogoutUri"
        label="clientsFrontchannelLogoutUri"
        description="clientsFrontchannelLogoutUriHint"
        placeholder="https://app.example.com/logout/frontchannel"
      />
      <SwitchRow
        {...props}
        field="frontchannelLogoutSessionRequired"
        label="clientsFrontchannelSessionRequired"
        description="clientsFrontchannelSessionRequiredHint"
      />
      <UriRow
        {...props}
        field="backchannelLogoutUri"
        label="clientsBackchannelLogoutUri"
        description="clientsBackchannelLogoutUriHint"
        placeholder="https://app.example.com/logout/backchannel"
      />
      <SwitchRow
        {...props}
        field="backchannelLogoutSessionRequired"
        label="clientsBackchannelSessionRequired"
        description="clientsBackchannelSessionRequiredHint"
      />
    </>
  )
}

const SUBJECT_LABELS: Record<ClientSubjectType, MessageKey> = {
  PUBLIC: 'clientsSubjectPublic',
  PAIRWISE: 'clientsSubjectPairwise',
}

/** How the `sub` claim is formed, and the sector a pairwise one belongs to. */
export function SubjectRows(props: OptionProps) {
  const t = useTranslator()
  const { draft, onChange, isDisabled = false, options } = props
  const supported = options?.subjectTypes ?? ['public', 'pairwise']
  const choices = (Object.keys(SUBJECT_LABELS) as ClientSubjectType[]).filter(
    (type) => supported.includes(type.toLowerCase()) || draft.subjectType === type,
  )
  return (
    <>
      <SettingsRow
        label={t('clientsSubjectType')}
        description={t(
          draft.subjectType === 'PAIRWISE'
            ? 'clientsSubjectPairwiseHint'
            : 'clientsSubjectPublicHint',
        )}
        action={
          <SettingsSelect
            label={t('clientsSubjectType')}
            value={draft.subjectType}
            onChange={(value) =>
              onChange({ ...draft, subjectType: value as ClientSubjectType })
            }
            options={choices.map((type) => ({ id: type, label: t(SUBJECT_LABELS[type]) }))}
            isDisabled={isDisabled}
          />
        }
      />
      {draft.subjectType === 'PAIRWISE' ? (
        <UriRow
          {...props}
          field="sectorIdentifierUri"
          label="clientsSectorIdentifierUri"
          description="clientsSectorIdentifierUriHint"
          placeholder="https://app.example.com/sector.json"
        />
      ) : null}
    </>
  )
}

const ACR_LABELS: Partial<Record<string, MessageKey>> = {
  [AuthenticationContextClass.SingleFactor]: 'clientsAcrSingleFactor',
  [AuthenticationContextClass.MultiFactor]: 'clientsAcrMultiFactor',
  [AuthenticationContextClass.PhishingResistant]: 'clientsAcrPhishingResistant',
}

/** Defaults applied when an authorization request does not ask itself. */
export function AuthenticationRequirementRows(props: OptionProps) {
  const t = useTranslator()
  const { draft, onChange, errors, isDisabled = false, options } = props
  return (
    <>
      <SettingsRow
        label={t('clientsDefaultMaxAge')}
        description={t('clientsDefaultMaxAgeHint')}
        action={
          <SettingsNumberInput
            name="defaultMaxAge"
            label={t('clientsDefaultMaxAge')}
            value={draft.defaultMaxAge}
            onChange={(defaultMaxAge) => onChange({ ...draft, defaultMaxAge })}
            min={0}
            max={MAX_DEFAULT_MAX_AGE_SECONDS}
            unit={t('clientsSecondsUnit')}
            invalid={Boolean(errors.defaultMaxAge)}
            isDisabled={isDisabled}
          />
        }
      >
        {errors.defaultMaxAge ? <RowError>{errors.defaultMaxAge}</RowError> : null}
      </SettingsRow>
      <SwitchRow
        {...props}
        field="requireAuthTime"
        label="clientsRequireAuthTime"
        description="clientsRequireAuthTimeHint"
      />
      <ChoiceRow
        {...props}
        field="defaultAcrValues"
        ordered
        autoHint="clientsAutoRequestDecides"
        label="clientsDefaultAcrValues"
        description="clientsDefaultAcrValuesHint"
        supported={options?.acrValues}
        labels={ACR_LABELS}
      />
    </>
  )
}

/** ID Token and UserInfo signing and encryption. */
export function TokenProtectionRows(props: OptionProps) {
  const { options, clientKeys } = props
  return (
    <>
      <ChoiceRow
        {...props}
        field="idTokenSignedResponseAlgs"
        ordered
        autoHint="clientsAutoActiveSigningKey"
        label="clientsIdTokenSigning"
        description="clientsIdTokenSigningHint"
        supported={options?.idTokenSigningAlgs}
        keyed={options?.activeSigningAlgs}
        resolves
        missingKey={{
          message: 'clientsIdTokenSigningNoKey',
          contact: 'clientsIdTokenSigningNoKeyContact',
          manage: 'signing-keys',
        }}
      />
      <ChoiceRow
        {...props}
        field="idTokenEncryptedResponseAlgs"
        ordered
        autoHint="clientsAutoNoEncryption"
        label="clientsIdTokenEncryptionAlg"
        description="clientsEncryptionAlgHint"
        supported={options?.idTokenEncryptionAlgs}
        keyed={clientKeys?.coverage.encryptionAlgs}
        resolves
        missingKey={{
          message: 'clientsIdTokenEncryptionNoKey',
          contact: 'clientsIdTokenEncryptionNoKeyContact',
          manage: 'client-credentials',
        }}
      />
      <ChoiceRow
        {...props}
        field="idTokenEncryptedResponseEncs"
        ordered
        autoHint={
          props.draft.idTokenEncryptedResponseAlgs.length > 0
            ? 'clientsAutoDefaultContentEncryption'
            : 'clientsAutoContentEncryptionOff'
        }
        label="clientsIdTokenEncryptionEnc"
        supported={options?.idTokenEncryptionEncs}
      />
      <ChoiceRow
        {...props}
        field="userinfoSignedResponseAlgs"
        ordered
        autoHint="clientsAutoUnsignedUserinfo"
        label="clientsUserinfoSigning"
        description="clientsUserinfoSigningHint"
        supported={options?.userinfoSigningAlgs}
        keyed={options?.activeSigningAlgs}
        resolves
        missingKey={{
          message: 'clientsUserinfoSigningNoKey',
          contact: 'clientsUserinfoSigningNoKeyContact',
          manage: 'signing-keys',
        }}
      />
      <ChoiceRow
        {...props}
        field="userinfoEncryptedResponseAlgs"
        ordered
        autoHint="clientsAutoNoEncryption"
        label="clientsUserinfoEncryptionAlg"
        description="clientsEncryptionAlgHint"
        supported={options?.userinfoEncryptionAlgs}
        keyed={clientKeys?.coverage.encryptionAlgs}
        resolves
        missingKey={{
          message: 'clientsUserinfoEncryptionNoKey',
          contact: 'clientsUserinfoEncryptionNoKeyContact',
          manage: 'client-credentials',
        }}
      />
      <ChoiceRow
        {...props}
        field="userinfoEncryptedResponseEncs"
        ordered
        autoHint={
          props.draft.userinfoEncryptedResponseAlgs.length > 0
            ? 'clientsAutoDefaultContentEncryption'
            : 'clientsAutoContentEncryptionOff'
        }
        label="clientsUserinfoEncryptionEnc"
        supported={options?.userinfoEncryptionEncs}
      />
    </>
  )
}

/** Signed and encrypted request objects, and pre-registered `request_uri`s. */
export function RequestObjectRows(props: OptionProps) {
  const t = useTranslator()
  const { draft, onChange, errors, isDisabled = false, options, clientKeys } = props
  return (
    <>
      <ChoiceRow
        {...props}
        field="requestObjectSigningAlgs"
        autoHint="clientsAutoAcceptSupported"
        label="clientsRequestObjectSigning"
        description="clientsRequestObjectSigningHint"
        supported={options?.requestObjectSigningAlgs}
        labels={{ none: 'clientsAlgorithmUnsigned' }}
        keyed={clientKeys?.coverage.verificationAlgs}
        keyless={['none']}
        missingKey={{
          message: 'clientsRequestObjectSigningNoKey',
          contact: 'clientsRequestObjectSigningNoKeyContact',
          manage: 'client-credentials',
        }}
      />
      <ChoiceRow
        {...props}
        field="requestObjectEncryptionAlgs"
        autoHint="clientsAutoAcceptSupported"
        label="clientsRequestObjectEncryptionAlg"
        description="clientsRequestObjectEncryptionAlgHint"
        supported={options?.requestObjectEncryptionAlgs}
        keyed={options?.activeRequestObjectEncryptionAlgs}
        missingKey={{
          message: 'clientsRequestObjectEncryptionNoKey',
          contact: 'clientsRequestObjectEncryptionNoKeyContact',
          manage: 'encryption-keys',
        }}
      />
      <ChoiceRow
        {...props}
        field="requestObjectEncryptionEncs"
        autoHint="clientsAutoAcceptSupported"
        label="clientsRequestObjectEncryptionEnc"
        supported={options?.requestObjectEncryptionEncs}
      />
      <SettingsRow label={t('clientsRequestUris')} description={t('clientsRequestUrisHint')}>
        <UserTextAreaField
          name="requestUris"
          label={t('clientsRequestUris')}
          hideLabel
          placeholder="https://app.example.com/requests/signed.jwt"
          value={draft.requestUris}
          onChange={(requestUris) => onChange({ ...draft, requestUris })}
          error={errors.requestUris}
          isDisabled={isDisabled}
          rows={2}
        />
      </SettingsRow>
    </>
  )
}

/**
 * Which assertion algorithms the client's credentials verify, for the
 * assertion methods it uses: a registered public key for `private_key_jwt`, an
 * active secret for HMAC `client_secret_jwt`. Unknown (`undefined`) when the
 * client uses neither, or fetches keys from a JWKS URI at verification time.
 */
function assertionKeyed(
  clientKeys: ClientKeyCoverage | null | undefined,
  supported: readonly string[] | undefined,
): string[] | undefined {
  if (!clientKeys) return undefined
  const privateKey = clientKeys.authMethods.includes('PRIVATE_KEY_JWT')
  const secret = clientKeys.authMethods.includes('CLIENT_SECRET_JWT')
  if (!privateKey && !secret) return undefined
  if (privateKey && clientKeys.coverage.remoteKeys) return undefined
  return [
    ...(privateKey ? clientKeys.coverage.verificationAlgs : []),
    ...(secret && clientKeys.coverage.secret
      ? (supported ?? []).filter((algorithm) => algorithm.startsWith('HS'))
      : []),
  ]
}

/** Algorithms accepted for `private_key_jwt` and `client_secret_jwt` assertions. */
export function ClientAssertionRow(props: OptionProps) {
  const supported = props.options?.tokenEndpointAuthSigningAlgs
  return (
    <ChoiceRow
      {...props}
      field="tokenEndpointAuthSigningAlgs"
      autoHint="clientsAutoAcceptSupported"
      label="clientsAssertionSigning"
      description="clientsAssertionSigningHint"
      supported={supported}
      keyed={assertionKeyed(props.clientKeys, supported)}
      missingKey={{
        message: 'clientsAssertionSigningNoKey',
        contact: 'clientsAssertionSigningNoKeyContact',
        manage: 'client-credentials',
      }}
    />
  )
}

/** Where a third party may start sign-in for this client. */
export function InitiateLoginRow(props: AdvancedFieldsProps) {
  return (
    <UriRow
      {...props}
      field="initiateLoginUri"
      label="clientsInitiateLoginUri"
      description="clientsInitiateLoginUriHint"
      placeholder="https://app.example.com/login"
    />
  )
}
