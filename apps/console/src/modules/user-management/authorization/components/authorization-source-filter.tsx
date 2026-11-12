import type { AuthorizationSource } from '#/generated/graphql'
import { useTranslator } from '#/lib/i18n'
import type { RbacScope } from '#/modules/user-management/lib/rbac-scope'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'

export type AuthorizationSourceFilterValue = 'any' | AuthorizationSource

/**
 * Filtering by source reveals which access comes from groups, so the server
 * requires both group membership and group role reads for it.
 */
export function canFilterBySource(scope: RbacScope): boolean {
  return scope.groupMembershipsRead && scope.groupRolesRead
}

export function sourceVariable(
  value: AuthorizationSourceFilterValue,
): AuthorizationSource | undefined {
  return value === 'any' ? undefined : value
}

export function AuthorizationSourceFilter({
  name,
  value,
  onChange,
}: {
  name: string
  value: AuthorizationSourceFilterValue
  onChange: (value: AuthorizationSourceFilterValue) => void
}) {
  const t = useTranslator()
  return (
    <div className="w-40">
      <UserSelectField
        name={name}
        label={t('authorizationSourceFilterLabel')}
        hideLabel
        value={value}
        onChange={(next) => {
          if (next === 'any' || next === 'DIRECT' || next === 'GROUP') {
            onChange(next)
          }
        }}
        options={[
          { id: 'any', label: t('authorizationSourceAny') },
          { id: 'DIRECT', label: t('authorizationSourceDirect') },
          { id: 'GROUP', label: t('authorizationSourceGroup') },
        ]}
      />
    </div>
  )
}
