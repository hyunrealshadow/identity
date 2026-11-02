import { toast, useOverlayState } from '@heroui/react'
import { XCircle } from 'lucide-react'

import { TableRowActions } from '#/components/table-row-actions'
import { useLocale, useTranslator } from '#/lib/i18n'
import { RelationDialog } from '../../components/relation-dialog'
import { useRelationMutation } from '../../lib/relation-mutation'
import { resolveLocalizedText } from '../../groups/lib/groups-search'
import { useRoleMutations } from '../hooks/role-mutations'

interface Props {
  binding: {
    userId: string
    roleId: string
    userVersion: string
    user?: { username: string } | null
    role?: {
      id: string
      name: string
      names: { locale: string; value: string }[]
    } | null
  }
  onRevoked: () => void
  onReload: () => void
  reloadPending: boolean
}

function RevokeUserRoleDialog({
  binding,
  perspective,
  onRevoked,
  onReload,
  reloadPending,
}: Props & { perspective: 'role' | 'user' }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutation = useRelationMutation()
  const mutations = useRoleMutations()
  const fromUser = perspective === 'user'
  const label = fromUser
    ? binding.role
      ? (resolveLocalizedText(binding.role.names, locale) ?? binding.role.name)
      : binding.roleId
    : (binding.user?.username ?? binding.userId)
  return (
    <>
      <TableRowActions
        subject={label}
        actions={[
          {
            id: 'remove',
            label: t(
              fromUser ? 'userRolesRevokeAction' : 'roleUsersRevokeAction',
            ),
            danger: true,
            onAction: () => {
              mutation.setFeedback(null)
              state.open()
            },
            icon: <XCircle className="size-4" aria-hidden="true" />,
          },
        ]}
      />
      <RelationDialog
        state={state}
        mutation={mutation}
        size="md"
        danger
        disabled={!binding.userVersion}
        title={t(fromUser ? 'userRolesRevokeTitle' : 'roleUsersRevokeTitle')}
        confirm={t(
          fromUser ? 'userRolesRevokeConfirm' : 'roleUsersRevokeConfirm',
        )}
        onReload={onReload}
        reloadPending={reloadPending}
        onSubmit={() =>
          void mutation.run(async () => {
            const result = await mutations.revokeUserRoles({
              userId: binding.userId,
              roleIds: [binding.roleId],
              expectedUserVersion: binding.userVersion,
            })
            const payload = result.data?.revokeUserRoles
            if (
              !mutation.accept(
                result,
                payload,
                'missing_revoke_user_roles_payload',
              )
            )
              return
            state.close()
            toast.success(
              t(fromUser ? 'userRolesRevokedToast' : 'roleUserRevokedToast'),
              {
                description: t(
                  fromUser
                    ? 'userRolesRevokedCommitted'
                    : 'roleUserRevokedCommitted',
                  { count: payload.revokedCount },
                ),
              },
            )
            if (result.partial) toast.warning(t('rbacPartialMutationNote'))
            onRevoked()
          }, 'revoke_user_roles_request_failed')
        }
      >
        <p className="text-sm leading-6 text-muted">
          {fromUser
            ? t('userRolesRevokeDescription', { role: label })
            : t('roleUsersRevokeDescription', { user: label })}
        </p>
      </RelationDialog>
    </>
  )
}

export function RevokeBindingDialog(props: Props) {
  return <RevokeUserRoleDialog perspective="user" {...props} />
}
export function RevokeRoleFromUserDialog(props: Props) {
  return <RevokeUserRoleDialog perspective="role" {...props} />
}
