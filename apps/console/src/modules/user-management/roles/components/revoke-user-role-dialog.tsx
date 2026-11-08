import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { XCircle } from 'lucide-react'

import { TableRowActions } from '#/components/table-row-actions'
import { useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RelationDialog } from '../../components/relation-dialog'
import { useRelationMutation } from '../../lib/relation-mutation'
import { useRoleMutations } from '../hooks/role-mutations'

interface Props {
  /** The user-role assignment to revoke, addressed by its two endpoints. */
  assignment: {
    userId: string
    roleId: string
    userVersion: string | null | undefined
  }
  /** Display name of the other endpoint: the role on a user, or the user on a role. */
  label: string
  onRevoked: () => void
  onReload: () => void
  reloadPending: boolean
}

function RevokeAssignmentDialog({
  assignment,
  label,
  perspective,
  onRevoked,
  onReload,
  reloadPending,
}: Props & { perspective: 'role' | 'user' }) {
  const t = useTranslator()
  const state = useOverlayState()
  const mutation = useRelationMutation()
  const mutations = useRoleMutations()
  const fromUser = perspective === 'user'
  const userVersion = assignment.userVersion
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
        disabled={!userVersion}
        title={t(fromUser ? 'userRolesRevokeTitle' : 'roleUsersRevokeTitle')}
        confirm={t(
          fromUser ? 'userRolesRevokeConfirm' : 'roleUsersRevokeConfirm',
        )}
        onReload={onReload}
        reloadPending={reloadPending}
        onSubmit={() =>
          void mutation.run(async () => {
            if (!userVersion) return
            const result = await mutations.revokeUserRoles({
              userId: assignment.userId,
              roleIds: [assignment.roleId],
              expectedUserVersion: userVersion,
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
        <p className="text-sm leading-6 text-muted-foreground">
          {fromUser
            ? t('userRolesRevokeDescription', { role: label })
            : t('roleUsersRevokeDescription', { user: label })}
        </p>
      </RelationDialog>
    </>
  )
}

export function RevokeUserRoleDialog(props: Props) {
  return <RevokeAssignmentDialog perspective="user" {...props} />
}
export function RevokeRoleFromUserDialog(props: Props) {
  return <RevokeAssignmentDialog perspective="role" {...props} />
}
