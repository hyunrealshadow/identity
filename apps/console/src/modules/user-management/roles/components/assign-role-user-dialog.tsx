import {
  RelationPagination,
  CandidateSearch,
  CandidateResults,
} from '../../components/relation-picker'
import { RelationDialog } from '../../components/relation-dialog'
import { useRelationMutation } from '../../lib/relation-mutation'

import { Button, Chip, toast, useOverlayState } from '@heroui/react'

import { UserPlus } from 'lucide-react'
import { useMemo, useState } from 'react'

import {
  ConsoleUserRoleVersionDocument,
  ConsoleUsersDocument,
  type ConsoleRoleQuery,
  type ConsoleUserRoleVersionQuery,
  type ConsoleUserRoleVersionQueryVariables,
  type ConsoleUsersQuery,
  type ConsoleUsersQueryVariables,
} from '#/gql/graphql'

import { useLocale, useTranslator } from '#/lib/i18n'
import { useGraphQL } from '#/lib/graphql/use-graphql'

import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import {
  roleDisplayName,
  withRoleDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { clearDraft } from '#/lib/draft-storage'
import { useDialogDraft } from '../../lib/dialog-draft'

const USER_PICKER_PAGE_SIZE = 10

function decodeSelection(stored: unknown): string | null {
  return stored &&
    typeof stored === 'object' &&
    'userId' in stored &&
    typeof stored.userId === 'string'
    ? stored.userId
    : null
}

export function AssignUserDialog({
  role,
  onAssigned,
  onReload,
  reloadPending,
}: {
  role: NonNullable<ConsoleRoleQuery['role']>
  onAssigned: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const request = useGraphQL()
  const mutations = useRoleMutations()
  const roleName = roleDisplayName(withRoleDisplayFields(role), locale)
  const draftKey = `identity.console.role-user-assign.${role.id}`
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const mutation = useRelationMutation()
  const { setFeedback, pending } = mutation
  const [localError, setLocalError] = useState<string | null>(null)
  const [selectedUserId, setSelectedUserId] = useDialogDraft(
    draftKey,
    state.isOpen,
    decodeSelection,
    null,
    () => {
      setQuery('')
      setAppliedQuery('')
      setAfter(undefined)
      setBefore(undefined)
      setFeedback(null)
      setLocalError(null)
    },
    (value) => ({ userId: value }),
  )

  const variables = useMemo<ConsoleUsersQueryVariables | null>(
    () =>
      state.isOpen
        ? {
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'USERNAME_ASC',
            ...cursorPage(USER_PICKER_PAGE_SIZE, after, before),
          }
        : null,
    [after, appliedQuery, before, state.isOpen],
  )
  const users = useConsoleQuery<ConsoleUsersQuery, ConsoleUsersQueryVariables>(
    ConsoleUsersDocument,
    variables,
    'ConsoleUsers',
    Boolean(variables),
    'missing_user_connection',
  )

  async function submit() {
    if (!selectedUserId) {
      setLocalError(t('roleUsersSelectUserRequired'))
      return
    }
    setLocalError(null)
    await mutation.run(async () => {
      const versionResult = await request<
        ConsoleUserRoleVersionQuery,
        ConsoleUserRoleVersionQueryVariables
      >(
        ConsoleUserRoleVersionDocument,
        { userId: selectedUserId },
        'ConsoleUserRoleVersion',
      )
      const version = versionResult.data?.userRoles.userVersion ?? ''
      if (
        !mutation.accept(
          versionResult,
          version || null,
          'missing_user_authorization_version',
        )
      )
        return

      const result = await mutations.assignUserRoles({
        userId: selectedUserId,
        roleIds: [role.id],
        expectedUserVersion: version,
      })
      const payload = result.data?.assignUserRoles ?? null
      if (
        !mutation.accept(result, payload, 'missing_assign_user_roles_payload')
      )
        return
      clearDraft(draftKey)
      state.close()
      toast.success(t('roleUserAssignedToast'), {
        description:
          payload.createdCount > 0
            ? t('roleUserAssignedCommitted', { count: payload.createdCount })
            : t('roleUserAlreadyAssigned'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onAssigned()
    }, 'assign_user_roles_request_failed')
  }
  const connection = users.data?.users ?? null
  const edges = connection?.edges ?? []

  return (
    <>
      <Button onPress={state.open}>
        <UserPlus className="size-4" aria-hidden="true" />
        {t('roleUsersAssignAction')}
      </Button>
      <RelationDialog
        state={state}
        mutation={mutation}
        title={t('roleUsersAssignTitle')}
        confirm={t('roleUsersAssignConfirm')}
        disabled={!selectedUserId}
        error={localError}
        onSubmit={() => void submit()}
        onReload={onReload}
        reloadPending={reloadPending}
      >
        <p className="text-sm leading-6 text-muted">
          {t('roleUsersAssignDescription', { role: roleName })}
        </p>
        <CandidateSearch
          label={t('roleUsersSearchUsers')}
          value={query}
          onChange={setQuery}
          onSearch={() => {
            setAppliedQuery(query.trim())
            setAfter(undefined)
            setBefore(undefined)
          }}
        />

        <CandidateResults
          query={users}
          count={edges.length}
          label={t('roleUsersSearchUsers')}
          empty={t('roleUsersNoCandidates')}
        >
          <ul className="divide-y divide-separator">
            {edges.map(({ node }) => (
              <li key={node.id}>
                <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-surface-secondary">
                  <input
                    type="radio"
                    name="assign-user"
                    className="mt-1 size-4"
                    checked={selectedUserId === node.id}
                    onChange={() => setSelectedUserId(node.id)}
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">
                      {node.username}
                    </span>
                    <span className="block break-all text-xs text-muted">
                      {node.email}
                    </span>
                    <span className="mt-1 flex gap-1">
                      {node.enabled === null ||
                      node.enabled === undefined ? null : (
                        <Chip
                          size="sm"
                          variant="soft"
                          color={node.enabled ? 'success' : 'default'}
                        >
                          <Chip.Label>
                            {t(node.enabled ? 'usersEnabled' : 'usersDisabled')}
                          </Chip.Label>
                        </Chip>
                      )}
                      {node.locked ? (
                        <Chip size="sm" variant="soft" color="warning">
                          <Chip.Label>{t('usersLocked')}</Chip.Label>
                        </Chip>
                      ) : null}
                    </span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </CandidateResults>
        {connection ? (
          <RelationPagination
            connection={connection}
            variables={variables}
            after={after}
            before={before}
            onNavigate={(page) => {
              setAfter(page.after)
              setBefore(page.before)
            }}
            label={t('roleUsersPagination')}
            isDisabled={users.refreshing || users.status !== 'ready' || pending}
          />
        ) : null}
      </RelationDialog>
    </>
  )
}
