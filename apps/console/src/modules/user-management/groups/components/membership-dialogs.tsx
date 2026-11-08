import { Button } from '@identity/ui/components/button'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { UserMinus, UserPlus } from 'lucide-react'
import { useMemo, useState } from 'react'

import { TableRowActions } from '#/components/table-row-actions'
import { toast } from '#/lib/toast'
import {
  ConsoleGroupsDocument,
  ConsoleUsersDocument,
  type ConsoleGroupsQuery,
  type ConsoleGroupsQueryVariables,
  type ConsoleUsersQuery,
  type ConsoleUsersQueryVariables,
  type ConsoleUserGroupsQuery,
} from '#/generated/graphql'
import { clearDraft } from '#/lib/draft-storage'
import { useLocale, useTranslator } from '#/lib/i18n'
import { RelationDialog } from '../../components/relation-dialog'
import {
  CandidateResults,
  CandidateSearch,
  RelationPagination,
} from '../../components/relation-picker'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { cursorPage } from '../../lib/cursor-page'
import { useDialogDraft } from '../../lib/dialog-draft'
import { useRelationMutation } from '../../lib/relation-mutation'
import { useGroupMemberMutations } from '../hooks/use-group-members'
import { resolveLocalizedText } from '../lib/groups-search'
import { GroupKindChip, GroupStatusChip } from './group-status'
import { UserStatusBadges } from '../../users/components/user-status'

type Target =
  | { kind: 'group'; id: string; version: string; label: string }
  | { kind: 'user'; id: string; label: string }
type Selection = { id: string; version: string }
const EMPTY: Selection = { id: '', version: '' }
type Callbacks = { onReload: () => void; reloadPending: boolean }
type MembershipGroup = NonNullable<
  NonNullable<ConsoleUserGroupsQuery['user']>['groups']
>['edges'][number]['node']

function AddMembershipDialog({
  target,
  onAdded,
  onReload,
  reloadPending,
}: Callbacks & { target: Target; onAdded: () => void }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutation = useRelationMutation()
  const mutations = useGroupMemberMutations()
  const fixedGroup = target.kind === 'group'
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string>()
  const [before, setBefore] = useState<string>()
  const [error, setError] = useState<string | null>(null)
  const draftKey = fixedGroup
    ? `identity.console.group-member-add.${target.id}`
    : `identity.console.user-group-add.${target.id}`
  const [selection, setSelection] = useDialogDraft(
    draftKey,
    state.isOpen,
    (value) => {
      if (!value || typeof value !== 'object') return EMPTY
      const stored = value as Record<string, unknown>
      const id = stored.id ?? stored[fixedGroup ? 'userId' : 'groupId']
      const version = stored.version ?? stored.groupVersion
      return {
        id: typeof id === 'string' ? id : '',
        version: typeof version === 'string' ? version : '',
      }
    },
    EMPTY,
    () => {
      setQuery('')
      setAppliedQuery('')
      setAfter(undefined)
      setBefore(undefined)
      setError(null)
      mutation.setFeedback(null)
    },
  )
  const userVariables = useMemo<ConsoleUsersQueryVariables | null>(
    () =>
      state.isOpen && fixedGroup
        ? {
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'USERNAME_ASC',
            ...cursorPage(10, after, before),
          }
        : null,
    [state.isOpen, fixedGroup, appliedQuery, after, before],
  )
  const groupVariables = useMemo<ConsoleGroupsQueryVariables | null>(
    () =>
      state.isOpen && !fixedGroup
        ? {
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(10, after, before),
          }
        : null,
    [state.isOpen, fixedGroup, appliedQuery, after, before],
  )
  const users = useConsoleQuery<ConsoleUsersQuery, ConsoleUsersQueryVariables>(
    ConsoleUsersDocument,
    userVariables,
    Boolean(userVariables),
    'missing_user_connection',
    { keepPreviousData: true },
  )
  const groups = useConsoleQuery<
    ConsoleGroupsQuery,
    ConsoleGroupsQueryVariables
  >(
    ConsoleGroupsDocument,
    groupVariables,
    Boolean(groupVariables),
    'missing_group_connection',
    { keepPreviousData: true },
  )
  const candidates = fixedGroup ? users : groups
  const userEdges = users.data?.users.edges ?? []
  const groupEdges = groups.data?.groups.edges ?? []
  const connection = fixedGroup ? users.data?.users : groups.data?.groups
  const selectedVisible = connection?.edges.some(
    ({ node }) => node.id === selection.id,
  )
  const select = (id: string, version = '') => {
    setSelection({ id, version })
    setError(null)
    mutation.setFeedback(null)
  }

  async function submit() {
    if (!selection.id) {
      setError(
        t(
          fixedGroup
            ? 'groupMembersSelectUserRequired'
            : 'userGroupsSelectGroupRequired',
        ),
      )
      return
    }
    // A group owns the membership CAS in both directions. Refreshing a candidate never silently replaces a conflicted version.
    const version = fixedGroup ? target.version : selection.version
    if (!version) {
      setError(t('userGroupsVersionUnavailable'))
      return
    }
    setError(null)
    await mutation.run(async () => {
      const result = await mutations.add({
        groupId: fixedGroup ? target.id : selection.id,
        userId: fixedGroup ? selection.id : target.id,
        expectedVersion: version,
      })
      if (
        !mutation.accept(
          result,
          result.data?.addGroupMember,
          'missing_add_group_member_payload',
        )
      )
        return
      clearDraft(draftKey)
      state.close()
      toast.success(
        t(fixedGroup ? 'groupMembersAddedToast' : 'userGroupsAddedToast'),
        {
          description: t(
            fixedGroup
              ? 'groupMembersAddedCommitted'
              : 'userGroupsAddedCommitted',
          ),
        },
      )
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onAdded()
    }, 'add_group_member_request_failed')
  }

  return (
    <>
      <Button onClick={state.open} disabled={fixedGroup && !target.version}>
        <UserPlus className="size-4" aria-hidden="true" />
        {t(fixedGroup ? 'groupMembersAddAction' : 'userGroupsAddAction')}
      </Button>
      <RelationDialog
        state={state}
        mutation={mutation}
        title={t(fixedGroup ? 'groupMembersAddTitle' : 'userGroupsAddTitle')}
        confirm={t(
          fixedGroup ? 'groupMembersAddConfirm' : 'userGroupsAddConfirm',
        )}
        disabled={
          !selection.id || (fixedGroup ? !target.version : !selection.version)
        }
        error={error}
        onSubmit={() => void submit()}
        onReload={() => {
          mutation.setFeedback(null)
          void candidates.refresh().then((data) => {
            if (!fixedGroup && data && 'groups' in data) {
              const node = data.groups.edges.find(
                (edge) => edge.node.id === selection.id,
              )?.node
              if (node) setSelection({ id: node.id, version: node.version })
            }
          })
          onReload()
        }}
        reloadPending={reloadPending || candidates.refreshing}
        conflictTitleKey={!fixedGroup ? 'userGroupsConflictTitle' : undefined}
        conflictDescriptionKey={
          !fixedGroup ? 'userGroupsConflictDescription' : undefined
        }
      >
        <p className="text-sm leading-6 text-muted-foreground">
          {fixedGroup
            ? t('groupMembersAddDescription', { group: target.label })
            : t('userGroupsAddDescription', { user: target.label })}
        </p>
        <CandidateSearch
          label={t(
            fixedGroup
              ? 'groupMembersSearchUsersLabel'
              : 'userGroupsSearchLabel',
          )}
          value={query}
          onChange={setQuery}
          onSearch={() => {
            setAppliedQuery(query.trim())
            setAfter(undefined)
            setBefore(undefined)
          }}
        />
        {selection.id && !selectedVisible ? (
          <p className="mt-3 break-all font-mono text-xs text-muted-foreground">
            {fixedGroup
              ? t('groupMembersAddSelectedUser', { user: selection.id })
              : t('userGroupsAddSelectedGroup', { group: selection.id })}
          </p>
        ) : null}
        <CandidateResults
          query={candidates}
          count={connection?.edges.length ?? 0}
          label={t(
            fixedGroup
              ? 'groupMembersAddResultsLabel'
              : 'userGroupsAddResultsLabel',
          )}
          empty={t(
            fixedGroup
              ? 'groupMembersNoCandidates'
              : 'userGroupsAddNoCandidates',
          )}
        >
          <ul className="divide-y divide-border">
            {fixedGroup
              ? userEdges.map(({ node }) => (
                  <li key={node.id}>
                    <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-muted">
                      <input
                        type="radio"
                        name="membership-user"
                        className="mt-1 size-4"
                        checked={selection.id === node.id}
                        onChange={() => select(node.id)}
                      />
                      <span className="min-w-0">
                        <span className="block text-sm font-medium">
                          {node.username}
                        </span>
                        <span className="block break-all text-xs text-muted-foreground">
                          {node.email}
                        </span>
                        <UserStatusBadges user={node} />
                      </span>
                    </label>
                  </li>
                ))
              : groupEdges.map(({ node }) => (
                  <li key={node.id}>
                    <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-muted">
                      <input
                        type="radio"
                        name="membership-group"
                        className="mt-1 size-4"
                        checked={selection.id === node.id}
                        onChange={() => select(node.id, node.version)}
                      />
                      <span className="min-w-0">
                        <span className="block text-sm font-medium">
                          {resolveLocalizedText(node.names, locale) ??
                            node.name}
                        </span>
                        <span className="block text-xs text-muted-foreground">
                          {resolveLocalizedText(node.descriptions, locale) ??
                            node.description}
                        </span>
                        <span className="mt-1 flex gap-1">
                          <GroupKindChip builtIn={node.builtIn} />
                          <GroupStatusChip enabled={node.enabled} />
                        </span>
                      </span>
                    </label>
                  </li>
                ))}
          </ul>
        </CandidateResults>
        {connection ? (
          <div className="mt-2">
            <RelationPagination
              connection={connection}
              variables={userVariables ?? groupVariables}
              after={after}
              before={before}
              onNavigate={(page) => {
                setAfter(page.after)
                setBefore(page.before)
              }}
              label={t('groupMembersAddResultsLabel')}
              isDisabled={
                candidates.refreshing ||
                candidates.status !== 'ready' ||
                mutation.pending
              }
            />
          </div>
        ) : null}
      </RelationDialog>
    </>
  )
}

function RemoveMembershipDialog({
  groupId,
  userId,
  version,
  label,
  description,
  fromUser,
  onRemoved,
  onReload,
  reloadPending,
}: Callbacks & {
  groupId: string
  userId: string
  version: string
  label: string
  description: string
  fromUser: boolean
  onRemoved: () => void
}) {
  const t = useTranslator()
  const state = useOverlayState()
  const mutation = useRelationMutation()
  const mutations = useGroupMemberMutations()
  return (
    <>
      <TableRowActions
        subject={label}
        actions={[
          {
            id: 'remove',
            label: t(
              fromUser ? 'userGroupsRemoveAction' : 'groupMembersRemoveAction',
            ),
            onAction: () => {
              mutation.setFeedback(null)
              state.open()
            },
            danger: true,
            icon: <UserMinus className="size-4" aria-hidden="true" />,
            isDisabled: !version,
          },
        ]}
      />
      <RelationDialog
        state={state}
        mutation={mutation}
        size="md"
        danger
        title={t(
          fromUser ? 'userGroupsRemoveTitle' : 'groupMembersRemoveTitle',
        )}
        confirm={t(
          fromUser ? 'userGroupsRemoveConfirm' : 'groupMembersRemoveConfirm',
        )}
        disabled={!version}
        onReload={onReload}
        reloadPending={reloadPending}
        conflictTitleKey={fromUser ? 'userGroupsConflictTitle' : undefined}
        conflictDescriptionKey={
          fromUser ? 'userGroupsConflictDescription' : undefined
        }
        onSubmit={() =>
          void mutation.run(async () => {
            const result = await mutations.remove({
              groupId,
              userId,
              expectedVersion: version,
            })
            if (
              !mutation.accept(
                result,
                result.data?.removeGroupMember,
                'missing_remove_group_member_payload',
              )
            )
              return
            state.close()
            toast.success(
              t(
                fromUser
                  ? 'userGroupsRemovedToast'
                  : 'groupMembersRemovedToast',
              ),
              {
                description: t(
                  fromUser
                    ? 'userGroupsRemovedCommitted'
                    : 'groupMembersRemovedCommitted',
                ),
              },
            )
            if (result.partial) toast.warning(t('rbacPartialMutationNote'))
            onRemoved()
          }, 'remove_group_member_request_failed')
        }
      >
        <p className="text-sm leading-6 text-muted-foreground">{description}</p>
      </RelationDialog>
    </>
  )
}

export function AddMemberDialog({
  groupId,
  groupName,
  groupVersion,
  ...callbacks
}: Callbacks & {
  groupId: string
  groupName: string
  groupVersion: string
  onAdded: () => void
}) {
  return (
    <AddMembershipDialog
      target={{
        kind: 'group',
        id: groupId,
        label: groupName,
        version: groupVersion,
      }}
      {...callbacks}
    />
  )
}
export function AddGroupMembershipDialog({
  userId,
  username,
  ...callbacks
}: Callbacks & { userId: string; username: string; onAdded: () => void }) {
  return (
    <AddMembershipDialog
      target={{ kind: 'user', id: userId, label: username }}
      {...callbacks}
    />
  )
}
export function RemoveMemberDialog({
  groupId,
  userId,
  username,
  groupVersion,
  ...callbacks
}: Callbacks & {
  groupId: string
  userId: string
  username: string
  groupVersion: string
  onRemoved: () => void
}) {
  const t = useTranslator()
  const label = username
  return (
    <RemoveMembershipDialog
      groupId={groupId}
      userId={userId}
      version={groupVersion}
      label={label}
      description={t('groupMembersRemoveDescription', { user: label })}
      fromUser={false}
      {...callbacks}
    />
  )
}
export function RemoveGroupMembershipDialog({
  group,
  userId,
  username,
  ...callbacks
}: Callbacks & {
  group: MembershipGroup
  userId: string
  username: string
  onRemoved: () => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const label = resolveLocalizedText(group.names, locale) ?? group.name
  return (
    <RemoveMembershipDialog
      groupId={group.id}
      userId={userId}
      version={group.version}
      label={label}
      description={t('userGroupsRemoveDescription', {
        user: username,
        group: label,
      })}
      fromUser
      {...callbacks}
    />
  )
}
