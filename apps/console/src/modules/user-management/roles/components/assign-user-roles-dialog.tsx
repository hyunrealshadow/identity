import {
  RelationPagination,
  CandidateSearch,
  CandidateResults,
} from '../../components/relation-picker'
import { RelationDialog } from '../../components/relation-dialog'
import { useRelationMutation } from '../../lib/relation-mutation'

import { Badge } from '@identity/ui/components/badge'
import { Button } from '@identity/ui/components/button'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'

import { ShieldPlus } from 'lucide-react'
import { useMemo, useState } from 'react'

import {
  ConsoleRolesDocument,
  type ConsoleRolesQuery,
  type ConsoleRolesQueryVariables,
} from '#/generated/graphql'

import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'

import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'

import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { clearDraft } from '#/lib/draft-storage'
import { useDialogDraft } from '../../lib/dialog-draft'

const ROLE_PICKER_PAGE_SIZE = 10

const EMPTY_SELECTION = new Set<string>()

function decodeSelection(stored: unknown): Set<string> {
  if (!stored || typeof stored !== 'object' || !('roleIds' in stored))
    return new Set()
  return new Set(
    Array.isArray(stored.roleIds)
      ? stored.roleIds.filter((id): id is string => typeof id === 'string')
      : [],
  )
}

export function AssignRolesDialog({
  userId,
  username,
  expectedUserVersion,
  onAssigned,
  onReload,
  reloadPending,
}: {
  userId: string
  username: string
  expectedUserVersion: string
  onAssigned: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutations = useRoleMutations()
  const draftKey = `identity.console.user-role-assign.${userId}`
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const mutation = useRelationMutation()
  const { setFeedback, pending } = mutation
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useDialogDraft(
    draftKey,
    state.isOpen,
    decodeSelection,
    EMPTY_SELECTION,
    () => {
      setQuery('')
      setAppliedQuery('')
      setAfter(undefined)
      setBefore(undefined)
      setFeedback(null)
      setError(null)
    },
    (value) => ({ roleIds: [...value] }),
  )

  const variables = useMemo<ConsoleRolesQueryVariables | null>(
    () =>
      state.isOpen
        ? {
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'NAME_ASC',
            ...cursorPage(ROLE_PICKER_PAGE_SIZE, after, before),
          }
        : null,
    [after, appliedQuery, before, state.isOpen],
  )
  const roles = useConsoleQuery<ConsoleRolesQuery, ConsoleRolesQueryVariables>(
    ConsoleRolesDocument,
    variables,
    Boolean(variables),
    'missing_role_connection',
    { keepPreviousData: true },
  )

  async function submit() {
    if (selected.size === 0) {
      setError(t('userRolesSelectRoleRequired'))
      return
    }
    if (!expectedUserVersion) {
      setFeedback({
        errors: [],
        failure: {
          kind: 'invalid_response',
          code: 'missing_user_version',
        },
        forbidden: false,
      })
      return
    }
    setError(null)
    await mutation.run(async () => {
      const result = await mutations.assignUserRoles({
        userId,
        roleIds: [...selected],
        expectedUserVersion,
      })
      const payload = result.data?.assignUserRoles ?? null
      if (
        !mutation.accept(result, payload, 'missing_assign_user_roles_payload')
      )
        return
      clearDraft(draftKey)
      state.close()
      toast.success(t('userRolesAssignedToast'), {
        description: t('userRolesAssignedCommitted', {
          count: payload.createdCount,
        }),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onAssigned()
    }, 'assign_user_roles_request_failed')
  }
  const connection = roles.data?.roles ?? null
  const edges = connection?.edges ?? []

  return (
    <>
      <Button onClick={state.open}>
        <ShieldPlus className="size-4" aria-hidden="true" />
        {t('userRolesAssignAction')}
      </Button>
      <RelationDialog
        state={state}
        mutation={mutation}
        title={t('userRolesAssignTitle')}
        confirm={t('userRolesAssignConfirm')}
        disabled={selected.size === 0}
        error={error}
        onSubmit={() => void submit()}
        onReload={onReload}
        reloadPending={reloadPending}
      >
        <p className="text-sm leading-6 text-muted-foreground">
          {t('userRolesAssignDescription', { user: username })}
        </p>
        <CandidateSearch
          label={t('userRolesSearchRoles')}
          value={query}
          onChange={setQuery}
          onSearch={() => {
            setAppliedQuery(query.trim())
            setAfter(undefined)
            setBefore(undefined)
          }}
        />
        <CandidateResults
          query={roles}
          count={edges.length}
          label={t('userRolesSearchRoles')}
          empty={t('userRolesNoCandidates')}
        >
          <ul className="divide-y divide-border">
            {edges.map(({ node }) => (
              <li key={node.id}>
                <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-muted">
                  <input
                    type="checkbox"
                    className="mt-1 size-4"
                    checked={selected.has(node.id)}
                    onChange={() => {
                      setSelected((current) => {
                        const next = new Set(current)
                        if (next.has(node.id)) next.delete(node.id)
                        else next.add(node.id)
                        return next
                      })
                    }}
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">
                      {resolveLocalizedText(node.names, locale) ??
                        node.name ??
                        node.name ??
                        node.id}
                    </span>
                    {!node.enabled ? (
                      <Badge variant="secondary" className="mt-1">
                        {t('rolesDisabled')}
                      </Badge>
                    ) : null}
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
            isDisabled={roles.refreshing || roles.status !== 'ready' || pending}
          />
        ) : null}
      </RelationDialog>
    </>
  )
}
