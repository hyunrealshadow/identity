import {
  RelationPagination,
  CandidateSearch,
} from '../../components/relation-picker'
import { RelationDialog } from '../../components/relation-dialog'
import { useRelationMutation } from '../../lib/relation-mutation'

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Badge } from '@identity/ui/components/badge'
import { Button } from '@identity/ui/components/button'
import { Checkbox } from '@identity/ui/components/checkbox'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Spinner } from '@identity/ui/components/spinner'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { Pencil, TriangleAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { toast } from '#/lib/toast'
import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'

import {
  ConsoleRolesDocument,
  type ConsoleRolesQuery,
  type ConsoleRolesQueryVariables,
  type SetGroupRolesInput,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'

import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'

import { useGroupRoleMutations } from '#/modules/user-management/groups/hooks/use-group-roles'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'

const ROLE_PICKER_PAGE_SIZE = 5

interface RoleEditDraft {
  roleIds: string[]
}

function roleEditDraftKey(groupId: string): string {
  return `identity.console.group-roles.${groupId}`
}

function readRoleEditDraft(groupId: string): RoleEditDraft | null {
  const stored = readDraft<unknown>(roleEditDraftKey(groupId))
  if (!stored || typeof stored !== 'object' || Array.isArray(stored))
    return null
  const value = stored as Record<string, unknown>
  if (!Array.isArray(value.roleIds)) return null
  return {
    roleIds: value.roleIds.filter((id): id is string => typeof id === 'string'),
  }
}

function sameRoleSet(
  left: ReadonlyArray<string>,
  right: ReadonlyArray<string>,
) {
  if (left.length !== right.length) return false
  const rightSet = new Set(right)
  return left.every((id) => rightSet.has(id))
}

export function EditRolesDialog({
  groupId,
  groupVersion,
  groupName,
  onSaved,
  onReload,
  reloadPending,
}: {
  groupId: string
  groupVersion: string
  groupName: string
  onSaved: (addedCount: number, removedCount: number) => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutations = useGroupRoleMutations()
  const draftKey = roleEditDraftKey(groupId)
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [selected, setSelected] = useState<Set<string>>(() => {
    const draft = readRoleEditDraft(groupId)
    return new Set(draft?.roleIds ?? [])
  })
  const hasStoredSelection = useRef(Boolean(readRoleEditDraft(groupId)))
  const [roleSnapshot, setRoleSnapshot] = useState<string[] | null>(null)
  const [snapshotStatus, setSnapshotStatus] = useState<
    'idle' | 'loading' | 'ready' | 'error'
  >('idle')
  const [snapshotFeedback, setSnapshotFeedback] =
    useState<RbacFeedbackState | null>(null)
  const mutation = useRelationMutation()
  const { setFeedback, pending } = mutation
  const [localError, setLocalError] = useState<string | null>(null)
  const opened = useRef(false)
  const completed = useRef(false)
  const loadVersion = useRef(0)

  const roleVariables = useMemo<ConsoleRolesQueryVariables | null>(
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
  const catalog = useConsoleQuery<
    ConsoleRolesQuery,
    ConsoleRolesQueryVariables
  >(
    ConsoleRolesDocument,
    roleVariables,
    Boolean(roleVariables),
    'missing_role_connection',
    { keepPreviousData: true },
  )

  useEffect(() => {
    if (!state.isOpen) return
    opened.current = true
    const version = loadVersion.current + 1
    loadVersion.current = version
    setSnapshotStatus('loading')
    setSnapshotFeedback(null)
    setFeedback(null)
    setLocalError(null)
    void mutations
      .loadActiveRoleIds(groupId)
      .then((snapshot) => {
        if (loadVersion.current !== version) return
        if (snapshot.failure || snapshot.partial) {
          setSnapshotStatus('error')
          setSnapshotFeedback({
            errors: snapshot.errors,
            failure: snapshot.failure ?? {
              kind: 'invalid_response',
              code: 'partial_group_role_snapshot',
              requestId: snapshot.requestId,
              traceId: snapshot.traceId,
            },
            stepUp: snapshot.stepUp,
            requestId: snapshot.requestId,
            traceId: snapshot.traceId,
            forbidden: snapshot.forbidden,
          })
          return
        }
        setRoleSnapshot(snapshot.roleIds)
        setSnapshotStatus('ready')
        if (!hasStoredSelection.current) {
          setSelected(new Set(snapshot.roleIds))
        }
      })
      .catch(() => {
        if (loadVersion.current !== version) return
        setSnapshotStatus('error')
        setSnapshotFeedback({
          errors: [],
          failure: {
            kind: 'network',
            code: 'group_role_snapshot_request_failed',
          },
          forbidden: false,
        })
      })
  }, [groupId, mutations, state.isOpen])

  useEffect(() => {
    if (state.isOpen) {
      opened.current = true
      return
    }
    if (!opened.current) return
    if (!completed.current) clearDraft(draftKey)
    setQuery('')
    setAppliedQuery('')
    setAfter(undefined)
    setBefore(undefined)
    setSelected(new Set())
    hasStoredSelection.current = false
    setRoleSnapshot(null)
    setSnapshotStatus('idle')
    setSnapshotFeedback(null)
    setFeedback(null)
    setLocalError(null)
    completed.current = false
    loadVersion.current += 1
  }, [draftKey, state.isOpen])

  useEffect(() => {
    if (!state.isOpen || !hasStoredSelection.current) return
    writeDraft(draftKey, {
      roleIds: [...selected],
    } satisfies RoleEditDraft)
  }, [draftKey, selected, state.isOpen])

  function toggleRole(roleId: string, isSelected: boolean) {
    hasStoredSelection.current = true
    setSelected((current) => {
      const next = new Set(current)
      if (isSelected) next.add(roleId)
      else next.delete(roleId)
      return next
    })
    setLocalError(null)
    setFeedback(null)
  }

  async function reloadSnapshot() {
    const version = loadVersion.current + 1
    loadVersion.current = version
    setSnapshotStatus('loading')
    setSnapshotFeedback(null)
    const snapshot = await mutations.loadActiveRoleIds(groupId)
    if (loadVersion.current !== version) return
    if (snapshot.failure || snapshot.partial) {
      setSnapshotStatus('error')
      setSnapshotFeedback({
        errors: snapshot.errors,
        failure: snapshot.failure ?? {
          kind: 'invalid_response',
          code: 'partial_group_role_snapshot',
          requestId: snapshot.requestId,
          traceId: snapshot.traceId,
        },
        stepUp: snapshot.stepUp,
        requestId: snapshot.requestId,
        traceId: snapshot.traceId,
        forbidden: snapshot.forbidden,
      })
      return
    }
    setRoleSnapshot(snapshot.roleIds)
    setSnapshotStatus('ready')
    setSelected(new Set(snapshot.roleIds))
    hasStoredSelection.current = true
  }

  async function submit() {
    if (snapshotStatus !== 'ready') return
    if (!groupVersion) {
      setLocalError(t('groupsVersionUnavailable'))
      return
    }
    setLocalError(null)
    const input: SetGroupRolesInput = {
      groupId,
      roleIds: [...selected],
      expectedVersion: groupVersion,
    }
    await mutation.run(async () => {
      const result = await mutations.setRoles(input)
      const payload = result.data?.setGroupRoles ?? null
      if (!mutation.accept(result, payload, 'missing_set_group_roles_payload'))
        return
      completed.current = true
      clearDraft(draftKey)
      state.close()
      toast.success(t('groupRolesSavedToast'), {
        description: t('groupRolesSavedCommitted', {
          addedCount: payload.addedCount,
          removedCount: payload.removedCount,
        }),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onSaved(payload.addedCount, payload.removedCount)
    }, 'set_group_roles_request_failed')
  }
  const connection = catalog.data?.roles ?? null
  const roleEdges = connection?.edges ?? []
  const changes =
    roleSnapshot !== null && !sameRoleSet([...selected], roleSnapshot)
  const canSave =
    snapshotStatus === 'ready' && !pending && Boolean(groupVersion) && changes

  return (
    <>
      <Button onClick={state.open} disabled={!groupVersion}>
        <Pencil className="size-4" aria-hidden="true" />
        {t('groupRolesEditAction')}
      </Button>
      <RelationDialog
        state={state}
        mutation={mutation}
        title={t('groupRolesEditTitle')}
        confirm={t('groupRolesSaveAction')}
        disabled={!canSave}
        error={localError}
        onSubmit={() => void submit()}
        onReload={() => {
          void reloadSnapshot()
          onReload()
        }}
        reloadPending={reloadPending}
        bodyClassName="flex min-h-0 flex-col gap-3 overflow-hidden"
        dialogClassName="w-full sm:max-w-3xl"
      >
        <p className="text-sm leading-5 text-muted-foreground">
          {t('groupRolesEditDescription', { group: groupName })}
        </p>
        <p className="text-xs leading-5 text-muted-foreground">
          {t('groupRolesEditHint')}
        </p>

        {snapshotStatus === 'loading' ? (
          <div
            className="flex items-center gap-2 rounded-lg border border-border p-3 text-sm"
            role="status"
          >
            <Spinner aria-label={t('loading')} />
            {t('groupRolesCurrentLoading')}
          </div>
        ) : null}

        {snapshotStatus === 'error' && snapshotFeedback ? (
          <div className="space-y-2">
            <RbacMutationFeedback
              feedback={snapshotFeedback}
              onReload={() => void reloadSnapshot()}
            />
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void reloadSnapshot()}
            >
              {t('groupRolesCurrentReload')}
            </Button>
          </div>
        ) : null}

        <CandidateSearch
          label={t('groupRolesCatalogSearchLabel')}
          value={query}
          onChange={setQuery}
          onSearch={() => {
            setAppliedQuery(query.trim())
            setAfter(undefined)
            setBefore(undefined)
          }}
        />

        <div
          className="min-h-40 flex-1 overflow-y-auto rounded-lg border border-border"
          role="region"
          aria-label={t('groupRolesCatalogLabel')}
        >
          {catalog.status === 'error' ? (
            <div className="p-3">
              <AsyncState
                kind={catalog.forbidden ? 'forbidden' : 'error'}
                compact
                title={t(failureTitleKey(catalog.failure, catalog.forbidden))}
                description={t(
                  failureDescriptionKey(catalog.failure, catalog.forbidden),
                )}
                requestId={catalog.requestId}
                traceId={catalog.traceId}
                issues={catalog.errors}
                onRetry={() => void catalog.refresh()}
              />
            </div>
          ) : catalog.status !== 'ready' ? (
            <div
              className="space-y-2 p-3"
              role="status"
              aria-label={t('groupRolesCatalogLoading')}
            >
              <span className="sr-only">{t('groupRolesCatalogLoading')}</span>
              {Array.from({ length: 4 }, (_, index) => (
                <Skeleton key={index} className="h-14 w-full rounded-lg" />
              ))}
            </div>
          ) : roleEdges.length === 0 ? (
            <div className="p-3">
              <AsyncState
                kind="empty"
                compact
                title={t('groupRolesCatalogEmpty')}
                description={t('groupRolesCatalogEmptyDescription')}
              />
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {roleEdges.map(({ node }) => {
                const name =
                  resolveLocalizedText(node.names, locale) ??
                  node.name ??
                  node.name ??
                  node.id
                return (
                  <li key={node.id}>
                    <label className="flex min-h-14 w-full cursor-pointer items-center gap-3 px-3 py-2 text-start">
                      <Checkbox
                        checked={selected.has(node.id)}
                        onCheckedChange={(checked) =>
                          toggleRole(node.id, checked === true)
                        }
                      />
                      <span className="min-w-0 flex-1">
                        <span className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium">{name}</span>
                          {node.builtIn ? (
                            <Badge variant="secondary" className="text-primary">
                              {t('groupRolesBuiltInRoleLabel')}
                            </Badge>
                          ) : null}
                          {!node.enabled ? (
                            <Badge variant="secondary" className="text-warning">
                              {t('rolesDisabled')}
                            </Badge>
                          ) : null}
                        </span>
                      </span>
                    </label>
                  </li>
                )
              })}
            </ul>
          )}
        </div>

        {connection ? (
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">
              {t('groupRolesSelectedCount', {
                count: selected.size,
              })}
            </span>
            <RelationPagination
              connection={connection}
              variables={roleVariables}
              after={after}
              before={before}
              onNavigate={(page) => {
                setAfter(page.after)
                setBefore(page.before)
              }}
              label={t('roleUsersPagination')}
              isDisabled={
                catalog.refreshing || catalog.status !== 'ready' || pending
              }
            />
          </div>
        ) : null}

        {catalog.partial ? (
          <Alert variant="default" className="text-warning">
            <TriangleAlert aria-hidden="true" />
            <AlertTitle>{t('rolesPartialTitle')}</AlertTitle>
            <AlertDescription>{t('rolesPartialDescription')}</AlertDescription>
            <RequestCorrelation
              requestId={catalog.requestId}
              traceId={catalog.traceId}
            />
            <ErrorDetails issues={catalog.errors} />
          </Alert>
        ) : null}

        {snapshotStatus === 'ready' && !changes ? (
          <p className="text-xs text-muted-foreground">
            {t('groupRolesNoChanges')}
          </p>
        ) : null}
      </RelationDialog>
    </>
  )
}
