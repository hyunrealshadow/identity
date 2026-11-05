import {
  Alert,
  Button,
  Checkbox,
  Chip,
  Modal,
  Pagination,
  Skeleton,
  useOverlayState,
} from '@heroui/react'
import { ChevronLeft, ChevronRight, Plus, Search } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import {
  ConsolePermissionOptionsDocument,
  ConsoleResourceOptionsDocument,
  type ConsolePermissionOptionsQuery,
  type ConsolePermissionOptionsQueryVariables,
  type ConsoleResourceOptionsQuery,
  type ConsoleResourceOptionsQueryVariables,
} from '#/gql/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { PermissionBuiltInChip } from '#/modules/user-management/roles/components/role-status'
import {
  permissionDisplayDescription,
  permissionDisplayName,
  permissionIsBuiltIn,
  withPermissionDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'
import type { StagedPermission } from '#/modules/user-management/roles/lib/permission-selection'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

const CATALOG_PAGE_SIZE = 100
const RESOURCE_PAGE_SIZE = 10
const ALL_RESOURCES = 'all'

type ResourceOption =
  ConsoleResourceOptionsQuery['resources']['edges'][number]['node']
type PermissionOption =
  ConsolePermissionOptionsQuery['permissions']['edges'][number]['node'] & {
    resource?: ResourceOption | null
  }

function metadataFromNode(item: PermissionOption): StagedPermission {
  const display = withPermissionDisplayFields(item)
  return {
    id: item.id,
    code: item.code,
    name: display.name ?? null,
    description: item.description,
    builtIn: permissionIsBuiltIn(display),
    names: display.names ? [...display.names] : [],
    descriptions: display.descriptions ? [...display.descriptions] : [],
    resourceId: item.resourceId ?? '',
    resourceName: item.resource?.name ?? null,
    resourceUri: item.resource?.uri ?? null,
    enabled: item.enabled,
  }
}

function resourceLabel(resource: ResourceOption): string {
  return resource.name || resource.uri
}

export function PermissionPickerDialog({
  subjectName,
  hint,
  assignedIds,
  initialSelected,
  initialMetadata,
  permissionRead,
  resourcesRead,
  disabled,
  triggerSize = 'sm',
  onApply,
}: {
  /** Display name of the role or client receiving permissions. */
  subjectName: string
  /** Optional replacement for the built-in permission hint. */
  hint?: string
  assignedIds: ReadonlySet<string>
  initialSelected: ReadonlySet<string>
  initialMetadata: ReadonlyMap<string, StagedPermission>
  permissionRead: boolean
  resourcesRead: boolean
  disabled: boolean
  /** Match the trigger to neighbouring actions; filter rows use the small size. */
  triggerSize?: 'sm' | 'md'
  onApply: (ids: string[], metadata: StagedPermission[]) => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [catalogAfter, setCatalogAfter] = useState<string | undefined>()
  const [catalogBefore, setCatalogBefore] = useState<string | undefined>()
  const [resourceQueryDraft, setResourceQueryDraft] = useState('')
  const [resourceQuery, setResourceQuery] = useState('')
  const [resourceAfter, setResourceAfter] = useState<string | undefined>()
  const [resourceHistory, setResourceHistory] = useState<
    Array<string | undefined>
  >([])
  const [resourceId, setResourceId] = useState('')
  const [modalSelected, setModalSelected] = useState<Set<string>>(new Set())
  const [modalMetadata, setModalMetadata] = useState<
    Map<string, StagedPermission>
  >(new Map())
  const [knownResources, setKnownResources] = useState<
    Map<string, ResourceOption>
  >(new Map())
  const opened = useRef(false)
  const initialSelectedRef = useRef(initialSelected)
  const initialMetadataRef = useRef(initialMetadata)
  initialSelectedRef.current = initialSelected
  initialMetadataRef.current = initialMetadata

  const catalogVariables =
    useMemo<ConsolePermissionOptionsQueryVariables | null>(
      () =>
        state.isOpen && permissionRead
          ? {
              filter: {
                apiOnly: true,
                ...(appliedQuery ? { query: appliedQuery } : {}),
                ...(resourceId ? { resourceId } : {}),
              },
              orderBy: 'CODE_ASC',
              ...cursorPage(CATALOG_PAGE_SIZE, catalogAfter, catalogBefore),
            }
          : null,
      [
        appliedQuery,
        catalogAfter,
        catalogBefore,
        permissionRead,
        resourceId,
        state.isOpen,
      ],
    )
  const catalog = useConsoleQuery<
    ConsolePermissionOptionsQuery,
    ConsolePermissionOptionsQueryVariables
  >(
    ConsolePermissionOptionsDocument,
    catalogVariables,
    'ConsolePermissionOptions',
    Boolean(catalogVariables),
    'missing_permission_catalog',
  )

  const resourceVariables =
    useMemo<ConsoleResourceOptionsQueryVariables | null>(
      () =>
        state.isOpen && resourcesRead
          ? {
              filter: resourceQuery ? { query: resourceQuery } : {},
              first: RESOURCE_PAGE_SIZE,
              after: resourceAfter,
            }
          : null,
      [resourceAfter, resourceQuery, resourcesRead, state.isOpen],
    )
  const resources = useConsoleQuery<
    ConsoleResourceOptionsQuery,
    ConsoleResourceOptionsQueryVariables
  >(
    ConsoleResourceOptionsDocument,
    resourceVariables,
    'ConsoleResourceOptions',
    Boolean(resourceVariables),
    'missing_resource_connection',
  )

  useEffect(() => {
    const edges = resources.data?.resources.edges
    if (!edges || edges.length === 0) return
    setKnownResources((current) => {
      let changed = false
      const next = new Map(current)
      for (const { node } of edges) {
        const previous = next.get(node.id)
        if (
          !previous ||
          previous.name !== node.name ||
          previous.uri !== node.uri ||
          previous.enabled !== node.enabled
        ) {
          next.set(node.id, node)
          changed = true
        }
      }
      return changed ? next : current
    })
  }, [resources.data])

  useEffect(() => {
    if (state.isOpen) {
      opened.current = true
      setQuery('')
      setAppliedQuery('')
      setCatalogAfter(undefined)
      setCatalogBefore(undefined)
      setResourceQueryDraft('')
      setResourceQuery('')
      setResourceAfter(undefined)
      setResourceHistory([])
      setResourceId('')
      setModalSelected(new Set(initialSelectedRef.current))
      setModalMetadata(new Map(initialMetadataRef.current))
      return
    }
    if (!opened.current) return
    setQuery('')
    setAppliedQuery('')
    setCatalogAfter(undefined)
    setCatalogBefore(undefined)
    setResourceQueryDraft('')
    setResourceQuery('')
    setResourceAfter(undefined)
    setResourceHistory([])
    setResourceId('')
    setModalSelected(new Set())
    setModalMetadata(new Map())
  }, [state.isOpen])

  const catalogItems: PermissionOption[] =
    catalog.data?.permissions.edges.map(({ node }) => ({
      ...node,
      resource: resourcesRead
        ? (knownResources.get(node.resourceId ?? '') ?? null)
        : null,
    })) ?? []
  const catalogConnection = catalog.data?.permissions ?? null
  const resourceConnection = resources.data?.resources ?? null
  const resourceOptions = useMemo(() => {
    const options: Array<{ id: string; label: string }> = [
      { id: ALL_RESOURCES, label: t('rolePermissionsPickerAllResources') },
    ]
    const seen = new Set<string>()
    for (const edge of resourceConnection?.edges ?? []) {
      if (seen.has(edge.node.id)) continue
      seen.add(edge.node.id)
      options.push({
        id: edge.node.id,
        label: resourceLabel(edge.node),
      })
    }
    if (resourceId && !seen.has(resourceId)) {
      const known = knownResources.get(resourceId)
      options.push({
        id: resourceId,
        label: known ? resourceLabel(known) : '',
      })
    }
    return options
  }, [knownResources, resourceConnection, resourceId, t])

  function applyCatalogSearch() {
    setAppliedQuery(query.trim())
    setCatalogAfter(undefined)
    setCatalogBefore(undefined)
  }

  function applyResourceSearch() {
    setResourceQuery(resourceQueryDraft.trim())
    setResourceAfter(undefined)
    setResourceHistory([])
  }

  function selectResource(value: string) {
    setResourceId(value === ALL_RESOURCES ? '' : value)
    setCatalogAfter(undefined)
    setCatalogBefore(undefined)
  }

  function previousResourcePage() {
    if (resourceHistory.length === 0) return
    const previous = resourceHistory[resourceHistory.length - 1]
    setResourceHistory((current) => current.slice(0, -1))
    setResourceAfter(previous)
  }

  function nextResourcePage() {
    const cursor = resourceConnection?.pageInfo.endCursor
    if (!cursor) return
    setResourceHistory((current) => [...current, resourceAfter])
    setResourceAfter(cursor)
  }

  function toggleCatalogItem(item: PermissionOption, isSelected: boolean) {
    setModalSelected((current) => {
      const next = new Set(current)
      if (isSelected) next.add(item.id)
      else next.delete(item.id)
      return next
    })
    if (isSelected) {
      setModalMetadata((current) => {
        const next = new Map(current)
        next.set(item.id, metadataFromNode(item))
        return next
      })
    }
  }

  function applySelection(close: () => void) {
    const ids = [...modalSelected].filter((id) => modalMetadata.has(id))
    const metadata = ids
      .map((id) => modalMetadata.get(id))
      .filter((item): item is StagedPermission => Boolean(item))
    onApply(ids, metadata)
    close()
  }

  return (
    <>
      <Button
        size={triggerSize}
        isDisabled={disabled || !permissionRead}
        onPress={state.open}
      >
        <Plus className="size-4" aria-hidden="true" />
        {t('rolePermissionsAddAction')}
      </Button>
      <Modal state={state}>
        <Modal.Backdrop isDismissable>
          <Modal.Container size="lg" scroll="inside">
            <Modal.Dialog className="w-full max-w-3xl">
              {({ close }) => (
                <>
                  <Modal.CloseTrigger aria-label={t('close')} />
                  <Modal.Header>
                    <Modal.Heading>
                      {t('rolePermissionsAddTitle')}
                    </Modal.Heading>
                  </Modal.Header>
                  <Modal.Body className="flex min-h-0 flex-col gap-3 overflow-y-auto">
                    <p className="text-sm leading-5 text-muted">
                      {t('rolePermissionsPickerDescription', {
                        role: subjectName,
                      })}
                    </p>
                    <p className="text-xs leading-5 text-muted">
                      {hint ?? t('rolePermissionsProtectedHint')}
                    </p>

                    <form
                      className="collection-filter-controls flex items-end gap-2"
                      onSubmit={(event) => {
                        event.preventDefault()
                        applyCatalogSearch()
                      }}
                    >
                      <div className="min-w-0 flex-1">
                        <UserTextField
                          name="permission-picker-query"
                          label={t('rolePermissionsCatalogSearchLabel')}
                          value={query}
                          onChange={setQuery}
                          placeholder={t(
                            'rolePermissionsCatalogSearchPlaceholder',
                          )}
                          maxLength={256}
                        />
                      </div>
                      <Button type="submit" size="sm">
                        <Search className="size-4" aria-hidden="true" />
                        {t('roleUsersSearchAction')}
                      </Button>
                    </form>

                    {resourcesRead ? (
                      <div className="grid shrink-0 gap-2 sm:grid-cols-2 sm:items-end">
                        <form
                          className="collection-filter-controls flex items-end gap-2"
                          onSubmit={(event) => {
                            event.preventDefault()
                            applyResourceSearch()
                          }}
                        >
                          <div className="min-w-0 flex-1">
                            <UserTextField
                              name="permission-picker-resource-query"
                              label={t(
                                'rolePermissionsPickerResourceSearchLabel',
                              )}
                              value={resourceQueryDraft}
                              onChange={setResourceQueryDraft}
                              placeholder={t(
                                'rolePermissionsPickerResourceSearchPlaceholder',
                              )}
                              maxLength={256}
                            />
                          </div>
                          <Button type="submit" size="sm">
                            {t('roleUsersSearchAction')}
                          </Button>
                        </form>
                        <div className="collection-filter-controls flex items-end gap-2">
                          <div className="min-w-0 flex-1">
                            <UserSelectField
                              name="permission-picker-resource"
                              label={t('rolePermissionsPickerResourceLabel')}
                              value={resourceId || ALL_RESOURCES}
                              onChange={selectResource}
                              options={resourceOptions}
                              isDisabled={resources.status === 'loading'}
                            />
                          </div>
                          <div
                            className="flex items-end gap-1"
                            role="group"
                            aria-label={t(
                              'rolePermissionsPickerResourceGroupLabel',
                            )}
                          >
                            <Button
                              size="sm"
                              variant="secondary"
                              isIconOnly
                              isDisabled={
                                resourceHistory.length === 0 ||
                                resources.status === 'loading'
                              }
                              aria-label={t(
                                'rolePermissionsPickerResourcePrevious',
                              )}
                              onPress={previousResourcePage}
                            >
                              <ChevronLeft
                                className="size-4"
                                aria-hidden="true"
                              />
                            </Button>
                            <Button
                              size="sm"
                              variant="secondary"
                              isIconOnly
                              isDisabled={
                                !resourceConnection?.pageInfo.hasNextPage ||
                                resources.status === 'loading'
                              }
                              aria-label={t(
                                'rolePermissionsPickerResourceNext',
                              )}
                              onPress={nextResourcePage}
                            >
                              <ChevronRight
                                className="size-4"
                                aria-hidden="true"
                              />
                            </Button>
                          </div>
                        </div>
                        {resources.status === 'loading' ? (
                          <p className="text-xs text-muted" role="status">
                            {t('rolePermissionsPickerResourceLoading')}
                          </p>
                        ) : null}
                        {resources.status === 'error' ? (
                          <AsyncState
                            kind={resources.forbidden ? 'forbidden' : 'error'}
                            compact
                            title={t('rolePermissionsPickerResourceError')}
                            description={t(
                              failureDescriptionKey(
                                resources.failure,
                                resources.forbidden,
                              ),
                            )}
                            requestId={resources.requestId}
                            traceId={resources.traceId}
                            issues={resources.errors}
                            onRetry={() => void resources.refresh()}
                          />
                        ) : null}
                        {resources.status === 'ready' &&
                        resourceConnection &&
                        resourceConnection.edges.length === 0 ? (
                          <p className="text-xs text-muted">
                            {t('rolePermissionsPickerResourceEmpty')}
                          </p>
                        ) : null}
                        {resources.partial ? (
                          <Alert status="warning">
                            <Alert.Indicator />
                            <Alert.Content>
                              <Alert.Title>
                                {t('rolesPartialTitle')}
                              </Alert.Title>
                              <Alert.Description>
                                {t('rolesPartialDescription')}
                              </Alert.Description>
                              <RequestCorrelation
                                requestId={resources.requestId}
                                traceId={resources.traceId}
                              />
                              <ErrorDetails issues={resources.errors} />
                            </Alert.Content>
                          </Alert>
                        ) : null}
                      </div>
                    ) : null}

                    <div
                      className="min-h-32 max-h-[min(24rem,32dvh)] shrink-0 overflow-y-auto overscroll-contain rounded-field border border-border sm:max-h-[min(24rem,40dvh)]"
                      role="region"
                      aria-label={t('rolePermissionsPickerResultsLabel')}
                    >
                      {catalog.status === 'error' ? (
                        <div className="p-3">
                          <AsyncState
                            kind={catalog.forbidden ? 'forbidden' : 'error'}
                            compact
                            title={t(
                              failureTitleKey(
                                catalog.failure,
                                catalog.forbidden,
                              ),
                            )}
                            description={t(
                              failureDescriptionKey(
                                catalog.failure,
                                catalog.forbidden,
                              ),
                            )}
                            requestId={catalog.requestId}
                            traceId={catalog.traceId}
                            issues={catalog.errors}
                            onRetry={() => void catalog.refresh()}
                          />
                        </div>
                      ) : catalog.status !== 'ready' || !catalog.data ? (
                        <div
                          className="space-y-2 p-3"
                          role="status"
                          aria-label={t('rolePermissionsCatalogLoading')}
                        >
                          <span className="sr-only">
                            {t('rolePermissionsCatalogLoading')}
                          </span>
                          {Array.from({ length: 4 }, (_, index) => (
                            <Skeleton
                              key={index}
                              className="h-14 w-full rounded-field"
                            />
                          ))}
                        </div>
                      ) : catalogItems.length === 0 ? (
                        <div className="p-3">
                          <AsyncState
                            kind="empty"
                            compact
                            title={t('rolePermissionsCatalogEmptyTitle')}
                            description={t(
                              'rolePermissionsCatalogEmptyDescription',
                            )}
                          />
                        </div>
                      ) : (
                        <ul className="divide-y divide-separator">
                          {catalogItems.map((item) => {
                            const display = withPermissionDisplayFields(item)
                            const alreadyAssigned = assignedIds.has(item.id)
                            const checked =
                              alreadyAssigned || modalSelected.has(item.id)
                            const name = permissionDisplayName(display, locale)
                            const description = permissionDisplayDescription(
                              display,
                              locale,
                            )
                            return (
                              <li key={item.id}>
                                <Checkbox
                                  className="w-full"
                                  isSelected={checked}
                                  isDisabled={alreadyAssigned}
                                  onChange={(isSelected) =>
                                    toggleCatalogItem(item, isSelected)
                                  }
                                >
                                  <Checkbox.Content className="min-h-14 w-full items-center gap-3 px-3 py-2 text-start">
                                    <Checkbox.Control>
                                      <Checkbox.Indicator />
                                    </Checkbox.Control>
                                    <span className="min-w-0 flex-1">
                                      <span className="flex flex-wrap items-center gap-2">
                                        <span className="text-xs font-medium">
                                          {name}
                                        </span>
                                        <span className="break-all font-mono text-[11px] text-muted">
                                          {item.code}
                                        </span>
                                        <PermissionBuiltInChip
                                          builtIn={permissionIsBuiltIn(display)}
                                        />
                                        {alreadyAssigned ? (
                                          <Chip
                                            size="sm"
                                            variant="soft"
                                            color="default"
                                          >
                                            <Chip.Label>
                                              {t(
                                                'rolePermissionsPickerAlreadyAssigned',
                                              )}
                                            </Chip.Label>
                                          </Chip>
                                        ) : null}
                                        {!item.enabled ? (
                                          <Chip
                                            size="sm"
                                            variant="soft"
                                            color="warning"
                                          >
                                            <Chip.Label>
                                              {t(
                                                'rolePermissionsPermissionDisabled',
                                              )}
                                            </Chip.Label>
                                          </Chip>
                                        ) : null}
                                        <span className="ms-auto max-w-[55%] truncate text-xs text-muted">
                                          {item.resource?.name ??
                                            item.resource?.uri ??
                                            ''}
                                        </span>
                                      </span>
                                      {description ? (
                                        <span className="mt-0.5 block truncate text-xs leading-4 text-muted">
                                          {description}
                                        </span>
                                      ) : null}
                                    </span>
                                  </Checkbox.Content>
                                </Checkbox>
                              </li>
                            )
                          })}
                        </ul>
                      )}
                    </div>

                    {catalog.partial ? (
                      <Alert status="warning">
                        <Alert.Indicator />
                        <Alert.Content>
                          <Alert.Title>{t('rolesPartialTitle')}</Alert.Title>
                          <Alert.Description>
                            {t('rolesPartialDescription')}
                          </Alert.Description>
                          <RequestCorrelation
                            requestId={catalog.requestId}
                            traceId={catalog.traceId}
                          />
                          <ErrorDetails issues={catalog.errors} />
                        </Alert.Content>
                      </Alert>
                    ) : null}

                    {catalogConnection ? (
                      <Pagination
                        aria-label={t('rolePermissionsCatalogPagination')}
                      >
                        <Pagination.Summary>
                          {t('tablePageSummary', {
                            count: catalogItems.length,
                            total: catalogConnection.totalCount,
                          })}
                        </Pagination.Summary>
                        <Pagination.Content>
                          <Pagination.Item>
                            <Pagination.Previous
                              isDisabled={
                                catalog.status === 'loading' ||
                                !catalogConnection.pageInfo.hasPreviousPage
                              }
                              onPress={() => {
                                const cursor =
                                  catalogConnection.pageInfo.startCursor
                                if (cursor) {
                                  setCatalogBefore(cursor)
                                  setCatalogAfter(undefined)
                                }
                              }}
                            >
                              <Pagination.PreviousIcon />
                              {t('previousPage')}
                            </Pagination.Previous>
                          </Pagination.Item>
                          <Pagination.Item>
                            <Pagination.Next
                              isDisabled={
                                catalog.status === 'loading' ||
                                !catalogConnection.pageInfo.hasNextPage
                              }
                              onPress={() => {
                                const cursor =
                                  catalogConnection.pageInfo.endCursor
                                if (cursor) {
                                  setCatalogAfter(cursor)
                                  setCatalogBefore(undefined)
                                }
                              }}
                            >
                              {t('nextPage')}
                              <Pagination.NextIcon />
                            </Pagination.Next>
                          </Pagination.Item>
                        </Pagination.Content>
                      </Pagination>
                    ) : null}
                  </Modal.Body>
                  <Modal.Footer>
                    <span className="me-auto text-xs text-muted">
                      {t('rolePermissionsPickerSelectedCount', {
                        count: modalSelected.size,
                      })}
                    </span>
                    <Button variant="secondary" onPress={close}>
                      {t('cancel')}
                    </Button>
                    <Button
                      isDisabled={modalSelected.size === 0}
                      onPress={() => applySelection(close)}
                    >
                      {t('rolePermissionsPickerAddSelected')}
                    </Button>
                  </Modal.Footer>
                </>
              )}
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>
    </>
  )
}
