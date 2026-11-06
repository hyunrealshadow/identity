import { TableRowActions } from '#/components/table-row-actions'
import { CopyButton } from '#/components/copy-button'
import { DataTable } from '@identity/ui/data-table'
import { Chip, Pagination } from '@heroui/react'
import { Undo2, X } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import type { MessageKey } from '#/lib/i18n'
import { useLocale, useTranslator } from '#/lib/i18n'
import { PermissionBuiltInChip } from '#/modules/user-management/roles/components/role-status'
import type { PermissionNode } from '#/modules/user-management/roles/hooks/use-role-membership'
import {
  permissionDisplayDescription,
  permissionDisplayName,
  permissionIsBuiltIn,
  withPermissionDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'
import type { StagedPermission } from '#/modules/user-management/roles/lib/permission-selection'

type RowStatus = 'assigned' | 'assigned-disabled' | 'added' | 'removed'

interface PermissionRow {
  id: string
  code: string
  name: string
  description: string | null
  builtIn: boolean
  resourceId: string | null
  resource: string | null
  status: RowStatus
}

const STATUS_LABEL: Record<RowStatus, MessageKey> = {
  assigned: 'rolePermissionsStatusAssigned',
  'assigned-disabled': 'rolePermissionsStatusAssignedDisabled',
  added: 'rolePermissionsStatusAdded',
  removed: 'rolePermissionsStatusRemoved',
}

function compareRows(a: PermissionRow, b: PermissionRow): number {
  if (a.code !== b.code) return a.code < b.code ? -1 : 1
  if (a.id === b.id) return 0
  return a.id < b.id ? -1 : 1
}

export function RolePermissionTable({
  resourceId,
  items,
  initial,
  selected,
  staged,
  disabled,
  onToggle,
}: {
  resourceId?: string
  items: ReadonlyArray<PermissionNode>
  initial: ReadonlySet<string>
  selected: ReadonlySet<string>
  staged: ReadonlyMap<string, StagedPermission>
  disabled: boolean
  onToggle: (permissionId: string) => void
}) {
  const [page, setPage] = useState(1)
  useEffect(() => setPage(1), [resourceId])
  const t = useTranslator()
  const { locale } = useLocale()
  const rows: PermissionRow[] = []

  for (const item of items) {
    const isSelected = selected.has(item.id)
    const display = withPermissionDisplayFields(item)
    rows.push({
      id: item.id,
      code: item.code,
      name: permissionDisplayName(display, locale),
      description: permissionDisplayDescription(display, locale) ?? null,
      builtIn: permissionIsBuiltIn(display),
      resourceId: item.resourceId ?? null,
      resource: item.resource?.name ?? item.resource?.uri ?? null,
      status:
        !initial.has(item.id) || isSelected
          ? item.enabled
            ? 'assigned'
            : 'assigned-disabled'
          : 'removed',
    })
  }

  for (const item of staged.values()) {
    if (initial.has(item.id)) continue
    if (!selected.has(item.id)) continue
    const display = withPermissionDisplayFields(item)
    rows.push({
      id: item.id,
      code: item.code,
      name: permissionDisplayName(display, locale),
      description: permissionDisplayDescription(display, locale) ?? null,
      builtIn: permissionIsBuiltIn(display),
      resourceId: item.resourceId,
      resource: item.resourceName ?? item.resourceUri ?? null,
      status: 'added',
    })
  }

  rows.sort(compareRows)
  const visibleRows = resourceId
    ? rows.filter((row) => row.resourceId === resourceId)
    : rows

  const pageSize = 100
  const pages = Math.max(1, Math.ceil(visibleRows.length / pageSize))
  const currentPage = Math.min(page, pages)
  const pageRows = visibleRows.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize,
  )

  if (visibleRows.length === 0) {
    return (
      <div className="p-4">
        <AsyncState
          kind="empty"
          compact
          title={t('rolePermissionsNoneTitle')}
          description={t('rolePermissionsNoneDescription')}
        />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <DataTable
        label={t('rolePermissionsTableLabel')}
        minWidth={760}
        density="compact"
        maxHeight="clamp(12rem, calc(100dvh - 26rem), 32rem)"
        columns={[
          {
            id: 'rolePermissionsColumnPermission',
            label: t('rolePermissionsColumnPermission'),
            primary: true,
          },
          {
            id: 'rolePermissionsColumnDescription',
            label: t('rolePermissionsColumnDescription'),
            primary: false,
          },
          {
            id: 'rolePermissionsColumnResource',
            label: t('rolePermissionsColumnResource'),
            primary: false,
          },
          {
            id: 'rolePermissionsColumnStatus',
            label: t('rolePermissionsColumnStatus'),
            primary: false,
          },
          {
            id: 'rolePermissionsColumnActions',
            label: t('rolePermissionsColumnActions'),
            primary: false,
          },
        ]}
      >
        <DataTable.Body>
          {pageRows.map((row) => {
            const removed = row.status === 'removed'
            return (
              <DataTable.Row key={row.id} id={row.id} className="h-14">
                <DataTable.Cell className="py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={
                        removed
                          ? 'text-xs font-medium text-muted line-through'
                          : 'text-xs font-medium'
                      }
                    >
                      {row.name}
                    </span>
                    <PermissionBuiltInChip builtIn={row.builtIn} />
                  </div>
                  <div className="flex items-center gap-1">
                    <span
                      className={
                        removed
                          ? 'mt-0.5 block break-all font-mono text-[11px] text-muted line-through'
                          : 'mt-0.5 block break-all font-mono text-[11px] text-muted'
                      }
                    >
                      {row.code}
                    </span>
                    <CopyButton
                      value={row.code}
                      label={t('permissionCodeLabel')}
                    />
                  </div>
                </DataTable.Cell>
                <DataTable.Cell className="py-2">
                  <span
                    className={
                      removed
                        ? 'line-clamp-2 max-w-[26rem] text-xs leading-4 text-muted line-through'
                        : 'line-clamp-2 max-w-[26rem] text-xs leading-4 text-muted'
                    }
                  >
                    {row.description}
                  </span>
                </DataTable.Cell>
                <DataTable.Cell className="py-2">
                  <span className="line-clamp-1 max-w-56 text-xs text-muted">
                    {row.resource ?? t('rolePermissionsResourceUnavailable')}
                  </span>
                </DataTable.Cell>
                <DataTable.Cell className="py-2">
                  <Chip
                    size="sm"
                    variant="soft"
                    color={
                      row.status === 'added'
                        ? 'success'
                        : row.status === 'removed'
                          ? 'warning'
                          : row.status === 'assigned-disabled'
                            ? 'default'
                            : 'success'
                    }
                  >
                    <Chip.Label>{t(STATUS_LABEL[row.status])}</Chip.Label>
                  </Chip>
                </DataTable.Cell>
                <DataTable.Cell className="py-2">
                  <TableRowActions
                    subject={row.code}
                    actions={[
                      {
                        id: 'toggle',
                        label: t(
                          removed
                            ? 'rolePermissionsUndoRemoval'
                            : 'rolePermissionsRemoveAction',
                        ),
                        isDisabled: disabled,
                        onAction: () => onToggle(row.id),
                        danger: !removed,
                        icon: removed ? (
                          <Undo2 className="size-4" aria-hidden="true" />
                        ) : (
                          <X className="size-4" aria-hidden="true" />
                        ),
                      },
                    ]}
                  />
                </DataTable.Cell>
              </DataTable.Row>
            )
          })}
        </DataTable.Body>
      </DataTable>
      <Pagination aria-label={t('rolePermissionsTableLabel')}>
        <Pagination.Summary>
          {t('tablePageSummary', {
            count: pageRows.length,
            total: visibleRows.length,
          })}
        </Pagination.Summary>
        <Pagination.Content>
          <Pagination.Item>
            <Pagination.Previous
              isDisabled={currentPage === 1}
              onPress={() => setPage(currentPage - 1)}
            >
              <Pagination.PreviousIcon />
              {t('previousPage')}
            </Pagination.Previous>
          </Pagination.Item>
          {Array.from({ length: pages }, (_, index) => index + 1).map(
            (number) => (
              <Pagination.Item key={number}>
                <Pagination.Link
                  isActive={number === currentPage}
                  onPress={() => setPage(number)}
                  aria-label={t('tableGoToPage', { page: number })}
                >
                  {number}
                </Pagination.Link>
              </Pagination.Item>
            ),
          )}
          <Pagination.Item>
            <Pagination.Next
              isDisabled={currentPage === pages}
              onPress={() => setPage(currentPage + 1)}
            >
              {t('nextPage')}
              <Pagination.NextIcon />
            </Pagination.Next>
          </Pagination.Item>
        </Pagination.Content>
      </Pagination>
    </div>
  )
}
