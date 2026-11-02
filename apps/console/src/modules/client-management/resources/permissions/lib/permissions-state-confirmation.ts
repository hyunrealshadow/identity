import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'

export type PermissionStateAction = 'enable' | 'disable'

/**
 * The exact explicit confirmation the user was reviewing when authentication
 * interrupted the action. It contains no credentials and is only persisted by
 * the subject/issuer-scoped draft storage, so another actor cannot resume it.
 */
export interface PendingPermissionStateConfirmation {
  permissionId: string
  action: PermissionStateAction
  expectedVersion: string
}

const DRAFT_PREFIX = 'identity.console.permission-state-confirmation'

export function permissionStateConfirmationDraftKey(
  permissionId: string,
): string {
  return `${DRAFT_PREFIX}.${permissionId}`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parsePending(
  value: unknown,
): PendingPermissionStateConfirmation | null {
  if (!isRecord(value)) return null
  const { permissionId, action, expectedVersion } = value
  if (typeof permissionId !== 'string' || permissionId.length === 0) return null
  if (action !== 'enable' && action !== 'disable') return null
  if (typeof expectedVersion !== 'string' || expectedVersion.length === 0) {
    return null
  }
  return { permissionId, action, expectedVersion }
}

export function readPendingPermissionStateConfirmation(
  permissionId: string,
): PendingPermissionStateConfirmation | null {
  const pending = parsePending(
    readDraft<unknown>(permissionStateConfirmationDraftKey(permissionId)),
  )
  if (!pending || pending.permissionId !== permissionId) return null
  return pending
}

export function writePendingPermissionStateConfirmation(
  pending: PendingPermissionStateConfirmation,
): void {
  const normalized = parsePending(pending)
  if (!normalized) return
  writeDraft(
    permissionStateConfirmationDraftKey(normalized.permissionId),
    normalized,
  )
}

export function clearPendingPermissionStateConfirmation(
  permissionId: string,
): void {
  clearDraft(permissionStateConfirmationDraftKey(permissionId))
}
