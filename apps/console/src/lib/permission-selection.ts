export interface PermissionMembershipState {
  status: 'idle' | 'loading' | 'ready' | 'error'
  ids: ReadonlySet<string>
  loadedPages: number
  hasNextPage: boolean
}

/**
 * Display metadata retained for permissions staged from a catalog page that
 * may no longer be loaded. It intentionally excludes versions and other
 * technical fields from the draft.
 */
export interface StagedPermission {
  id: string
  code: string
  name?: string | null
  description: string | null
  builtIn?: boolean | null
  names?: ReadonlyArray<{ locale: string; value: string }>
  descriptions?: ReadonlyArray<{ locale: string; value: string }>
  resourceId: string
  resourceName: string | null
  resourceUri: string | null
  enabled: boolean
}

export interface SubmitAvailability {
  allowed: boolean
  reason:
    | 'ready'
    | 'membership-loading'
    | 'membership-incomplete'
    | 'membership-error'
    | 'catalog-loading'
    | 'catalog-error'
    | 'no-changes'
}

export function initialPermissionSelection(
  membership: PermissionMembershipState,
): Set<string> {
  if (
    membership.status !== 'ready' ||
    membership.hasNextPage ||
    membership.loadedPages < 1
  ) {
    return new Set()
  }
  return new Set(membership.ids)
}

export function togglePermission(
  selected: ReadonlySet<string>,
  permissionId: string,
): Set<string> {
  const next = new Set(selected)
  if (next.has(permissionId)) next.delete(permissionId)
  else next.add(permissionId)
  return next
}

function sameIds(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  if (a.size !== b.size) return false
  for (const value of a) if (!b.has(value)) return false
  return true
}

export function rolePermissionSubmitAvailability(input: {
  membership: PermissionMembershipState
  catalogStatus: 'idle' | 'loading' | 'ready' | 'error'
  initial: ReadonlySet<string>
  selected: ReadonlySet<string>
}): SubmitAvailability {
  if (input.membership.status === 'loading') {
    return { allowed: false, reason: 'membership-loading' }
  }
  if (input.membership.status === 'error') {
    return { allowed: false, reason: 'membership-error' }
  }
  if (
    input.membership.status !== 'ready' ||
    input.membership.hasNextPage ||
    input.membership.loadedPages < 1
  ) {
    return { allowed: false, reason: 'membership-incomplete' }
  }
  if (input.catalogStatus === 'idle' || input.catalogStatus === 'loading') {
    return { allowed: false, reason: 'catalog-loading' }
  }
  if (input.catalogStatus === 'error') {
    return { allowed: false, reason: 'catalog-error' }
  }
  if (sameIds(input.initial, input.selected)) {
    return { allowed: false, reason: 'no-changes' }
  }
  return { allowed: true, reason: 'ready' }
}

export function selectionDiff(
  initial: ReadonlySet<string>,
  selected: ReadonlySet<string>,
): { added: string[]; removed: string[] } {
  const added: string[] = []
  const removed: string[] = []
  for (const id of selected) if (!initial.has(id)) added.push(id)
  for (const id of initial) if (!selected.has(id)) removed.push(id)
  return { added: added.sort(), removed: removed.sort() }
}
