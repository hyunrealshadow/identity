import type { LuceneFieldValueOption } from '@identity/lucene-input'

/** Server error codes (E30003–E30013) that reject the query statement itself. */
export const AUDIT_QUERY_ERROR_CODES: ReadonlySet<number> = new Set([
  30003, 30004, 30005, 30006, 30007, 30008, 30009, 30010, 30011, 30012, 30013,
])

export const AUDIT_ACTOR_TYPE_OPTIONS: readonly LuceneFieldValueOption[] = [
  { label: 'user', value: 'user' },
  { label: 'client', value: 'client' },
  { label: 'system', value: 'system' },
  { label: 'unknown', value: 'unknown' },
]

export const AUDIT_OPERATION_OPTIONS: readonly LuceneFieldValueOption[] = [
  { label: 'mutation', value: 'mutation' },
  { label: 'authorization', value: 'authorization' },
]

export const AUDIT_STATUS_OPTIONS: readonly LuceneFieldValueOption[] = [
  { label: 'success', value: 'success' },
  { label: 'failed', value: 'failed' },
]

export const AUDIT_EVENT_KIND_OPTIONS: readonly LuceneFieldValueOption[] = [
  { label: 'semantic', value: 'semantic' },
]

export const AUDIT_ENTITY_TYPE_OPTIONS: readonly LuceneFieldValueOption[] = [
  { label: 'user', value: 'user' },
  { label: 'client', value: 'client' },
  { label: 'resource', value: 'resource' },
  { label: 'scope', value: 'scope' },
  { label: 'role', value: 'role' },
  { label: 'user_group', value: 'user_group' },
  { label: 'session', value: 'session' },
  { label: 'key', value: 'key' },
  { label: 'setting', value: 'setting' },
  { label: 'login', value: 'login' },
  { label: 'user_credential', value: 'user_credential' },
  { label: 'group_membership', value: 'group_membership' },
  { label: 'group_role', value: 'group_role' },
  { label: 'user_role', value: 'user_role' },
  { label: 'client_authorization', value: 'client_authorization' },
  { label: 'device_authorization', value: 'device_authorization' },
  { label: 'device_authorization_request', value: 'device_authorization_request' },
]

export const KNOWN_STATIC_ACTIONS: readonly string[] = [
  'client.create',
  'client.update',
  'client.enable',
  'client.disable',
  'client.delete',
  'client_credential.create',
  'client_credential.revoke',
  'group.create',
  'group.update',
  'group.enable',
  'group.disable',
  'group.delete',
  'group_member.add',
  'group_member.remove',
  'group_role.assign',
  'group_role.revoke',
  'role.create',
  'role.update',
  'role.enable',
  'role.disable',
  'role.delete',
  'role_permission.set',
  'user.create',
  'user.update',
  'user.enable',
  'user.disable',
  'user.lock',
  'user.unlock',
  'user_role.assign',
  'user_role.revoke',
  'resource.create',
  'resource.update',
  'resource.enable',
  'resource.disable',
  'resource.delete',
  'scope.create',
  'scope.update',
  'scope.enable',
  'scope.disable',
  'scope.delete',
  'key.rotate',
  'key.revoke',
  'setting.update',
  'session.revoke',
  'owner.bootstrap',
]

export function mergeActionOptions(liveActions: readonly string[] | undefined): LuceneFieldValueOption[] {
  const seen = new Set<string>()
  const merged: LuceneFieldValueOption[] = []
  for (const action of [...(liveActions ?? []), ...KNOWN_STATIC_ACTIONS]) {
    const trimmed = action.trim()
    if (!trimmed || seen.has(trimmed)) continue
    seen.add(trimmed)
    merged.push({ label: trimmed, value: trimmed })
  }
  merged.sort((a, b) => a.label.localeCompare(b.label))
  return merged
}

export function filterCatalogOptions(
  options: readonly LuceneFieldValueOption[],
  query: string,
): LuceneFieldValueOption[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return [...options]
  return options.filter(
    (option) =>
      option.label.toLowerCase().includes(needle) ||
      Boolean(option.detail?.toLowerCase().includes(needle)),
  )
}
