import type { LocalizedEntry } from '#/lib/localized-values'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'

export type LocalizedTextValue = LocalizedEntry

/**
 * Display-only fields that the role and permission documents request. Names
 * are always resolved through the viewer's locale chain; base `name`,
 * `description`, and `code` are only final fallbacks.
 */
export interface RoleDisplayFields {
  builtIn?: boolean | null
  names?: ReadonlyArray<LocalizedTextValue> | null
  descriptions?: ReadonlyArray<LocalizedTextValue> | null
  name?: string | null
  description?: string | null
}

export interface PermissionDisplayFields {
  builtIn?: boolean | null
  names?: ReadonlyArray<LocalizedTextValue> | null
  descriptions?: ReadonlyArray<LocalizedTextValue> | null
  name?: string | null
  description?: string | null
  code: string
}

export function withRoleDisplayFields<T extends object>(
  role: T,
): T & RoleDisplayFields {
  return role as T & RoleDisplayFields
}

export function withPermissionDisplayFields<T extends object>(
  permission: T,
): T & PermissionDisplayFields {
  return permission as T & PermissionDisplayFields
}

export function roleIsBuiltIn(role: Pick<RoleDisplayFields, 'builtIn'>): boolean {
  return role.builtIn === true
}

export function permissionIsBuiltIn(
  permission: Pick<PermissionDisplayFields, 'builtIn'>,
): boolean {
  return permission.builtIn === true
}

export function roleDisplayName(
  role: RoleDisplayFields,
  locale: string,
): string {
  return resolveLocalizedText(role.names, locale) ?? role.name?.trim() ?? ''
}

export function roleDisplayDescription(
  role: RoleDisplayFields,
  locale: string,
): string | undefined {
  return (
    resolveLocalizedText(role.descriptions, locale) ??
    role.description?.trim() ??
    undefined
  )
}

export function permissionDisplayName(
  permission: PermissionDisplayFields,
  locale: string,
): string {
  return (
    resolveLocalizedText(permission.names, locale) ??
    permission.name?.trim() ??
    permission.code
  )
}

export function permissionDisplayDescription(
  permission: PermissionDisplayFields,
  locale: string,
): string | undefined {
  return (
    resolveLocalizedText(permission.descriptions, locale) ??
    permission.description?.trim() ??
    undefined
  )
}

/** Exact locale lookup used to seed editors, never a fallback translation. */
export function localizedValueFor(
  entries: ReadonlyArray<LocalizedTextValue> | null | undefined,
  locale: string,
): string {
  const normalized = locale.trim().toLowerCase()
  return (
    entries?.find(
      (entry) => entry.locale.trim().toLowerCase() === normalized,
    )?.value.trim() ?? ''
  )
}
