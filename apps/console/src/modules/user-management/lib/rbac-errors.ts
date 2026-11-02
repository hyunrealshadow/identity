import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'

export interface RbacFeedbackState {
  errors: ReadonlyArray<GraphQLIssue>
  failure?: GraphQLFailure
  stepUp?: GraphQLStepUp
  requestId?: string
  traceId?: string
  forbidden: boolean
}

export interface RbacConflict {
  conflict: boolean
  currentVersion?: string
}

function text(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return undefined
}

function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

function currentVersion(issue: GraphQLIssue): string | undefined {
  const extensions = issue.extensions
  if (!extensions) return undefined
  const params = object(extensions.params)
  return (
    text(params?.current_version) ??
    text(params?.currentVersion) ??
    text(params?.version) ??
    text(extensions.current_version) ??
    text(extensions.currentVersion) ??
    text(extensions.version)
  )
}

/**
 * RBAC version and authorization-generation conflicts are intentionally
 * broader than user-profile conflicts, but never match field uniqueness errors.
 */
export function rbacConflict(
  issues: ReadonlyArray<GraphQLIssue>,
): RbacConflict {
  for (const issue of issues) {
    const versionField = issue.fields.some(({ path }) =>
      ['expectedVersion', 'expectedUserVersion'].includes(
        path.split('.').at(-1) ?? '',
      ),
    )
    if (issue.fields.length > 0 && !versionField) continue
    const value =
      `${issue.kind ?? ''} ${String(issue.code ?? '')}`.toLowerCase()
    if (
      value.includes('conflict') ||
      value.includes('stale') ||
      value.includes('version_mismatch')
    ) {
      return { conflict: true, currentVersion: currentVersion(issue) }
    }
  }
  return { conflict: false }
}

export function rbacFieldErrors(
  issues: ReadonlyArray<GraphQLIssue>,
): Record<string, string> {
  const result: Record<string, string> = {}
  for (const issue of issues) {
    for (const field of issue.fields) {
      const parts = field.path.split('.').filter(Boolean)
      const key = parts[parts.length - 1] ?? field.path
      if (!result[key]) {
        result[key] =
          field.message ?? (field.code !== undefined ? String(field.code) : '')
      }
    }
  }
  return result
}

export function hasFieldErrors(issues: ReadonlyArray<GraphQLIssue>): boolean {
  return issues.some((issue) => issue.fields.length > 0)
}
