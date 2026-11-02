import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'

export interface VersionConflict {
  conflict: boolean
  currentVersion?: string
}

export interface MutationFeedbackState {
  errors: ReadonlyArray<GraphQLIssue>
  failure?: GraphQLFailure
  stepUp?: GraphQLStepUp
  requestId?: string
  traceId?: string
  forbidden: boolean
}

function extensionText(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return undefined
}

function extensionObject(
  value: unknown,
): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

/**
 * User-management version conflicts use the stable numeric application code
 * 16008. The backend exposes the current version only when available, so the
 * parser tolerates top-level and nested version params for display. Detection
 * stays code-only, so identifier uniqueness conflicts never become version
 * conflicts.
 */
const VERSION_CONFLICT_CODE = 16008

function isVersionConflictCode(code: unknown): boolean {
  return code === VERSION_CONFLICT_CODE || code === '16008'
}

function currentVersionOf(issue: GraphQLIssue): string | undefined {
  const extensions = issue.extensions
  if (!extensions) return undefined
  const params = extensionObject(extensions.params)
  return (
    extensionText(params?.current_version) ??
    extensionText(params?.currentVersion) ??
    extensionText(params?.version) ??
    extensionText(extensions.current_version) ??
    extensionText(extensions.currentVersion) ??
    extensionText(extensions.version)
  )
}

/**
 * The backend owns the stable conflict code. Keep the detection deliberately
 * narrow so username/email uniqueness errors stay field-level validation.
 */
export function versionConflict(
  issues: ReadonlyArray<GraphQLIssue>,
): VersionConflict {
  for (const issue of issues) {
    if (!isVersionConflictCode(issue.code)) continue
    return { conflict: true, currentVersion: currentVersionOf(issue) }
  }

  return { conflict: false }
}

function lastPathSegment(path: string): string {
  const parts = path.split('.').filter(Boolean)
  return parts[parts.length - 1] ?? path
}

/**
 * Flatten the server field paths to the leaf name used by the form. Nested
 * profile paths like `input.profile.givenName` map to `givenName`.
 */
export function fieldErrorsFromIssues(
  issues: ReadonlyArray<GraphQLIssue>,
): Record<string, string> {
  const result: Record<string, string> = {}
  for (const issue of issues) {
    for (const field of issue.fields) {
      const key = lastPathSegment(field.path)
      if (!key || result[key]) continue
      result[key] =
        field.message ?? (field.code !== undefined ? String(field.code) : '')
    }
  }
  return result
}

export function formLevelIssues(
  issues: ReadonlyArray<GraphQLIssue>,
): GraphQLIssue[] {
  return issues.filter(
    (issue) =>
      issue.fields.length === 0 &&
      Boolean(issue.message || issue.code !== undefined || issue.kind),
  )
}
