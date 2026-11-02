/**
 * Permission writes reuse the shared RBAC feedback, conflict, and field-error
 * helpers so version conflicts and structured server errors behave exactly
 * like role, group, and assignment writes.
 */
export {
  hasFieldErrors,
  rbacConflict as permissionConflict,
  rbacFieldErrors as permissionFieldErrors,
  type RbacConflict,
  type RbacFeedbackState,
} from '#/modules/user-management/lib/rbac-errors'
