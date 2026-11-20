import type { AuditCategory } from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'

/** Route of one audit log; each log is its own Console menu entry. */
export type AuditLogPath =
  | '/audit-events'
  | '/audit-events/management'
  | '/audit-events/sign-in'
  | '/audit-events/account'
  | '/audit-events/authorization'

export interface AuditLog {
  /** Absent for the log of every category. */
  category?: AuditCategory
  path: AuditLogPath
  nav: MessageKey
  title: MessageKey
  description: MessageKey
}

export const ALL_AUDIT_LOG: AuditLog = {
  path: '/audit-events',
  nav: 'navAuditAll',
  title: 'auditTitle',
  description: 'auditDescription',
}

// One log per category; the Record keeps every schema category routed.
export const AUDIT_CATEGORY_LOGS: Readonly<Record<AuditCategory, AuditLog>> = {
  MANAGEMENT: {
    category: 'MANAGEMENT',
    path: '/audit-events/management',
    nav: 'navAuditManagement',
    title: 'auditCategoryManagement',
    description: 'auditDescriptionManagement',
  },
  SIGN_IN: {
    category: 'SIGN_IN',
    path: '/audit-events/sign-in',
    nav: 'navAuditSignIn',
    title: 'auditCategorySignIn',
    description: 'auditDescriptionSignIn',
  },
  ACCOUNT: {
    category: 'ACCOUNT',
    path: '/audit-events/account',
    nav: 'navAuditAccount',
    title: 'auditCategoryAccount',
    description: 'auditDescriptionAccount',
  },
  AUTHORIZATION: {
    category: 'AUTHORIZATION',
    path: '/audit-events/authorization',
    nav: 'navAuditAuthorization',
    title: 'auditCategoryAuthorization',
    description: 'auditDescriptionAuthorization',
  },
}
