/**
 * Identity of the account-center read. Kept separate from the query factory so
 * components can invalidate it without importing the server functions.
 */
export const ACCOUNT_QUERY_KEY = ['account'] as const
