import { createServerFn } from '@tanstack/react-start'

import {
  executeAccountAction,
  type AccountActionInput,
} from '#/modules/account/lib/account-action.server'

export const runAccountAction = createServerFn({ method: 'POST' })
  .validator((data: AccountActionInput) => data)
  .handler(({ data }) => executeAccountAction(data))
