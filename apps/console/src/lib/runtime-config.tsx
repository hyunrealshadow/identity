import { createContext, useContext, type ReactNode } from 'react'

import type { RuntimeConfig } from '#/lib/config'

const RuntimeConfigContext = createContext<RuntimeConfig | null>(null)

export function RuntimeConfigProvider({
  config,
  children,
}: {
  config: RuntimeConfig
  children: ReactNode
}) {
  return (
    <RuntimeConfigContext.Provider value={config}>
      {children}
    </RuntimeConfigContext.Provider>
  )
}

export function useRuntimeConfig(): RuntimeConfig {
  const config = useContext(RuntimeConfigContext)
  if (!config) throw new Error('useRuntimeConfig must be used inside RuntimeConfigProvider')
  return config
}
