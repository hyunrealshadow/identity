import basicSsl from '@vitejs/plugin-basic-ssl'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'
import { defineConfig, type Connect, type Plugin } from 'vite'

const BASE = '/console/'
const BASE_PATH = BASE.slice(0, -1)
const securityHeaders = {
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "frame-ancestors 'none'",
}

/**
 * Vite only serves paths below `/console/`. Serve the canonical `/console`
 * address directly and send the legacy slash form back to it.
 */
const consoleBasePath: Connect.NextHandleFunction = (req, res, next) => {
  const url = req.url ?? '/'
  const queryIndex = url.indexOf('?')
  const pathname = queryIndex === -1 ? url : url.slice(0, queryIndex)
  const query = queryIndex === -1 ? '' : url.slice(queryIndex)
  if (pathname === BASE) {
    res.statusCode = 308
    res.setHeader('Location', `${BASE_PATH}${query}`)
    res.end()
    return
  }
  if (pathname === BASE_PATH) req.url = `${BASE}${query}`
  next()
}

function consoleBasePathPlugin(): Plugin {
  return {
    name: 'console-base-path',
    configureServer: (server) => void server.middlewares.use(consoleBasePath),
    configurePreviewServer: (server) => void server.middlewares.use(consoleBasePath),
  }
}

export default defineConfig(({ command }) => ({
  base: BASE,
  appType: 'spa',
  plugins: [
    command === 'serve' && basicSsl(),
    consoleBasePathPlugin(),
    tailwindcss(),
    tanstackRouter({
      target: 'react',
      autoCodeSplitting: true,
    }),
    react(),
  ],
  resolve: {
    tsconfigPaths: true,
  },
  server: {
    headers: securityHeaders,
    port: 3100,
    strictPort: true,
  },
  preview: {
    headers: securityHeaders,
    port: 3100,
    strictPort: true,
  },
}))
