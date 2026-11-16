import { existsSync, readFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import basicSsl from '@vitejs/plugin-basic-ssl'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'
import { defineConfig, type Connect, type Plugin } from 'vite'

const BASE = '/console/'
const BASE_PATH = BASE.slice(0, -1)
const CONFIG_PATH = `${BASE}config.json`
const DEV_CA_PATH = path.resolve(import.meta.dirname, '../../config/tls/server.crt')
const securityHeaders = {
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "frame-ancestors 'none'",
}

function readWorkloadToken(): string | undefined {
  const file = process.env.IDENTITY_WORKLOAD_TOKEN_FILE?.trim()
  if (file && existsSync(file)) {
    return readFileSync(file, 'utf8').trim() || undefined
  }
  return (
    process.env.IDENTITY_CONSOLE_WORKLOAD_TOKEN?.trim() ||
    process.env.IDENTITY_WORKLOAD_TOKEN?.trim() ||
    undefined
  )
}

function fetchRuntimeConfiguration(
  targetUrl: URL,
  token: string,
): Promise<{ statusCode: number; body: string }> {
  const isHttps = targetUrl.protocol === 'https:'
  const caPath = process.env.IDENTITY_CA_FILE?.trim() || DEV_CA_PATH
  const ca = isHttps && existsSync(caPath) ? readFileSync(caPath) : undefined

  return new Promise((resolve, reject) => {
    const transport = isHttps ? https : http
    const req = transport.request(
      targetUrl,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${token}`,
        },
        ...(isHttps
          ? ca
            ? { ca }
            : { rejectUnauthorized: false }
          : {}),
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode ?? 502,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        })
      },
    )
    req.on('error', reject)
    req.end()
  })
}

/**
 * In development, proxy `/console/config.json` to Identity's internal runtime
 * configuration endpoint using the Console workload token so the browser always
 * receives the live client ID and addresses without a static snapshot.
 */
function consoleConfigProxyPlugin(): Plugin {
  return {
    name: 'console-config-proxy',
    configureServer: (server) => {
      server.middlewares.use(async (req, res, next) => {
        const pathname = (req.url ?? '/').split('?')[0]
        if (pathname !== CONFIG_PATH || (req.method !== 'GET' && req.method !== 'HEAD')) {
          next()
          return
        }
        const token = readWorkloadToken()
        if (!token) {
          next()
          return
        }
        const baseUrl =
          process.env.IDENTITY_INTERNAL_API_URL?.trim() || 'https://localhost:5151'
        const target = new URL('/internal/workloads/self/runtime-configuration', baseUrl)
        try {
          const upstream = await fetchRuntimeConfiguration(target, token)
          res.statusCode = upstream.statusCode
          res.setHeader('Content-Type', 'application/json; charset=utf-8')
          res.setHeader('Cache-Control', 'no-store')
          res.end(req.method === 'HEAD' ? undefined : upstream.body)
        } catch {
          res.statusCode = 503
          res.setHeader('Content-Type', 'application/json; charset=utf-8')
          res.setHeader('Cache-Control', 'no-store')
          res.end(
            req.method === 'HEAD'
              ? undefined
              : JSON.stringify({ error: 'console_configuration_unavailable' }),
          )
        }
      })
    },
  }
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
    consoleConfigProxyPlugin(),
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
