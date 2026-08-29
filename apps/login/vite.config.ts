import { defineConfig } from 'vite'
import { devtools } from '@tanstack/devtools-vite'
import basicSsl from '@vitejs/plugin-basic-ssl'

import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import { nitro } from 'nitro/vite'

import viteReact from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const config = defineConfig(({ command, isPreview, mode }) => {
  const isTest = mode === 'test'
  const isDevelopment = command === 'serve' && !isPreview && !isTest

  if (isDevelopment) {
    // The local Identity server uses an auto-generated self-signed certificate.
    // Scope this relaxation to the Vite development process only.
    process.env.NODE_TLS_REJECT_UNAUTHORIZED ??= '0'
  }

  return {
    resolve: { tsconfigPaths: true },
    server: {
      allowedHosts: ['login', 'login.localhost'],
    },
    plugins: [
      isDevelopment && basicSsl(),
      devtools(),
      tailwindcss(),
      tanstackStart(),
      !isTest && nitro(),
      viteReact(),
    ],
  }
})

export default config
