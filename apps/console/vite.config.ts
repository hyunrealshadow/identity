import basicSsl from '@vitejs/plugin-basic-ssl'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'
import { defineConfig } from 'vite'
const securityHeaders = {
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "frame-ancestors 'none'",
}

export default defineConfig(({ command }) => ({
  base: '/console/',
  appType: 'spa',
  plugins: [
    command === 'serve' && basicSsl(),
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
