import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from '@rsbuild/core'
import { CopyDistToAssetsPlugin } from './plugins/copy-dist-to-assets.plugin'

const __dirname = dirname(fileURLToPath(import.meta.url))

const r = (...parts: string[]) => resolve(__dirname, ...parts)

export default defineConfig({
  mode: 'production',
  source: {
    entry: {
      'views/auth/login':    r('src/pages/login.ts'),
      'views/install/index': r('src/pages/install.ts'),
      'views/auth/otp':      r('src/pages/otp.ts'),
      'views/auth/password': r('src/pages/password.ts'),
    },
  },
  html: {
    title: '',
    meta: {
      charset: false,
      viewport: false
    },
    inject: false,
    template({ entryName }) {
      const templates: Record<string, string> = {
        'views/auth/login':    r('src/views/auth/login.html'),
        'views/install/index': r('src/views/install/index.html'),
        'views/auth/otp':      r('src/views/auth/otp.html'),
        'views/auth/password': r('src/views/auth/password.html'),
      };
      return templates[entryName]
    },
  },
  output: {
    polyfill: 'usage',
    filename: {
      js: '[contenthash].js',
      css: '[contenthash].css',
    },
    copy: [
      { from: r('src/views/layouts'), to: 'views/layouts' },
      { from: r('src/views/oauth2'), to: 'views/oauth2' },
    ],
  },
  tools: {
    rspack(config) {
      config.plugins.push(
        new CopyDistToAssetsPlugin({
          assetsRoot: r('../../assets'),
        }),
      )
    },
  },
})
