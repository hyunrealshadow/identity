import { cp, rm } from 'node:fs/promises'
import { resolve } from 'node:path'

type CompilerLike = {
  hooks: {
    done: {
      tapPromise: (name: string, handler: () => Promise<void>) => void
    }
  }
  options?: {
    output?: {
      path?: string
    }
  }
}

export class CopyDistToAssetsPlugin {
  constructor(
    private readonly options: {
      assetsRoot: string
    },
  ) {}

  apply(compiler: CompilerLike): void {
    compiler.hooks.done.tapPromise('CopyDistToAssetsPlugin', async () => {
      const distRoot = compiler.options?.output?.path
      if (!distRoot) {
        throw new Error('CopyDistToAssetsPlugin: output.path is not defined')
      }

      const fromViews = resolve(distRoot, 'views')
      const fromStaticCss = resolve(distRoot, 'static/css')
      const fromStaticJs = resolve(distRoot, 'static/js')
      const toViews = resolve(this.options.assetsRoot, 'views')
      const toStaticCss = resolve(this.options.assetsRoot, 'static/css')
      const toStaticJs = resolve(this.options.assetsRoot, 'static/js')

      await rm(toViews, { recursive: true, force: true })
      await rm(toStaticCss, { recursive: true, force: true })
      await rm(toStaticJs, { recursive: true, force: true })

      await cp(fromViews, toViews, { recursive: true, force: true })
      await cp(fromStaticCss, toStaticCss, { recursive: true, force: true })
      await cp(fromStaticJs, toStaticJs, { recursive: true, force: true })
    })
  }
}
