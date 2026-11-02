import type { CodegenConfig } from '@graphql-codegen/cli'

const config: CodegenConfig = {
  schema: '../../graphql/schema.graphql',
  documents: ['src/**/*.graphql'],
  ignoreNoDocuments: false,
  generates: {
    'src/gql/': {
      preset: 'client',
      config: {
        useTypeImports: true,
        documentMode: 'string',
        enumsAsTypes: true,
        scalars: {
          UUID: { input: 'string', output: 'string' },
          NaiveDate: { input: 'string', output: 'string' },
          DateTime: { input: 'string', output: 'string' },
          JSON: { input: 'unknown', output: 'unknown' },
        },
      },
      presetConfig: {
        fragmentMasking: false,
      },
    },
  },
}

export default config
