import { defineConfig } from 'tsup'

export default defineConfig({
  entry: { 'wallet-plugin-passkey': 'src/index.ts' },
  outDir: 'lib',
  format: ['esm'],
  outExtension: () => ({ js: '.mjs' }),
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
  /* @wharfkit/session is the peer dep — consumers bring their own. */
  external: ['@wharfkit/session'],
})
