/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * R24: "email:password" of the seeded demo account (LOCAL DEV value, baked in at build time). When set, the
   * login page offers "Use demo account". Read it through `getDemoCredentials()` in src/lib/demo.ts.
   */
  readonly VITE_DEMO_CREDENTIALS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
