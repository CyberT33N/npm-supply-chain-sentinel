/*
 *███████████████████████████████████████████████████████████████████████████████
 *██******************** PRESENTED BY t33n Software ***************************██
 *██                                                                           ██
 *██                  ████████╗██████╗ ██████╗ ███╗   ██╗                      ██
 *██                  ╚══██╔══╝╚════██╗╚════██╗████╗  ██║                      ██
 *██                     ██║    █████╔╝ █████╔╝██╔██╗ ██║                      ██
 *██                     ██║    ╚═══██╗ ╚═══██╗██║╚██╗██║                      ██
 *██                     ██║   ██████╔╝██████╔╝██║ ╚████║                      ██
 *██                     ╚═╝   ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                      ██
 *██                                                                           ██
 *███████████████████████████████████████████████████████████████████████████████
 *███████████████████████████████████████████████████████████████████████████████
 */

// ═══╡ 🧩 IMPORTS ╞═══
import { config as dotenvConfig } from 'dotenv'
import tsconfigPaths from 'vite-tsconfig-paths'
import { defineConfig } from 'vitest/config'

// ═══╡ 🏷️TYPES ╞═══
import type { ViteUserConfig } from 'vitest/config'

// 🔄 Load the test environment variables from .env.test and override defaults
dotenvConfig({
    override: true,
    path: '.env.test'
})

// 📋 Define the base verification configuration for the modularized server topology
const cfg = defineConfig({
    /**
     * List of plugins to be used in the configuration.
     */
    plugins: [tsconfigPaths()],

    /**
     * Configuration options for tests.
     */
    test: {
    // ✅ Sauberes Mocking, um Nebeneffekte zu vermeiden

        /*
         *> Setzt **alle Aufrufe (calls)** zurück – nicht die Implementierung.
         *
         *🧠 Wenn **nicht gesetzt**, musst du manuell `mockClear` aufrufen:
         *
         *```ts
         *afterEach(() => {
         *  vi.clearAllMocks(); // = alle mockFn.mock.calls = []
         *});
         *```
         *
         *Oder gezielt:
         *
         *```ts
         *afterEach(() => {
         *  myMockFn.mockClear();
         *});
         *```
         */
        clearMocks: true,

        /**
         * Configuration for coverage reporting.
         */
        coverage: {
            /**
             * Specifies whether coverage is enabled.
             *
             */
            enabled: true,

            /**
             * Specifies the files or directories to exclude from coverage.
             *
             */
            exclude: [
                '**/e2e/**',
                '**/*.e2e.{ts,tsx,js,jsx}',
                'dist/',
                'out/',
                'log/',
                '.cursor/'
            ],

            /**
             * Specifies the directories to include for coverage.
             *
             */
            include: ['src/'],

            /**
             * Specifies the coverage provider to use.
             *
             */
            provider: 'v8',

            /**
             * Specifies the coverage reporters to use.
             *
             */
            reporter: [
                'text',
                'json',
                'html'
            ]
        },

        // 🌐 Test environment set to Node.js
        /**
         * Disables the console intercept.
         *
         */
        disableConsoleIntercept: true,

        /**
         * The environment in which the tests will run.
         *
         */
        environment: 'node',

         /**
          * Path to the shared global setup file that establishes the common
          * verification baseline before unit and regression projects run.
          */
         globalSetup: ['test/pretest-base.ts'],

        hookTimeout: 300_000,

        /*
         *> Setzt Implementierung + Aufrufe zurück.
         *
         *🧠 Wenn du es **trotzdem tun willst**, aber nicht global gesetzt hast:
         *
         *```ts
         *afterEach(() => {
         *  vi.resetAllMocks(); // calls + implementation reset
         *});
         *```
         *
         *Oder individuell:
         *
         *```ts
         *afterEach(() => {
         *  someMockFn.mockReset();
         *});
         *```
         */
        mockReset: false,

         /**
          * Project configurations keep unit and regression verification surfaces
          * distinct while sharing one modularized server baseline.
          */
         projects: [
             './vitest.unit.config.ts',
             './vitest.regression.config.ts'
         ],

        /*
         *> Behalte die ursprüngliche Implementierung von Mocks (z.B. `vi.spyOn`), selbst nach dem Testlauf.
         *
         *🧠 Wenn `restoreMocks: true` **nicht gesetzt ist**, du willst aber manuell *restore*-n:
         *
         *```ts
         *afterEach(() => {
         *  vi.restoreAllMocks(); // setzt originale Implementierung zurück
         *});
         *```
         *
         *Oder gezielt:
         *
         *```ts
         *afterEach(() => {
         *  someSpy.mockRestore();
         *});
         *```
         */
        restoreMocks: false,

         /**
          * Path to the shared setup file that installs common Vitest matchers and
          * shared verification helpers for all projects.
          */
         setupFiles: ['test/vitest-setup.ts'],

        /**
         * The timeout for each test hook.
         *
         */
        testTimeout: 300_000,

        /**
         * Configuration for type checking.
         */
        typecheck: {
            enabled: true
        },

        /*
         *> Setzt **alle gestubbten Umgebungsvariablen** automatisch nach jedem Test zurück.
         *Hilfreich, wenn du `vi.stubEnv('FOO', 'bar')` o.Ä. nutzt – spart dir `vi.unstubEnv(...)` Aufräumaktionen.
         *
         *## 🧼 Wenn **nicht** gesetzt – manuell aufräumen:
         *
         *
         *```ts
         *afterEach(() => {
         *  vi.unstubEnv('MY_ENV_VAR');
         *  vi.unstubEnv('ANOTHER_ENV_VAR');
         *});
         *```
         *
         *### 🔁 Variante 2: Komplett aufräumen
         *
         *```ts
         *afterEach(() => {
         *  vi.unstubAllEnvs(); // entfernt alle gestubbten ENV-Overrides
         *});
         *```
         */
        unstubEnvs: true,

        /*
         *> Entfernt gestubbte globale Objekte, z.B. `globalThis.fetch = vi.fn()`.
         *
         *🧠 Wenn nicht global gesetzt – selbst aufräumen:
         *
         *```ts
         *afterEach(() => {
         *  vi.unstubAllGlobals(); // Global-Stubs wie fetch, window.alert etc.
         *});
         *```
         *
         *Oder gezielt:
         *
         *```ts
         *afterEach(() => {
         *  vi.unstubGlobal('fetch');
         *});
         *```
         */
        unstubGlobals: true,

        /**
         * Indicates whether to watch files for changes.
         *
         */
        watch: false
    }
}) satisfies ViteUserConfig

/**
 * Represents the configuration for the Vitest test runner.
 */
export default cfg
