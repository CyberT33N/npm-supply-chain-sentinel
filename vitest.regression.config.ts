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
import {
    defineConfig, mergeConfig

} from 'vitest/config'

import baseConfig from './vitest.config'

// ═══╡ 🏷️TYPES ╞═══
import type { ViteUserConfig } from 'vitest/config'

// 📋 Define the regression verification configuration for the final modularized topology
const cfg = defineConfig({
    test: {

        /**
         * Specifies the coverage configuration.
         *
         */
        coverage: {

            /**
             * Specifies the files or directories to exclude from coverage.
             *
             */
            exclude: [],

            /**
             * Specifies the coverage provider to use.
             *
             */
            provider: 'v8'
        },

        /**
         * Specifies the test files to include.
         *
         */
        include: ['test/regression/**/*.test.ts'],

         /**
          * Name of the verification project for workspace selection.
          */
         name: 'regression',

         /**
          * Setup file for regression verification. It keeps category-specific globals
          * separated from the shared base and shared Vitest setup.
          */
         setupFiles: ['test/regression/test-setup.ts'],

        /**
         * Type checking configuration for unit tests.
         *
         */
        typecheck: {
            /**
             * Specifies the files to include for type checking.
             *
             */
            include: ['test/regression/**/*.test-d.ts']
        }
    }
}) satisfies ViteUserConfig

/**
 * 🛠️ Merges the shared modular verification baseline with the regression-specific surface.
 */
const mergedCfg = mergeConfig(baseConfig, defineConfig(cfg))

export default mergedCfg
