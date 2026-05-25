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

/**
 * 📌 pretest-base.ts.
 *
 * Basis-Setup-Datei für die gemeinsame Verifikationsbasis von Unit- und Regression-Tests.
 * Diese Datei wird als globalSetup in vitest.config.ts eingetragen und
 * stellt die gemeinsame Infrastruktur für die finale modulare Server-Topologie bereit.
 *
 * Hinweis: In dieser Datei können KEINE Vitest-spezifischen Funktionen wie
 * vi, expect, etc. Verwendet werden, da sie in einem separaten Kontext ausgeführt wird.
 */

// Import des zentralen Bootstrap
import {
    bootstrapTestEnvironment, cleanupTestEnvironment
} from './bootstrap'

/**
 * 🔄 Setup-Funktion für Vitest
 * Diese Funktion wird vor allen Tests ausgeführt.
 */
export const setup = (): void => {
    console.info('📋 [1. PRETEST-BASE] Starte gemeinsames Basis-Setup für die modulare Verifikationsstruktur...')

    // Zentralen Bootstrap ausführen
    bootstrapTestEnvironment()

    // Zusätzliches spezifisches Setup für die Basis-Konfiguration
    console.info('✅ [1. PRETEST-BASE] Gemeinsames Basis-Setup für Unit- und Regression-Verifikation abgeschlossen')
}

/**
 * 🧹 Teardown-Funktion für Vitest
 * Diese Funktion wird nach allen Tests ausgeführt.
 */
export const teardown = (): void => {
    console.info('🧹 [TEARDOWN - PRETEST-BASE] Starte gemeinsames Basis-Teardown der modularen Verifikationsstruktur...')

    // Zentralen Cleanup ausführen
    cleanupTestEnvironment()

    // Zusätzliches spezifisches Cleanup für die Basis-Konfiguration
    console.info('✅ [TEARDOWN - PRETEST-BASE] Gemeinsames Basis-Teardown der modularen Verifikationsstruktur abgeschlossen')
}
