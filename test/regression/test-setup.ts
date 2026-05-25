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
 * 📌 test/regression/test-setup.ts.
 *
 * Setup-Datei für Regression-Tests gegen die finale modulare Server-Komposition.
 * Diese Datei wird in der setupFiles-Konfiguration der vitest.regression.config.ts geladen.
 *
 * WICHTIG: Hier können vi.* Funktionen verwendet werden, da setupFiles
 * im Kontext der Testsuite ausgeführt wird.
 */

// ==== Imports ====
import { vi } from 'vitest'

/**
 * 🧪 Regression-Test-Setup-Logik
 * Diese Funktion bereitet die Umgebung für Regression-Tests vor.
 */
const setupRegressionTestEnvironment = (): void => {
    console.info('🧪 Initialisiere Regression-Test-Umgebung für die finale modulare Server-Komposition...')

    // Hier können Vitest-spezifische Mocks und Setups erfolgen
    vi.stubGlobal('REGRESSION_TEST_MODE', true)

    console.info('✅ Regression-Test-Umgebung für die finale modulare Server-Komposition erfolgreich initialisiert')
}

// Automatische Ausführung beim Import
setupRegressionTestEnvironment()
