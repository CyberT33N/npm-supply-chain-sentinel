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
 * 📌 test/unit/test-setup.ts.
 *
 * Setup-Datei für Unit-Tests gegen die final getrennten Registrierungs- und Infrastrukturgrenzen.
 * Diese Datei wird in der setupFiles-Konfiguration der vitest.unit.config.ts geladen.
 *
 * WICHTIG: Hier können vi.* Funktionen verwendet werden, da setupFiles
 * im Kontext der Testsuite ausgeführt wird.
 */

// ═══╡ 🧩 IMPORTS ╞═══
import { vi } from 'vitest'

/**
 * 🧪 Unit-Test-Setup-Logik
 * Diese Funktion bereitet die Umgebung für Unit-Tests vor.
 */
const setupUnitTestEnvironment = (): void => {
    console.info('🧪 Initialisiere Unit-Test-Umgebung für getrennte Registrierungs- und Infrastrukturgrenzen...')

    // ════════════════════════════╡ 🧪 ENVIRONMENT ╞═════════════════════════════
    vi.stubGlobal('TEST_ENV_TYPE', 'unit')

    console.info('✅ Unit-Test-Umgebung für getrennte Registrierungs- und Infrastrukturgrenzen erfolgreich initialisiert')
}

// Automatische Ausführung beim Import
setupUnitTestEnvironment()
