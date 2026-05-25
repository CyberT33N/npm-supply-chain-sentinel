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
import is from '@sindresorhus/is'

// ═══╡ 🏷️TYPES ╞═══
import type { Matcher } from '@test/shared/utils/asymmetric-matchers/contracts'
import type { AsymmetricLike } from './types'

/*
 *╭───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───
 *📦 EXPORTS ► Exports for asymmetric matchers
 *╰───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───
 */

/**
 * Creates a matcher function that can be used to match against a value.
 *
 * @param name - The name of the matcher.
 * @param type - The type of the matcher.
 * @param matchFn - The function that will be used to match against the value.
 * @returns A matcher function that can be used to match against a value.
 */
export const makeMatcher = (
    name: string, type: string, matchFn: (value: unknown) => boolean
): Matcher => ({
    asymmetricMatch: matchFn,

    /**
     * Gets the expected type of the matcher.
     *
     * @returns The expected type of the matcher.
     */
    getExpectedType: () => type,

    /**
     * Gets the string representation of the matcher.
     *
     * @returns The string representation of the matcher.
     */
    toString: () => name
})

/**
 * Checks if a value is a plain object.
 *
 * @param value - The value to check.
 * @returns True if the value is a plain object, false otherwise.
 */
export const isPlainObject = (value: unknown): value is Record<string, unknown> => is.object(value)
    && !is.array(value) && !is.function(value)

/**
 * Checks if a value has an asymmetric match function.
 *
 * @param value - The value to check.
 * @returns True if the value has an asymmetric match function, false otherwise.
 */
export const hasAsymmetricMatch = (value: unknown): value is AsymmetricLike => {
    if (is.nullOrUndefined(value)) {
        return false
    }

    const desc = Object.getOwnPropertyDescriptor(new Object(value), 'asymmetricMatch')

    return Boolean(desc) && typeof desc?.value === 'function'
}
