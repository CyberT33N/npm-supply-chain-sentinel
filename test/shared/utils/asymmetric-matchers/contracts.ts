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

/*
 *╭───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───
 *📦 EXPORTS ► Exports for asymmetric matchers
 *╰───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───
 */

/**
 * Matcher interface.
 */
export interface Matcher {
    /**
     * Matches against a value.
     *
     * @param received - The value to match against.
     * @returns True if the value matches, false otherwise.
     */
    asymmetricMatch: (received: unknown) => boolean

    /**
     * Gets the expected type of the matcher.
     *
     * @returns The expected type of the matcher.
     */
    getExpectedType: () => string

    /**
     * Gets the string representation of the matcher.
     *
     * @returns The string representation of the matcher.
     */
    toString: () => string
}

/**
 * Matcher name type.
 */
export type MatcherName = | 'array' | 'boolean' | 'date' | 'defined' | 'function' | 'number' | 'object' | 'string'
