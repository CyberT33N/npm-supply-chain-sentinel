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

import {
    hasAsymmetricMatch,
    isPlainObject,
    makeMatcher
} from './internal/matcher-utils'

// ═══╡ 🏷️TYPES ╞═══
import type {
    Matcher, MatcherName
} from './contracts'

/*
 *╭───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───
 *📦 EXPORTS ► Exports for asymmetric matchers
 *╰───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───═══◎◎◎═══───
 */
export type {
    Matcher, MatcherName
} from './contracts'

/**
 * Matches against a Date object.
 *
 * @param value - The value to match against.
 * @returns True if the value is a Date object and not NaN, false otherwise.
 */
export const anyDate = makeMatcher('anyDate', 'Date', value => is.validDate(value))

/**
 * Matches against a String object.
 *
 * @param value - The value to match against.
 * @returns True if the value is a String object, false otherwise.
 */
export const anyString = makeMatcher('anyString', 'String', value => is.string(value))

/**
 * Matches against a Number object.
 *
 * @param value - The value to match against.
 * @returns True if the value is a Number object and not NaN, false otherwise.
 */
export const anyNumber = makeMatcher('anyNumber', 'Number', value => is.number(value))

/**
 * Matches against a Boolean object.
 *
 * @param value - The value to match against.
 * @returns True if the value is a Boolean object, false otherwise.
 */
export const anyBoolean = makeMatcher('anyBoolean', 'Boolean', value => is.boolean(value))

/**
 * Matches against an Object object.
 *
 * @param value - The value to match against.
 * @returns True if the value is an Object object, false otherwise.
 */
export const anyObject = makeMatcher('anyObject', 'Object', value => is.object(value)
    && !is.array(value) && !is.function(value))

/**
 * Matches against an Array object.
 *
 * @param value - The value to match against.
 * @returns True if the value is an Array object, false otherwise.
 */
export const anyArray = makeMatcher('anyArray', 'Array', value => is.array(value))

/**
 * Matches against a Defined object.
 *
 * @param value - The value to match against.
 * @returns True if the value is not null or undefined, false otherwise.
 */
export const anything = makeMatcher('anything', 'Defined', value => !is.nullOrUndefined(value))

/**
 * Matches against a Function object.
 *
 * @param value - The value to match against.
 * @returns True if the value is a Function object, false otherwise.
 */
export const anyFunction = makeMatcher('anyFunction', 'Function', value => is.function(value))

/**
 * Matcher name type.
 */
const matcherByType = new Map<MatcherName, Matcher>([
    [
        'array',
        anyArray
    ],
    [
        'boolean',
        anyBoolean
    ],
    [
        'date',
        anyDate
    ],
    [
        'defined',
        anything
    ],
    [
        'function',
        anyFunction
    ],
    [
        'number',
        anyNumber
    ],
    [
        'object',
        anyObject
    ],
    [
        'string',
        anyString
    ]
])

/**
 * Matches against a MatcherName object.
 *
 * @param type - The type of the matcher.
 * @returns A matcher function that can be used to match against a value.
 */
export const any = (type: MatcherName): Matcher => matcherByType.get(type)
    ?? makeMatcher('never', 'Never', () => false)

/**
 * Matches against an Object object.
 *
 * @param subset - The subset of the object to match against.
 * @returns A matcher function that can be used to match against a value.
 */
export const objectContaining = <T extends Record<string, unknown>>(
    subset: Readonly<Partial<T>>
): Matcher => makeMatcher('ObjectContaining', 'Object', (received: unknown) => {
    if (!isPlainObject(received)) {
        return false
    }

    const entries = Object.entries(subset)

    const target = received

    /**
     * Checks if a single [key, expectedValue] pair matches against the target object.
     *
     * @param key - The property name to check on the target object.
     * @param expectedValue - The expected value or matcher to verify against the actual value.
     * @returns True when the actual value satisfies the expected value semantics.
     */
    const entryMatches = (
        key: string,
        expectedValue: unknown
    ): boolean => {
        const descriptor = Object.getOwnPropertyDescriptor(target, key)

        if (descriptor) {
            const actualValue: unknown = descriptor.value

            if (hasAsymmetricMatch(expectedValue)) {
                return expectedValue.asymmetricMatch(actualValue)
            }

            if (isPlainObject(expectedValue)) {
                const nestedMatcher = objectContaining(expectedValue)

                return nestedMatcher.asymmetricMatch(actualValue)
            }

            return actualValue === expectedValue
        }

        return false
    }

    for (const [
        key,
        expectedValue
    ] of entries) {
        if (!entryMatches(key, expectedValue)) {
            return false
        }
    }

    return true
})
