import { createRequire } from 'node:module';

export interface ExtendedMatcherResult {
  pass: boolean;
  message: () => string;
}

export type ExtendedMatcher = (
  this: unknown,
  received: unknown,
  ...expected: readonly unknown[]
) => ExtendedMatcherResult | Promise<ExtendedMatcherResult>;

export type ExtendedMatcherMap = Record<string, ExtendedMatcher>;

const require = createRequire(import.meta.url);
const matchers: ExtendedMatcherMap = require('jest-extended');

export default matchers;
