import semver from 'semver';

import {
  OFFICIAL_NPM_REGISTRY_URL,
  createReferenceGovernanceToolchainPolicy,
  type GovernanceNodePolicy,
  type GovernancePnpmPolicy,
  type GovernanceToolchainPolicy,
} from '../domain/pnpm-governance';

const NODE_RELEASE_INDEX_URL = 'https://nodejs.org/dist/index.json';
const PNPM_PACKAGE_METADATA_URL = new URL('pnpm', OFFICIAL_NPM_REGISTRY_URL).toString();
const GOVERNANCE_VERSION_FETCH_TIMEOUT_MS = 5000;

type JsonRecord = Record<string, unknown>;

interface PolicyResolution<TPolicy> {
  policy: TPolicy;
  warnings: string[];
}

interface ParsedNodeReleasePolicy {
  latestVersion: string;
  latestMajor: number;
  minimumLtsVersion: string;
  minimumLtsMajor: number;
  ltsCodename: string | null;
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export async function resolveGovernanceToolchainPolicy(): Promise<GovernanceToolchainPolicy> {
  const referencePolicy = createReferenceGovernanceToolchainPolicy();
  const resolvedAt = new Date().toISOString();

  const [pnpmResolution, nodeResolution] = await Promise.all([
    resolvePnpmPolicy(referencePolicy.pnpm, resolvedAt),
    resolveNodePolicy(referencePolicy.node, resolvedAt),
  ]);

  return {
    pnpm: pnpmResolution.policy,
    node: nodeResolution.policy,
    warnings: [...pnpmResolution.warnings, ...nodeResolution.warnings],
  };
}

async function resolvePnpmPolicy(
  referencePolicy: GovernancePnpmPolicy,
  resolvedAt: string,
): Promise<PolicyResolution<GovernancePnpmPolicy>> {
  try {
    const response = await fetchJson(PNPM_PACKAGE_METADATA_URL);
    const latestVersion = parsePnpmLatestVersion(response);
    if (!latestVersion) {
      throw new TypeError('The npm registry response did not expose a valid dist-tags.latest semver.');
    }

    return {
      policy: {
        requiredVersion: latestVersion,
        requiredMajor: semver.major(latestVersion),
        latestVersion,
        checkedAt: resolvedAt,
        source: PNPM_PACKAGE_METADATA_URL,
        liveResolved: true,
      },
      warnings: [],
    };
  } catch (error) {
    return {
      policy: referencePolicy,
      warnings: [
        `Could not resolve the official pnpm latest version from ${PNPM_PACKAGE_METADATA_URL}. Falling back to the reference PNPM contract ${referencePolicy.requiredVersion} for this run. Reason: ${toErrorMessage(error)}`,
      ],
    };
  }
}

async function resolveNodePolicy(
  referencePolicy: GovernanceNodePolicy,
  resolvedAt: string,
): Promise<PolicyResolution<GovernanceNodePolicy>> {
  try {
    const response = await fetchJson(NODE_RELEASE_INDEX_URL);
    const parsed = parseNodeReleasePolicy(response);
    if (!parsed) {
      throw new TypeError('The Node.js release index did not contain a usable latest and LTS release contract.');
    }

    return {
      policy: {
        minimumLtsVersion: parsed.minimumLtsVersion,
        minimumLtsMajor: parsed.minimumLtsMajor,
        latestVersion: parsed.latestVersion,
        latestMajor: parsed.latestMajor,
        checkedAt: resolvedAt,
        source: NODE_RELEASE_INDEX_URL,
        ltsCodename: parsed.ltsCodename,
        liveResolved: true,
      },
      warnings: [],
    };
  } catch (error) {
    return {
      policy: referencePolicy,
      warnings: [
        `Could not resolve the official Node.js release index from ${NODE_RELEASE_INDEX_URL}. Falling back to the reference Node.js LTS floor ${referencePolicy.minimumLtsVersion}; live latest-upgrade guidance is disabled for this run. Reason: ${toErrorMessage(error)}`,
      ],
    };
  }
}

async function fetchJson(url: string): Promise<unknown> {
  if (typeof globalThis.fetch !== 'function') {
    throw new Error('The current Node.js runtime does not provide fetch().');
  }

  const abortController = new AbortController();
  const timeoutHandle = setTimeout(() => {
    abortController.abort();
  }, GOVERNANCE_VERSION_FETCH_TIMEOUT_MS);

  try {
    const response = await globalThis.fetch(url, {
      headers: {
        accept: 'application/json',
      },
      signal: abortController.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } finally {
    clearTimeout(timeoutHandle);
  }
}

function parsePnpmLatestVersion(value: unknown): string | null {
  if (!isJsonRecord(value)) {
    return null;
  }

  const distTags = value['dist-tags'];
  if (!isJsonRecord(distTags)) {
    return null;
  }

  const latest = distTags['latest'];
  if (typeof latest !== 'string') {
    return null;
  }

  return semver.valid(latest);
}

function parseNodeReleasePolicy(value: unknown): ParsedNodeReleasePolicy | null {
  if (!Array.isArray(value)) {
    return null;
  }

  const releases = value
    .map(parseNodeReleaseEntry)
    .filter((entry): entry is { version: string; ltsCodename: string | null } => entry !== null)
    .toSorted((left, right) => semver.rcompare(left.version, right.version));

  const latestRelease = releases[0];
  const latestLtsRelease = releases.find((release) => release.ltsCodename !== null);
  if (!latestRelease || !latestLtsRelease) {
    return null;
  }

  return {
    latestVersion: latestRelease.version,
    latestMajor: semver.major(latestRelease.version),
    minimumLtsVersion: latestLtsRelease.version,
    minimumLtsMajor: semver.major(latestLtsRelease.version),
    ltsCodename: latestLtsRelease.ltsCodename,
  };
}

function parseNodeReleaseEntry(value: unknown): { version: string; ltsCodename: string | null } | null {
  if (!isJsonRecord(value)) {
    return null;
  }

  const rawVersion = value['version'];
  if (typeof rawVersion !== 'string') {
    return null;
  }

  const normalizedVersion = rawVersion.startsWith('v') ? rawVersion.slice(1) : rawVersion;
  const version = semver.valid(normalizedVersion);
  if (!version) {
    return null;
  }

  const rawLts = value['lts'];
  return {
    version,
    ltsCodename: typeof rawLts === 'string' && rawLts.length > 0 ? rawLts : rawLts === true ? 'lts' : null,
  };
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
