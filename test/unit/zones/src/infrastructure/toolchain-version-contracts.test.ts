import { afterEach, describe, expect, it, vi } from 'vitest';

import { createReferenceGovernanceToolchainPolicy } from '../../../../../src/domain/pnpm-governance';
import { resolveGovernanceToolchainPolicy } from '../../../../../src/infrastructure/toolchain-version-contracts';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('resolveGovernanceToolchainPolicy', () => {
  it('resolves the official pnpm latest version and Node latest/LTS contracts', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-05-27T09:34:35.333Z'));

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === 'https://registry.npmjs.org/pnpm') {
        return new Response(JSON.stringify({
          'dist-tags': {
            latest: '12.1.0',
          },
          time: {
            created: '2025-01-01T00:00:00.000Z',
            modified: '2026-05-20T08:00:00.000Z',
            '11.9.1': '2026-05-10T08:00:00.000Z',
            '12.1.0': '2026-05-12T08:00:00.000Z',
          },
        }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        });
      }

      if (url === 'https://nodejs.org/dist/index.json') {
        return new Response(JSON.stringify([
          { version: 'v27.1.0', lts: false },
          { version: 'v26.2.0', lts: 'Krypton' },
          { version: 'v25.9.0', lts: false },
        ]), {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        });
      }

      return new Response('not found', { status: 404 });
    });

    vi.stubGlobal('fetch', fetchMock);

    const policy = await resolveGovernanceToolchainPolicy();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(policy.warnings).toEqual([]);
    expect(policy.pnpm.requiredVersion).toBe('12.1.0');
    expect(policy.pnpm.requiredMajor).toBe(12);
    expect(policy.pnpm.latestVersion).toBe('12.1.0');
    expect(policy.pnpm.minimumReleaseAgeMinutes).toBe(10080);
    expect(policy.pnpm.latestPublishedAt).toBe('2026-05-12T08:00:00.000Z');
    expect(policy.pnpm.requiredPublishedAt).toBe('2026-05-12T08:00:00.000Z');
    expect(policy.pnpm.releaseAgeCutoff).toBe('2026-05-20T09:34:35.333Z');
    expect(policy.pnpm.latestDeferredByMinimumReleaseAge).toBe(false);
    expect(policy.pnpm.liveResolved).toBe(true);
    expect(policy.node.minimumLtsVersion).toBe('26.2.0');
    expect(policy.node.minimumLtsMajor).toBe(26);
    expect(policy.node.latestVersion).toBe('27.1.0');
    expect(policy.node.latestMajor).toBe(27);
    expect(policy.node.ltsCodename).toBe('Krypton');
    expect(policy.node.liveResolved).toBe(true);
  });

  it('keeps the latest pnpm release out of the required contract until the minimum release age window has passed', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-05-27T09:34:35.333Z'));

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === 'https://registry.npmjs.org/pnpm') {
        return new Response(JSON.stringify({
          'dist-tags': {
            latest: '11.5.2',
          },
          time: {
            created: '2025-01-01T00:00:00.000Z',
            modified: '2026-05-24T08:43:45.834Z',
            '11.5.0': '2026-05-19T08:43:45.834Z',
            '11.5.2': '2026-05-24T08:43:45.834Z',
          },
        }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        });
      }

      if (url === 'https://nodejs.org/dist/index.json') {
        return new Response(JSON.stringify([
          { version: 'v27.1.0', lts: false },
          { version: 'v26.2.0', lts: 'Krypton' },
        ]), {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        });
      }

      return new Response('not found', { status: 404 });
    }));

    const policy = await resolveGovernanceToolchainPolicy();

    expect(policy.pnpm.latestVersion).toBe('11.5.2');
    expect(policy.pnpm.requiredVersion).toBe('11.5.0');
    expect(policy.pnpm.requiredMajor).toBe(11);
    expect(policy.pnpm.latestPublishedAt).toBe('2026-05-24T08:43:45.834Z');
    expect(policy.pnpm.requiredPublishedAt).toBe('2026-05-19T08:43:45.834Z');
    expect(policy.pnpm.releaseAgeCutoff).toBe('2026-05-20T09:34:35.333Z');
    expect(policy.pnpm.latestDeferredByMinimumReleaseAge).toBe(true);
    expect(policy.warnings).toEqual([]);
  });

  it('falls back to the checked-in reference contracts when the official sources are unavailable', async () => {
    const referencePolicy = createReferenceGovernanceToolchainPolicy();

    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('network down');
    }));

    const policy = await resolveGovernanceToolchainPolicy();

    expect(policy.pnpm.requiredVersion).toBe(referencePolicy.pnpm.requiredVersion);
    expect(policy.pnpm.liveResolved).toBe(false);
    expect(policy.node.minimumLtsVersion).toBe(referencePolicy.node.minimumLtsVersion);
    expect(policy.node.latestVersion).toBeNull();
    expect(policy.node.liveResolved).toBe(false);
    expect(policy.warnings).toHaveLength(2);
    expect(policy.warnings[0]).toContain('pnpm');
    expect(policy.warnings[1]).toContain('Node.js');
  });
});
