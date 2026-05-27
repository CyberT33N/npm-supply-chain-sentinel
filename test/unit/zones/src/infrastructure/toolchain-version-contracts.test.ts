import { afterEach, describe, expect, it, vi } from 'vitest';

import { createReferenceGovernanceToolchainPolicy } from '../../../../../src/domain/pnpm-governance';
import { resolveGovernanceToolchainPolicy } from '../../../../../src/infrastructure/toolchain-version-contracts';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('resolveGovernanceToolchainPolicy', () => {
  it('resolves the official pnpm latest version and Node latest/LTS contracts', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === 'https://registry.npmjs.org/pnpm') {
        return new Response(JSON.stringify({
          'dist-tags': {
            latest: '11.9.1',
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
    expect(policy.pnpm.requiredVersion).toBe('11.9.1');
    expect(policy.pnpm.requiredMajor).toBe(11);
    expect(policy.pnpm.liveResolved).toBe(true);
    expect(policy.node.minimumLtsVersion).toBe('26.2.0');
    expect(policy.node.minimumLtsMajor).toBe(26);
    expect(policy.node.latestVersion).toBe('27.1.0');
    expect(policy.node.latestMajor).toBe(27);
    expect(policy.node.ltsCodename).toBe('Krypton');
    expect(policy.node.liveResolved).toBe(true);
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
