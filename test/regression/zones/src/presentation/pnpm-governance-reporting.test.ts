import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { auditPnpmGovernance } from '../../../../../src/application/pnpm-governance';
import { renderPnpmGovernanceAudit } from '../../../../../src/presentation/pnpm-governance-reporting';
import {
  BASE_WORKSPACE_TEXT,
  PNPM_RUNTIME,
  buildMonorepoWorkspaceText,
  captureConsoleOutput,
  createFixtureProject,
  createPackageJson,
  escapeRegExp,
} from '@test/shared/utils/pnpm-governance-fixtures';

describe('renderPnpmGovernanceAudit', () => {
  it('renders nested domains with an arrow back to the containing monorepo', async () => {
    const rootPath = await createFixtureProject({
      workspaceText: buildMonorepoWorkspaceText(BASE_WORKSPACE_TEXT, {
        workspacePatterns: ['domains/*'],
      }),
      workspaceMembers: [
        {
          relativePath: path.join('domains', 'billing-domain'),
          packageJson: createPackageJson({
            name: '@fixture/billing-domain',
          }),
          workspaceText: BASE_WORKSPACE_TEXT,
          lockfileText: 'lockfileVersion: "9.0"\n',
        },
      ],
    });

    const audit = auditPnpmGovernance([rootPath], {}, PNPM_RUNTIME);
    const rootProject = audit.projects.find((project) => project.rootPath === rootPath);
    const nestedDomain = audit.projects.find(
      (project) => project.rootPath === path.join(rootPath, 'domains', 'billing-domain'),
    );

    if (!rootProject || !nestedDomain) {
      throw new Error('Expected both the root monorepo and nested domain audit results.');
    }

    const output = captureConsoleOutput(() => {
      renderPnpmGovernanceAudit(audit);
    });

    expect(output).toMatch(
      new RegExp(
        escapeRegExp(
          `${rootProject.displayPath} -> ${nestedDomain.displayPath} [pnpm-single-project domain]`,
        ),
        'u',
      ),
    );
  });
});
