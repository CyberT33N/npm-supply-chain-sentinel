export type FindingConfidence = 'low' | 'medium' | 'high';

export interface FindingRecord {
  type: string;
  message: string;
  path?: string;
  packageName?: string;
  version?: string;
  indicator?: string;
  rule?: string;
  campaignId?: string;
  confidence?: FindingConfidence;
  _key?: string;
  [key: string]: unknown;
}

export interface FindingInput {
  type: string;
  message: string;
  path?: string;
  packageName?: string;
  version?: string;
  indicator?: string;
  rule?: string;
  campaignId?: string;
  confidence?: FindingConfidence;
  [key: string]: unknown;
}

export interface FindingsContainer {
  exactHits: FindingRecord[];
  heuristicHits: FindingRecord[];
  artifactHits: FindingRecord[];
  limitations: FindingRecord[];
  errors: FindingRecord[];
}

export function createFindingsContainer(): FindingsContainer {
  return {
    exactHits: [],
    heuristicHits: [],
    artifactHits: [],
    limitations: [],
    errors: [],
  };
}

export function addFinding(targetArray: FindingRecord[], finding: FindingInput): void {
  const key = JSON.stringify([
    finding.type,
    finding.path ?? '',
    finding.packageName ?? '',
    finding.version ?? '',
    finding.indicator ?? '',
    finding.rule ?? '',
  ]);
  if (!targetArray.some((existing) => existing._key === key)) {
    targetArray.push({ ...finding, _key: key });
  }
}

export function mergeFindings(target: FindingsContainer, source: FindingsContainer): void {
  for (const key of ['exactHits', 'heuristicHits', 'artifactHits', 'limitations', 'errors'] as const) {
    for (const finding of source[key] ?? []) {
      addFinding(target[key], finding);
    }
  }
}

export function stripInternalKeys(items: readonly FindingRecord[]): FindingInput[] {
  return items.map(({ _key, ...rest }) => rest);
}

export function summarizeFindings(findings: FindingsContainer): {
  exactCount: number;
  heuristicCount: number;
  artifactCount: number;
  limitationCount: number;
  errorCount: number;
} {
  const exactCount = findings.exactHits.length;
  const heuristicCount = findings.heuristicHits.length;
  const artifactCount = findings.artifactHits.length;
  const limitationCount = findings.limitations.length;
  const errorCount = findings.errors.length;
  return { exactCount, heuristicCount, artifactCount, limitationCount, errorCount };
}
