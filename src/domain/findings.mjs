export function createFindingsContainer() {
  return {
    exactHits: [],
    heuristicHits: [],
    artifactHits: [],
    errors: [],
  };
}

export function addFinding(targetArray, finding) {
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

export function mergeFindings(target, source) {
  for (const key of ['exactHits', 'heuristicHits', 'artifactHits', 'errors']) {
    for (const finding of source[key] ?? []) {
      addFinding(target[key], finding);
    }
  }
}

export function stripInternalKeys(items) {
  return items.map(({ _key, ...rest }) => rest);
}

export function summarizeFindings(findings) {
  const exactCount = findings.exactHits.length;
  const heuristicCount = findings.heuristicHits.length;
  const artifactCount = findings.artifactHits.length;
  const errorCount = findings.errors.length;
  return { exactCount, heuristicCount, artifactCount, errorCount };
}
