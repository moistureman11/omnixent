import crypto from 'crypto';
import {
  CanonicalEvidence,
  ChainOfCustodyEvent,
  CorrelationEdge,
  CorrelationResult,
  DetectionResult,
  EvidenceEntity,
  EvidenceSourceType,
  ExplainableReport,
  ForensicAuditRequest,
  ForensicAuditResult,
  IntegrityResult,
  LegalAssessment,
  RawFinding,
  SignedManifest,
  WorkflowBundle,
} from './types';

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
const DEFAULT_TIME_WINDOW_MINUTES = 10;
const MAX_CONTENT_PREVIEW_LENGTH = 280;
const MALICIOUS_CONFIDENCE_THRESHOLD = 55;
const UNSAFE_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_REGEX = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/g;
const HASH_REGEX = /\b(?:sha(?:1|224|256|384|512):)?[a-f0-9]{32,128}\b/g;

const SUSPICIOUS_ARTIFACT_PATTERNS: Array<{ label: string; matcher: RegExp }> = [
  { label: 'traffic-capture', matcher: /\.har\b/i },
  { label: 'db-write-ahead-log', matcher: /\.db-wal\b/i },
  { label: 'notebook-staging', matcher: /\.ipynb\b/i },
  { label: 'macos-plist', matcher: /\.plist\b/i },
  { label: 'jvm-bytecode', matcher: /\.class\b/i },
  { label: 'python-cache', matcher: /__pycache__|\.pyc\b/i },
  { label: 'background-listener', matcher: /\b[a-z0-9_-]*(listener|daemon)[a-z0-9_-]*\b/i },
  { label: 'pid-persistence', matcher: /\.pid\b|port_guard_[a-z0-9_-]+/i },
];

export class InvalidForensicDateError extends Error {
  constructor(value: string) {
    super(`Invalid ISO-8601 date: ${value}`);
    this.name = 'InvalidForensicDateError';
  }
}

export class MissingManifestSecretError extends Error {
  constructor() {
    super('FORENSIC_MANIFEST_SECRET must be set');
    this.name = 'MissingManifestSecretError';
  }
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    const asObject = value as Record<string, unknown>;
    const keys = Object.keys(asObject).sort();
    const fields = keys.map((key) => `"${key}":${stableStringify(asObject[key])}`);
    return `{${fields.join(',')}}`;
  }

  return JSON.stringify(value);
}

function createHash(payload: string): string {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function normalizeDate(value: string): string {
  if (!ISO_DATE_REGEX.test(value)) {
    throw new InvalidForensicDateError(value);
  }

  return value;
}

function sanitizeMetadata(
  metadata?: Record<string, string | number | boolean | null>,
): Record<string, string | number | boolean | null> {
  if (!metadata) {
    return {};
  }

  const sanitized: Record<string, string | number | boolean | null> = {};
  Object.keys(metadata).forEach((key) => {
    if (UNSAFE_OBJECT_KEYS.has(key)) {
      return;
    }

    const value = metadata[key];
    if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
      sanitized[key] = typeof value === 'string' ? value.trim() : value;
    }
  });

  return sanitized;
}

function normalizeEntities(entities?: EvidenceEntity[]): EvidenceEntity[] {
  if (!entities) return [];

  return entities
    .filter((entity) => Boolean(entity.type) && Boolean(entity.value))
    .map((entity) => ({
      type: String(entity.type).toLowerCase(),
      value: String(entity.value).trim(),
    }));
}

function normalizeIocs(iocs?: string[]): string[] {
  if (!iocs) return [];

  return iocs
    .map((ioc) => ioc.trim().toLowerCase())
    .filter((ioc) => ioc.length > 0)
    .filter((ioc, index, arr) => arr.indexOf(ioc) === index);
}

function extractIocsFromText(text: string): string[] {
  const lowered = text.toLowerCase();
  const matches = [
    ...(lowered.match(IPV4_REGEX) || []),
    ...(lowered.match(DOMAIN_REGEX) || []),
    ...(lowered.match(HASH_REGEX) || []),
  ];

  return normalizeIocs(matches);
}

function parseBySourceType(sourceType: EvidenceSourceType, finding: RawFinding): RawFinding {
  const metadata = sanitizeMetadata(finding.metadata);

  switch (sourceType) {
    case 'network':
      return {
        ...finding,
        metadata: {
          parser: 'network-v1',
          protocol: metadata.protocol || 'unknown',
          ...metadata,
        },
      };
    case 'ble':
      return {
        ...finding,
        metadata: {
          parser: 'ble-v1',
          signalStrength: metadata.signalStrength || 'unknown',
          ...metadata,
        },
      };
    case 'radio':
      return {
        ...finding,
        metadata: {
          parser: 'radio-v1',
          band: metadata.band || 'unknown',
          ...metadata,
        },
      };
    case 'app':
      return {
        ...finding,
        metadata: {
          parser: 'app-v1',
          appId: metadata.appId || 'unknown',
          ...metadata,
        },
      };
    case 'code':
      return {
        ...finding,
        metadata: {
          parser: 'code-v1',
          repository: metadata.repository || 'unknown',
          ...metadata,
        },
      };
    case 'file':
      return {
        ...finding,
        metadata: {
          parser: 'file-v1',
          fileType: metadata.fileType || 'unknown',
          ...metadata,
        },
      };
    default:
      return finding;
  }
}

function toCanonicalEvidence(finding: RawFinding, index: number, ingestedAt: string): CanonicalEvidence {
  const parsedFinding = parseBySourceType(finding.sourceType, finding);
  const observedAt = normalizeDate(parsedFinding.observedAt);
  const metadata = sanitizeMetadata(parsedFinding.metadata);
  const contentPreview = String(parsedFinding.content || '').slice(0, MAX_CONTENT_PREVIEW_LENGTH);
  const derivedText = `${contentPreview} ${parsedFinding.location || ''} ${Object.values(metadata)
    .map((value) => String(value))
    .join(' ')}`;
  const normalizedIocs = normalizeIocs([...normalizeIocs(parsedFinding.iocs), ...extractIocsFromText(derivedText)]);
  const normalizedEntities = normalizeEntities(parsedFinding.entities);
  const fingerprint = stableStringify({
    sourceType: parsedFinding.sourceType,
    observedAt,
    location: parsedFinding.location || '',
    contentPreview,
    metadata,
    iocs: normalizedIocs,
    entities: normalizedEntities,
  });

  const evidenceId = parsedFinding.id || `ev-${index + 1}`;
  return {
    evidenceId,
    provenanceId: `prov-${createHash(`${evidenceId}:${fingerprint}`).slice(0, 16)}`,
    sourceType: parsedFinding.sourceType,
    observedAt,
    ingestedAt,
    location: parsedFinding.location || 'unknown',
    contentPreview,
    metadata,
    iocs: normalizedIocs,
    entities: normalizedEntities,
    integrity: {
      hashAlgorithm: 'sha256',
      hash: createHash(fingerprint),
    },
  };
}

export function assessLegalRequirements(payload: ForensicAuditRequest): LegalAssessment {
  const requirements = [
    `Jurisdiction: ${payload.jurisdiction}`,
    `Admissibility standards: ${payload.admissibilityStandards.join(', ')}`,
    `Retention policy days: ${payload.retentionPolicyDays}`,
    `Privacy scope: ${payload.privacyScope.join(', ')}`,
    'Chain-of-custody must be complete and immutable',
  ];

  const gaps: string[] = [];

  if (!payload.jurisdiction.trim()) gaps.push('Jurisdiction is required.');
  if (!payload.admissibilityStandards.length) gaps.push('At least one admissibility standard is required.');
  if (payload.retentionPolicyDays < 1) gaps.push('Retention policy must be at least 1 day.');
  if (!payload.privacyScope.length) gaps.push('Privacy scope entries are required.');
  if (!payload.findings.length) gaps.push('At least one finding is required to support legal evidence.');

  return {
    requirements,
    gaps,
    isCompliant: gaps.length === 0,
  };
}

export function ingestFindings(payload: ForensicAuditRequest, ingestedAt: string): CanonicalEvidence[] {
  return payload.findings.map((finding, index) => toCanonicalEvidence(finding, index, ingestedAt));
}

function createIndexValues(values: Array<{ key: string; evidenceId: string }>): Record<string, string[]> {
  return values.reduce<Record<string, string[]>>((acc, item) => {
    if (!acc[item.key]) acc[item.key] = [];
    if (!acc[item.key].includes(item.evidenceId)) {
      acc[item.key].push(item.evidenceId);
    }
    return acc;
  }, {});
}

function minutesBetween(left: string, right: string): number {
  const l = new Date(left).getTime();
  const r = new Date(right).getTime();
  return Math.abs(l - r) / (1000 * 60);
}

export function correlateEvidence(evidence: CanonicalEvidence[]): CorrelationResult {
  const entityPairs: Array<{ key: string; evidenceId: string }> = [];
  const iocPairs: Array<{ key: string; evidenceId: string }> = [];
  const edges: CorrelationEdge[] = [];

  evidence.forEach((item) => {
    item.entities.forEach((entity) => {
      entityPairs.push({
        key: `${entity.type}:${entity.value.toLowerCase()}`,
        evidenceId: item.evidenceId,
      });
    });

    item.iocs.forEach((ioc) => {
      iocPairs.push({ key: ioc.toLowerCase(), evidenceId: item.evidenceId });
    });
  });

  const entityIndex = createIndexValues(entityPairs);
  const iocIndex = createIndexValues(iocPairs);

  for (let i = 0; i < evidence.length; i++) {
    const left = evidence[i];

    for (let j = i + 1; j < evidence.length; j++) {
      const right = evidence[j];
      const reasons: string[] = [];
      let confidence = 0;

      if (minutesBetween(left.observedAt, right.observedAt) <= DEFAULT_TIME_WINDOW_MINUTES) {
        reasons.push('time-window');
        confidence += 0.35;
      }

      const sharedIocs = left.iocs.filter((ioc) => right.iocs.includes(ioc));
      if (sharedIocs.length > 0) {
        reasons.push(`ioc:${sharedIocs.join('|')}`);
        confidence += Math.min(0.45, 0.15 * sharedIocs.length);
      }

      const sharedEntities = left.entities.filter((entity) =>
        right.entities.some((candidate) => candidate.type === entity.type && candidate.value === entity.value),
      );

      if (sharedEntities.length > 0) {
        reasons.push(
          `entity:${sharedEntities
            .map((entity) => `${entity.type}:${entity.value}`)
            .join('|')}`,
        );
        confidence += Math.min(0.35, 0.1 * sharedEntities.length);
      }

      if (reasons.length > 0) {
        edges.push({
          leftEvidenceId: left.evidenceId,
          rightEvidenceId: right.evidenceId,
          reason: reasons.join(','),
          confidence: Number(Math.min(confidence, 0.99).toFixed(2)),
        });
      }
    }
  }

  const anomalyLinks = evidence
    .filter((item) => item.iocs.length >= 2 || item.entities.length >= 3)
    .map((item) => item.evidenceId);

  return {
    timeWindowMinutes: DEFAULT_TIME_WINDOW_MINUTES,
    edges,
    entityIndex,
    iocIndex,
    anomalyLinks,
  };
}

export function detectMaliciousActivity(
  evidence: CanonicalEvidence[],
  correlations: CorrelationResult,
): DetectionResult[] {
  const suspiciousKeywords = ['malware', 'beacon', 'exfiltration', 'payload', 'ransom', 'c2', 'phishing'];

  return evidence.map((item) => {
    const indicators: string[] = [];
    const evidenceText = `${item.contentPreview} ${item.location} ${Object.values(item.metadata)
      .map((value) => String(value))
      .join(' ')}`.toLowerCase();

    const keywordHits = suspiciousKeywords.filter((keyword) => evidenceText.includes(keyword));
    if (keywordHits.length > 0) {
      indicators.push(`keyword:${keywordHits.join('|')}`);
    }

    const artifactHits = SUSPICIOUS_ARTIFACT_PATTERNS.filter((pattern) => pattern.matcher.test(evidenceText)).map(
      (pattern) => pattern.label,
    );
    if (artifactHits.length > 0) {
      indicators.push(`artifact:${artifactHits.join('|')}`);
    }

    if (item.iocs.length > 0) {
      indicators.push(`ioc-count:${item.iocs.length}`);
    }

    const relatedEdges = correlations.edges.filter(
      (edge) => edge.leftEvidenceId === item.evidenceId || edge.rightEvidenceId === item.evidenceId,
    );

    if (relatedEdges.length > 0) {
      indicators.push(`correlations:${relatedEdges.length}`);
    }

    const ruleScore = Math.min(1, keywordHits.length * 0.2 + item.iocs.length * 0.15 + artifactHits.length * 0.15);
    const heuristicScore = Math.min(1, relatedEdges.length * 0.12 + item.entities.length * 0.08);
    const modelSeed = parseInt(item.integrity.hash.slice(0, 6), 16);
    // Deterministic placeholder score until a trained model is integrated.
    const modelScore = Number((((modelSeed % 100) / 100) * 0.6 + 0.2).toFixed(2));
    const confidence = Number(((ruleScore * 0.45 + heuristicScore * 0.35 + modelScore * 0.2) * 100).toFixed(2));

    return {
      evidenceId: item.evidenceId,
      indicators,
      ruleScore: Number((ruleScore * 100).toFixed(2)),
      heuristicScore: Number((heuristicScore * 100).toFixed(2)),
      modelScore: Number((modelScore * 100).toFixed(2)),
      confidence,
      malicious: confidence >= MALICIOUS_CONFIDENCE_THRESHOLD,
    };
  });
}

function getManifestSecret(): string {
  const secret = process.env.FORENSIC_MANIFEST_SECRET;

  if (!secret) {
    throw new MissingManifestSecretError();
  }

  return String(secret);
}

function buildManifest(caseId: string, evidence: CanonicalEvidence[], generatedAt: string): SignedManifest {
  const evidenceHashes = evidence.reduce<Record<string, string>>((acc, item) => {
    acc[item.evidenceId] = item.integrity.hash;
    return acc;
  }, {});

  const payload = stableStringify({ caseId, generatedAt, evidenceHashes });
  const signature = crypto.createHmac('sha256', getManifestSecret()).update(payload).digest('hex');

  return {
    algorithm: 'sha256-hmac',
    generatedAt,
    caseId,
    evidenceHashes,
    signature,
  };
}

export function createIntegrityPipeline(
  payload: ForensicAuditRequest,
  evidence: CanonicalEvidence[],
  generatedAt: string,
): IntegrityResult {
  const signedManifest = buildManifest(payload.caseId, evidence, generatedAt);
  const chainOfCustody: ChainOfCustodyEvent[] = [
    ...(payload.chainOfCustody || []),
    {
      actor: payload.analyst,
      action: 'INGESTED',
      timestamp: generatedAt,
      notes: `Ingested ${evidence.length} evidence records`,
    },
    {
      actor: payload.analyst,
      action: 'MANIFEST_SIGNED',
      timestamp: generatedAt,
      notes: signedManifest.signature,
    },
  ];

  return {
    signedManifest: Object.freeze(signedManifest),
    immutableEvidence: Object.freeze(evidence.map((item) => Object.freeze({ ...item }))),
    chainOfCustody: Object.freeze(chainOfCustody.map((event) => Object.freeze({ ...event }))),
  };
}

export function createExplainableReport(
  caseId: string,
  evidence: CanonicalEvidence[],
  detections: DetectionResult[],
  generatedAt: string,
): ExplainableReport {
  const findings = detections.map((detection) => {
    const evidenceItem = evidence.find((item) => item.evidenceId === detection.evidenceId);
    const sourceRef = evidenceItem ? `${evidenceItem.sourceType}:${evidenceItem.location}` : 'unknown';
    return {
      evidenceId: detection.evidenceId,
      malicious: detection.malicious,
      confidence: detection.confidence,
      rationale: detection.indicators.length ? detection.indicators : ['No direct indicators identified'],
      rawEvidenceRefs: [sourceRef],
      reproducibleQueries: [
        'SELECT * FROM canonical_evidence WHERE evidence_id = ?',
        'SELECT * FROM detections WHERE evidence_id = ?',
      ],
    };
  });

  const maliciousFindings = findings.filter((finding) => finding.malicious).length;
  const highConfidenceFindings = findings.filter((finding) => finding.confidence >= 80).length;

  return {
    generatedAt,
    caseId,
    summary: {
      totalEvidence: evidence.length,
      maliciousFindings,
      highConfidenceFindings,
    },
    findings,
  };
}

export function buildWorkflowBundle(
  payload: ForensicAuditRequest,
  evidence: CanonicalEvidence[],
  correlations: CorrelationResult,
  report: ExplainableReport,
  signedManifest: SignedManifest,
  generatedAt: string,
): WorkflowBundle {
  const sourceTypes: Record<EvidenceSourceType, string[]> = {
    network: [],
    ble: [],
    radio: [],
    app: [],
    code: [],
    file: [],
  };

  const artifactLocations = evidence.reduce<Record<string, string[]>>((acc, item) => {
    if (!acc[item.location]) acc[item.location] = [];
    acc[item.location].push(item.evidenceId);

    sourceTypes[item.sourceType].push(item.evidenceId);
    return acc;
  }, {});

  const timeline = [
    ...evidence.map((item) => ({
      timestamp: item.observedAt,
      event: `Evidence observed from ${item.sourceType}`,
      evidenceId: item.evidenceId,
    })),
    ...correlations.edges.map((edge) => ({
      timestamp: generatedAt,
      event: `Correlation ${edge.leftEvidenceId}<->${edge.rightEvidenceId}`,
    })),
  ].sort((left, right) => left.timestamp.localeCompare(right.timestamp));

  return {
    timeline,
    pivots: {
      entities: correlations.entityIndex,
      iocs: correlations.iocIndex,
      sourceTypes,
    },
    artifactLocations,
    exportBundle: {
      format: 'json',
      generatedAt,
      caseId: payload.caseId,
      report,
      signedManifest,
    },
  };
}

export default function runForensicAudit(payload: ForensicAuditRequest): ForensicAuditResult {
  const generatedAt = new Date().toISOString();
  const legalAssessment = assessLegalRequirements(payload);

  const canonicalEvidence = ingestFindings(payload, generatedAt);
  const correlations = correlateEvidence(canonicalEvidence);
  const detections = detectMaliciousActivity(canonicalEvidence, correlations);
  const integrity = createIntegrityPipeline(payload, canonicalEvidence, generatedAt);
  const report = createExplainableReport(payload.caseId, canonicalEvidence, detections, generatedAt);
  const workflow = buildWorkflowBundle(
    payload,
    canonicalEvidence,
    correlations,
    report,
    integrity.signedManifest,
    generatedAt,
  );

  return {
    legalAssessment,
    canonicalEvidence,
    correlations,
    detections,
    integrity,
    report,
    workflow,
  };
}

export * from './types';
