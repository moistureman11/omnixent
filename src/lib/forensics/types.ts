export type EvidenceSourceType = 'network' | 'ble' | 'radio' | 'app' | 'code' | 'file';

export interface EvidenceEntity {
  type: string;
  value: string;
}

export interface RawFinding {
  id?: string;
  sourceType: EvidenceSourceType;
  observedAt: string;
  location?: string;
  content?: string;
  metadata?: Record<string, string | number | boolean | null>;
  iocs?: string[];
  entities?: EvidenceEntity[];
}

export interface ChainOfCustodyEvent {
  actor: string;
  action: string;
  timestamp: string;
  evidenceId?: string;
  notes?: string;
}

export interface ForensicAuditRequest {
  caseId: string;
  title?: string;
  jurisdiction: string;
  admissibilityStandards: string[];
  retentionPolicyDays: number;
  privacyScope: string[];
  analyst: string;
  findings: RawFinding[];
  chainOfCustody?: ChainOfCustodyEvent[];
}

export interface CanonicalEvidence {
  evidenceId: string;
  provenanceId: string;
  sourceType: EvidenceSourceType;
  observedAt: string;
  ingestedAt: string;
  location: string;
  contentPreview: string;
  metadata: Record<string, string | number | boolean | null>;
  iocs: string[];
  entities: EvidenceEntity[];
  integrity: {
    hashAlgorithm: 'sha256';
    hash: string;
  };
}

export interface LegalAssessment {
  requirements: string[];
  gaps: string[];
  isCompliant: boolean;
}

export interface CorrelationEdge {
  leftEvidenceId: string;
  rightEvidenceId: string;
  reason: string;
  confidence: number;
}

export interface CorrelationResult {
  timeWindowMinutes: number;
  edges: CorrelationEdge[];
  entityIndex: Record<string, string[]>;
  iocIndex: Record<string, string[]>;
  anomalyLinks: string[];
}

export interface DetectionResult {
  evidenceId: string;
  indicators: string[];
  ruleScore: number;
  heuristicScore: number;
  modelScore: number;
  confidence: number;
  malicious: boolean;
}

export interface SignedManifest {
  algorithm: 'sha256-hmac';
  generatedAt: string;
  caseId: string;
  evidenceHashes: Record<string, string>;
  signature: string;
}

export interface IntegrityResult {
  signedManifest: SignedManifest;
  immutableEvidence: ReadonlyArray<CanonicalEvidence>;
  chainOfCustody: ReadonlyArray<ChainOfCustodyEvent>;
}

export interface ExplainableFinding {
  evidenceId: string;
  malicious: boolean;
  confidence: number;
  rationale: string[];
  rawEvidenceRefs: string[];
  reproducibleQueries: string[];
}

export interface ExplainableReport {
  generatedAt: string;
  caseId: string;
  summary: {
    totalEvidence: number;
    maliciousFindings: number;
    highConfidenceFindings: number;
  };
  findings: ExplainableFinding[];
}

export interface WorkflowBundle {
  timeline: Array<{ timestamp: string; event: string; evidenceId?: string }>;
  pivots: {
    entities: Record<string, string[]>;
    iocs: Record<string, string[]>;
    sourceTypes: Record<EvidenceSourceType, string[]>;
  };
  artifactLocations: Record<string, string[]>;
  exportBundle: {
    format: 'json';
    generatedAt: string;
    caseId: string;
    report: ExplainableReport;
    signedManifest: SignedManifest;
  };
}

export interface ForensicAuditResult {
  legalAssessment: LegalAssessment;
  canonicalEvidence: CanonicalEvidence[];
  correlations: CorrelationResult;
  detections: DetectionResult[];
  integrity: IntegrityResult;
  report: ExplainableReport;
  workflow: WorkflowBundle;
}
