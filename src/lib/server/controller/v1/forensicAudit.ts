import { Request, Response } from 'express';
import isAuthorized from '../../../auth';
import runForensicAudit, {
  ChainOfCustodyEvent,
  EvidenceEntity,
  ForensicAuditRequest,
  RawFinding,
  InvalidForensicDateError,
  MissingManifestSecretError,
} from '../../../forensics';

function isStringArray(input: unknown): input is string[] {
  return Array.isArray(input) && input.every((value) => typeof value === 'string');
}

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
const EVIDENCE_SOURCE_TYPES = new Set(['network', 'ble', 'radio', 'app', 'code', 'file']);
const UNSAFE_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_SHORT_TEXT_LENGTH = 256;
const MAX_LONG_TEXT_LENGTH = 5000;
const MAX_METADATA_KEYS = 128;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, maxLength = MAX_LONG_TEXT_LENGTH): value is string {
  return typeof value === 'string' && value.length <= maxLength;
}

function isNonEmptyBoundedString(value: unknown, maxLength = MAX_LONG_TEXT_LENGTH): value is string {
  return isBoundedString(value, maxLength) && value.trim().length > 0;
}

function isMetadataValue(value: unknown): value is string | number | boolean | null {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value);
}

function isValidEntity(entity: unknown): boolean {
  if (!isRecord(entity)) {
    return false;
  }

  return (
    isNonEmptyBoundedString(entity.type, MAX_SHORT_TEXT_LENGTH) &&
    isNonEmptyBoundedString(entity.value, MAX_LONG_TEXT_LENGTH)
  );
}

function isValidChainOfCustodyEvent(event: unknown): boolean {
  if (!isRecord(event)) {
    return false;
  }

  if (!isNonEmptyBoundedString(event.actor, MAX_SHORT_TEXT_LENGTH)) {
    return false;
  }

  if (!isNonEmptyBoundedString(event.action, MAX_SHORT_TEXT_LENGTH)) {
    return false;
  }

  if (!isNonEmptyBoundedString(event.timestamp, MAX_SHORT_TEXT_LENGTH) || !ISO_DATE_REGEX.test(event.timestamp)) {
    return false;
  }

  if (event.evidenceId !== undefined && !isBoundedString(event.evidenceId, MAX_SHORT_TEXT_LENGTH)) {
    return false;
  }

  if (event.notes !== undefined && !isBoundedString(event.notes, MAX_LONG_TEXT_LENGTH)) {
    return false;
  }

  return true;
}

function isValidFinding(finding: unknown): boolean {
  if (!isRecord(finding)) {
    return false;
  }

  if (!isNonEmptyBoundedString(finding.sourceType, MAX_SHORT_TEXT_LENGTH) || !EVIDENCE_SOURCE_TYPES.has(finding.sourceType)) {
    return false;
  }

  if (!isNonEmptyBoundedString(finding.observedAt, MAX_SHORT_TEXT_LENGTH) || !ISO_DATE_REGEX.test(finding.observedAt)) {
    return false;
  }

  if (finding.id !== undefined && !isBoundedString(finding.id, MAX_SHORT_TEXT_LENGTH)) {
    return false;
  }

  if (finding.location !== undefined && !isBoundedString(finding.location, MAX_LONG_TEXT_LENGTH)) {
    return false;
  }

  if (finding.content !== undefined && !isBoundedString(finding.content, MAX_LONG_TEXT_LENGTH)) {
    return false;
  }

  if (
    finding.metadata !== undefined &&
    (!isRecord(finding.metadata) ||
      Object.keys(finding.metadata).length > MAX_METADATA_KEYS ||
      Object.keys(finding.metadata).some((key) => !isBoundedString(key, MAX_SHORT_TEXT_LENGTH) || UNSAFE_OBJECT_KEYS.has(key)) ||
      !Object.values(finding.metadata).every((value) => isMetadataValue(value)))
  ) {
    return false;
  }

  if (
    finding.iocs !== undefined &&
    (!isStringArray(finding.iocs) || finding.iocs.some((ioc) => !isNonEmptyBoundedString(ioc, MAX_SHORT_TEXT_LENGTH)))
  ) {
    return false;
  }

  if (finding.entities !== undefined && (!Array.isArray(finding.entities) || !finding.entities.every(isValidEntity))) {
    return false;
  }

  return true;
}

function isValidRequestBody(body: ForensicAuditRequest): boolean {
  return (
    isNonEmptyBoundedString(body.caseId, MAX_SHORT_TEXT_LENGTH) &&
    (body.title === undefined || isBoundedString(body.title, MAX_LONG_TEXT_LENGTH)) &&
    isNonEmptyBoundedString(body.jurisdiction, MAX_SHORT_TEXT_LENGTH) &&
    isStringArray(body.admissibilityStandards) &&
    body.admissibilityStandards.every((standard) => isNonEmptyBoundedString(standard, MAX_SHORT_TEXT_LENGTH)) &&
    Number.isInteger(body.retentionPolicyDays) &&
    body.retentionPolicyDays > 0 &&
    body.retentionPolicyDays <= 36500 &&
    isStringArray(body.privacyScope) &&
    body.privacyScope.every((scope) => isNonEmptyBoundedString(scope, MAX_SHORT_TEXT_LENGTH)) &&
    isNonEmptyBoundedString(body.analyst, MAX_SHORT_TEXT_LENGTH) &&
    Array.isArray(body.findings) &&
    body.findings.length > 0 &&
    (body.chainOfCustody === undefined ||
      (Array.isArray(body.chainOfCustody) && body.chainOfCustody.every(isValidChainOfCustodyEvent))) &&
    body.findings.every(isValidFinding)
  );
}

function sanitizeString(value: string): string {
  return value.trim();
}

function sanitizeOptionalString(value: string | undefined): string | undefined {
  return value === undefined ? undefined : sanitizeString(value);
}

function sanitizeStringArray(values: string[]): string[] {
  const sanitized = values.map(sanitizeString).filter((value) => value.length > 0);
  return sanitized.filter((value, index) => sanitized.indexOf(value) === index);
}

function sanitizeMetadataValue(value: string | number | boolean | null): string | number | boolean | null {
  if (typeof value === 'string') {
    return sanitizeString(value);
  }

  return value;
}

function sanitizeMetadata(
  metadata: Record<string, string | number | boolean | null> | undefined,
): Record<string, string | number | boolean | null> | undefined {
  if (!metadata) {
    return undefined;
  }

  const sanitized: Record<string, string | number | boolean | null> = {};
  Object.keys(metadata).forEach((key) => {
    const normalizedKey = sanitizeString(key);
    if (!normalizedKey || UNSAFE_OBJECT_KEYS.has(normalizedKey)) {
      return;
    }

    sanitized[normalizedKey] = sanitizeMetadataValue(metadata[key]);
  });

  return sanitized;
}

function sanitizeEntities(entities: EvidenceEntity[] | undefined): EvidenceEntity[] | undefined {
  if (!entities) {
    return undefined;
  }

  return entities.map((entity) => ({
    type: sanitizeString(entity.type),
    value: sanitizeString(entity.value),
  }));
}

function sanitizeFindings(findings: RawFinding[]): RawFinding[] {
  return findings.map((finding) => ({
    ...finding,
    id: sanitizeOptionalString(finding.id),
    observedAt: sanitizeString(finding.observedAt),
    location: sanitizeOptionalString(finding.location),
    content: sanitizeOptionalString(finding.content),
    iocs: finding.iocs ? sanitizeStringArray(finding.iocs) : undefined,
    entities: sanitizeEntities(finding.entities),
    metadata: sanitizeMetadata(finding.metadata),
  }));
}

function sanitizeChainOfCustody(events: ChainOfCustodyEvent[] | undefined): ChainOfCustodyEvent[] | undefined {
  if (!events) {
    return undefined;
  }

  return events.map((event) => ({
    actor: sanitizeString(event.actor),
    action: sanitizeString(event.action),
    timestamp: sanitizeString(event.timestamp),
    evidenceId: sanitizeOptionalString(event.evidenceId),
    notes: sanitizeOptionalString(event.notes),
  }));
}

function sanitizePayload(payload: ForensicAuditRequest): ForensicAuditRequest {
  return {
    ...payload,
    caseId: sanitizeString(payload.caseId),
    title: sanitizeOptionalString(payload.title),
    jurisdiction: sanitizeString(payload.jurisdiction),
    admissibilityStandards: sanitizeStringArray(payload.admissibilityStandards),
    privacyScope: sanitizeStringArray(payload.privacyScope),
    analyst: sanitizeString(payload.analyst),
    findings: sanitizeFindings(payload.findings),
    chainOfCustody: sanitizeChainOfCustody(payload.chainOfCustody),
  };
}

export default function forensicAuditController(req: Request, res: Response) {
  const auth = req.header('x-omnixent-auth');

  try {
    if (!auth || !isAuthorized(auth)) {
      res.status(401).json({
        success: false,
        reason: 'Unauthorized',
      });
      return;
    }
  } catch (e) {
    res.status(401).json({
      success: false,
      reason: 'Unauthorized',
    });
    return;
  }

  const payload = req.body as ForensicAuditRequest;

  if (!payload || !isValidRequestBody(payload)) {
    res.status(422).json({
      success: false,
      reason: 'Invalid audit payload',
    });
    return;
  }

  try {
    const result = runForensicAudit(sanitizePayload(payload));
    res.status(200).json({
      success: true,
      result,
    });
  } catch (e) {
    if (e instanceof InvalidForensicDateError) {
      res.status(422).json({
        success: false,
        reason: 'Invalid audit payload',
      });
      return;
    }

    if (e instanceof MissingManifestSecretError) {
      console.error('Forensic audit configuration error', e);
      res.status(500).json({
        success: false,
        reason: 'Forensic audit service misconfigured',
      });
      return;
    }

    console.error('Unable to process forensic audit request', e);
    res.status(500).json({
      success: false,
      reason: 'Unable to process forensic audit request',
    });
  }
}
