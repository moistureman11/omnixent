import { Request, Response } from 'express';
import isAuthorized from '../../../auth';
import runForensicAudit, {
  ForensicAuditRequest,
  InvalidForensicDateError,
  MissingManifestSecretError,
} from '../../../forensics';

function isStringArray(input: unknown): input is string[] {
  return Array.isArray(input) && input.every((value) => typeof value === 'string');
}

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
const EVIDENCE_SOURCE_TYPES = new Set(['network', 'ble', 'radio', 'app', 'code', 'file']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isMetadataValue(value: unknown): value is string | number | boolean | null {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value);
}

function isValidEntity(entity: unknown): boolean {
  if (!isRecord(entity)) {
    return false;
  }

  return typeof entity.type === 'string' && typeof entity.value === 'string';
}

function isValidFinding(finding: unknown): boolean {
  if (!isRecord(finding)) {
    return false;
  }

  if (typeof finding.sourceType !== 'string' || !EVIDENCE_SOURCE_TYPES.has(finding.sourceType)) {
    return false;
  }

  if (typeof finding.observedAt !== 'string' || !ISO_DATE_REGEX.test(finding.observedAt)) {
    return false;
  }

  if (finding.id !== undefined && typeof finding.id !== 'string') {
    return false;
  }

  if (finding.location !== undefined && typeof finding.location !== 'string') {
    return false;
  }

  if (finding.content !== undefined && typeof finding.content !== 'string') {
    return false;
  }

  if (
    finding.metadata !== undefined &&
    (!isRecord(finding.metadata) || !Object.values(finding.metadata).every((value) => isMetadataValue(value)))
  ) {
    return false;
  }

  if (finding.iocs !== undefined && !isStringArray(finding.iocs)) {
    return false;
  }

  if (finding.entities !== undefined && (!Array.isArray(finding.entities) || !finding.entities.every(isValidEntity))) {
    return false;
  }

  return true;
}

function isValidRequestBody(body: ForensicAuditRequest): boolean {
  return (
    typeof body.caseId === 'string' &&
    typeof body.jurisdiction === 'string' &&
    isStringArray(body.admissibilityStandards) &&
    Number.isFinite(body.retentionPolicyDays) &&
    isStringArray(body.privacyScope) &&
    typeof body.analyst === 'string' &&
    Array.isArray(body.findings) &&
    body.findings.every(isValidFinding)
  );
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
    const result = runForensicAudit(payload);
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
