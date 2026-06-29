import { Request, Response } from 'express';
import isAuthorized from '../../../auth';
import runForensicAudit, { ForensicAuditRequest } from '../../../forensics';

function isStringArray(input: unknown): input is string[] {
  return Array.isArray(input) && input.every((value) => typeof value === 'string');
}

function isValidRequestBody(body: ForensicAuditRequest): boolean {
  return (
    typeof body.caseId === 'string' &&
    typeof body.jurisdiction === 'string' &&
    isStringArray(body.admissibilityStandards) &&
    typeof body.retentionPolicyDays === 'number' &&
    isStringArray(body.privacyScope) &&
    typeof body.analyst === 'string' &&
    Array.isArray(body.findings)
  );
}

export default async function forensicAuditController(req: Request, res: Response) {
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
    console.log(e);
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
    console.log(e);
    res.status(500).json({
      success: false,
      reason: 'Unable to process forensic audit request',
    });
  }
}
