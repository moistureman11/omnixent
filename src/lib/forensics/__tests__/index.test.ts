process.env.FORENSIC_MANIFEST_SECRET = 'forensic-test-secret';
import runForensicAudit from '../index';
import { ForensicAuditRequest } from '../types';

function getPayload(): ForensicAuditRequest {
  return {
    caseId: 'case-001',
    title: 'Suspected coordinated intrusion',
    jurisdiction: 'US-FED',
    admissibilityStandards: ['FRE 901', 'Daubert'],
    retentionPolicyDays: 365,
    privacyScope: ['PII-minimized', 'court-approved'],
    analyst: 'unit-test-analyst',
    findings: [
      {
        id: 'nw-1',
        sourceType: 'network',
        observedAt: '2026-01-01T10:00:00.000Z',
        location: 'pcap://capture-1',
        content: 'Beacon observed from host to suspected C2 endpoint',
        iocs: ['bad-domain.example', '10.0.0.99'],
        entities: [
          { type: 'host', value: 'host-001' },
          { type: 'ip', value: '10.0.0.99' },
        ],
      },
      {
        id: 'app-1',
        sourceType: 'app',
        observedAt: '2026-01-01T10:05:00.000Z',
        location: 'app://telemetry/session-9',
        content: 'Unauthorized payload execution with exfiltration marker',
        iocs: ['bad-domain.example'],
        entities: [{ type: 'host', value: 'host-001' }],
      },
      {
        id: 'file-1',
        sourceType: 'file',
        observedAt: '2026-01-01T10:04:00.000Z',
        location: '/evidence/tmp/dropper.bin',
        content: 'Malware payload',
        iocs: ['sha256:deadbeef'],
        entities: [{ type: 'hash', value: 'deadbeef' }],
      },
    ],
  };
}

describe('forensic audit pipeline', () => {
  it('builds auditable, correlated evidence output', () => {
    const result = runForensicAudit(getPayload());

    expect(result.legalAssessment.isCompliant).toBeTruthy();
    expect(result.canonicalEvidence).toHaveLength(3);
    expect(result.canonicalEvidence[0].provenanceId).toContain('prov-');
    expect(result.correlations.edges.length).toBeGreaterThan(0);
    expect(result.correlations.iocIndex['bad-domain.example']).toContain('nw-1');
    expect(result.detections.some((detection) => detection.malicious)).toBeTruthy();
    expect(result.integrity.signedManifest.signature).toBeTruthy();
    expect(result.report.findings[0].reproducibleQueries.length).toBe(2);
    expect(result.workflow.timeline.length).toBeGreaterThan(0);
    expect(result.workflow.exportBundle.caseId).toBe('case-001');
  });

  it('flags legal requirement gaps when core legal scope is invalid', () => {
    const payload = getPayload();
    payload.retentionPolicyDays = 0;
    payload.admissibilityStandards = [];

    const result = runForensicAudit(payload);

    expect(result.legalAssessment.isCompliant).toBeFalsy();
    expect(result.legalAssessment.gaps).toContain('At least one admissibility standard is required.');
    expect(result.legalAssessment.gaps).toContain('Retention policy must be at least 1 day.');
  });
});
