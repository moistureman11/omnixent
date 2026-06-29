process.env.FORENSIC_MANIFEST_SECRET = 'forensic-test-secret';
import supertest from 'supertest';
import server from '../../lib/server';

const app = server();

const validPayload = {
  caseId: 'case-e2e-1',
  jurisdiction: 'US-NY',
  admissibilityStandards: ['FRE 901'],
  retentionPolicyDays: 180,
  privacyScope: ['limited-to-court-order'],
  analyst: 'e2e-analyst',
  findings: [
    {
      sourceType: 'network',
      observedAt: '2026-01-01T10:00:00.000Z',
      content: 'beacon to c2',
      iocs: ['test-ioc.local'],
      entities: [{ type: 'host', value: 'host-1' }],
    },
  ],
};

describe('Testing forensic audit route', () => {
  it('Should reject unauthorized forensic audit requests', async () => {
    const res = await supertest(app).post('/v1/private/audit').send(validPayload);

    expect(res.status).toBe(401);
    expect(res.body.success).toBeFalsy();
  });

  it('Should run forensic audit with valid auth and payload', async () => {
    const res = await supertest(app)
      .post('/v1/private/audit')
      .set('x-omnixent-auth', 'JHgjQporKoi9rCD1wqkNNAirVBzRod')
      .send(validPayload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBeTruthy();
    expect(res.body.result).toHaveProperty('legalAssessment');
    expect(res.body.result).toHaveProperty('canonicalEvidence');
    expect(res.body.result).toHaveProperty('correlations');
    expect(res.body.result).toHaveProperty('report');
    expect(res.body.result).toHaveProperty('workflow');
  });

  it('Should fail with malformed payload', async () => {
    const res = await supertest(app)
      .post('/v1/private/audit')
      .set('x-omnixent-auth', 'JHgjQporKoi9rCD1wqkNNAirVBzRod')
      .send({ caseId: 'bad-payload' });

    expect(res.status).toBe(422);
    expect(res.body.success).toBeFalsy();
  });

  it('Should fail when findings have invalid shape', async () => {
    const invalidFindingPayload = {
      ...validPayload,
      findings: [
        {
          observedAt: '2026-01-01T10:00:00.000Z',
          content: 'missing source type',
        },
      ],
    };

    const res = await supertest(app)
      .post('/v1/private/audit')
      .set('x-omnixent-auth', 'JHgjQporKoi9rCD1wqkNNAirVBzRod')
      .send(invalidFindingPayload);

    expect(res.status).toBe(422);
    expect(res.body.success).toBeFalsy();
    expect(res.body.reason).toBe('Invalid audit payload');
  });

  it('Should fail when chain of custody entries are invalid', async () => {
    const invalidChainPayload = {
      ...validPayload,
      chainOfCustody: [
        {
          actor: 'analyst',
          action: 'REVIEWED',
          timestamp: '2026-01-01 10:00:00',
        },
      ],
    };

    const res = await supertest(app)
      .post('/v1/private/audit')
      .set('x-omnixent-auth', 'JHgjQporKoi9rCD1wqkNNAirVBzRod')
      .send(invalidChainPayload);

    expect(res.status).toBe(422);
    expect(res.body.success).toBeFalsy();
    expect(res.body.reason).toBe('Invalid audit payload');
  });

  it('Should sanitize accepted forensic payload values', async () => {
    const sanitizedPayload = {
      ...validPayload,
      caseId: '  case-e2e-sanitize  ',
      analyst: '  e2e-analyst  ',
      findings: [
        {
          ...validPayload.findings[0],
          content: '   beacon to c2   ',
          iocs: [' Test-Ioc.local ', 'test-ioc.local'],
          metadata: {
            protocol: ' https ',
            __proto__: 'blocked',
          },
        },
      ],
    };

    const res = await supertest(app)
      .post('/v1/private/audit')
      .set('x-omnixent-auth', 'JHgjQporKoi9rCD1wqkNNAirVBzRod')
      .send(sanitizedPayload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBeTruthy();
    expect(res.body.result.report.caseId).toBe('case-e2e-sanitize');
    expect(res.body.result.integrity.chainOfCustody[0].actor).toBe('e2e-analyst');
    expect(res.body.result.canonicalEvidence[0].iocs).toEqual(['test-ioc.local']);
    expect(res.body.result.canonicalEvidence[0].metadata.protocol).toBe('https');
    expect(Object.prototype.hasOwnProperty.call(res.body.result.canonicalEvidence[0].metadata, '__proto__')).toBeFalsy();
  });

  it('Should fail with misconfiguration when manifest secret is missing', async () => {
    const previousSecret = process.env.FORENSIC_MANIFEST_SECRET;
    delete process.env.FORENSIC_MANIFEST_SECRET;

    try {
      const res = await supertest(app)
        .post('/v1/private/audit')
        .set('x-omnixent-auth', 'JHgjQporKoi9rCD1wqkNNAirVBzRod')
        .send(validPayload);

      expect(res.status).toBe(500);
      expect(res.body.success).toBeFalsy();
      expect(res.body.reason).toBe('Forensic audit service misconfigured');
    } finally {
      process.env.FORENSIC_MANIFEST_SECRET = previousSecret;
    }
  });
});
