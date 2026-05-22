import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import supertest from 'supertest';
import server from '../../lib/server';

const app = server();

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'omnixent-e2e-organizer-'));
}

describe('Testing organizer routes', () => {
  it('Should reply with a 400 status when path is missing', async () => {
    const res = await supertest(app).post('/v1/organizer').send({});

    expect(res.status).toBe(400);
    expect(res.body.success).toBeFalsy();
    expect(res.body).toHaveProperty('reason');
  });

  it('Should reply with a 400 status when path does not exist', async () => {
    const res = await supertest(app)
      .post('/v1/organizer')
      .send({ path: '/non/existent/path' });

    expect(res.status).toBe(400);
    expect(res.body.success).toBeFalsy();
    expect(res.body).toHaveProperty('reason');
  });

  it('Should reply with a 200 status and organize files', async () => {
    const tmpDir = createTempDir();
    fs.writeFileSync(path.join(tmpDir, 'photo.jpg'), '');
    fs.writeFileSync(path.join(tmpDir, 'app.js'), '');

    const res = await supertest(app).post('/v1/organizer').send({ path: tmpDir });

    expect(res.status).toBe(200);
    expect(res.body.success).toBeTruthy();
    expect(res.body).toHaveProperty('result');
    expect(res.body.result).toHaveProperty('organized');
    expect(res.body.result).toHaveProperty('skipped');

    expect(fs.existsSync(path.join(tmpDir, 'images', 'photo.jpg'))).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, 'scripts', 'app.js'))).toBe(true);

    fs.rmSync(tmpDir, { recursive: true });
  });
});
