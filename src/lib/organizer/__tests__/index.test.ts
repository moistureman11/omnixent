import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { getScriptType, organizeByScriptType } from '../';

describe('getScriptType', () => {
  test('returns extension without the leading dot', () => {
    expect(getScriptType('file.ts')).toBe('ts');
    expect(getScriptType('file.js')).toBe('js');
    expect(getScriptType('file.json')).toBe('json');
    expect(getScriptType('file.md')).toBe('md');
  });

  test('returns no_extension for files without an extension', () => {
    expect(getScriptType('Makefile')).toBe('no_extension');
    expect(getScriptType('Dockerfile')).toBe('no_extension');
  });
});

describe('organizeByScriptType', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'organizer-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('groups files by script type and creates directories', () => {
    fs.writeFileSync(path.join(tmpDir, 'app.ts'), '');
    fs.writeFileSync(path.join(tmpDir, 'server.ts'), '');
    fs.writeFileSync(path.join(tmpDir, 'config.json'), '');
    fs.writeFileSync(path.join(tmpDir, 'README.md'), '');

    const result = organizeByScriptType(tmpDir);

    expect(result).toMatchSnapshot();

    expect(result['ts']).toEqual(expect.arrayContaining(['app.ts', 'server.ts']));
    expect(result['json']).toEqual(['config.json']);
    expect(result['md']).toEqual(['README.md']);
  });

  test('creates a subdirectory for each script type', () => {
    fs.writeFileSync(path.join(tmpDir, 'index.ts'), '');
    fs.writeFileSync(path.join(tmpDir, 'utils.js'), '');

    organizeByScriptType(tmpDir);

    expect(fs.existsSync(path.join(tmpDir, 'ts'))).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, 'js'))).toBe(true);
  });

  test('throws on a non-existent directory', () => {
    expect(() => organizeByScriptType('/tmp/this-path-does-not-exist-abc123')).toThrow(
      'Not a valid directory',
    );
  });

  test('throws when path points to a file, not a directory', () => {
    const tmpFile = path.join(tmpDir, 'just-a-file.txt');
    fs.writeFileSync(tmpFile, '');
    expect(() => organizeByScriptType(tmpFile)).toThrow('Not a valid directory');
  });

  test('handles an empty directory', () => {
    const result = organizeByScriptType(tmpDir);
    expect(result).toEqual({});
  });

  test('handles files with no extension', () => {
    fs.writeFileSync(path.join(tmpDir, 'Makefile'), '');

    const result = organizeByScriptType(tmpDir);

    expect(result['no_extension']).toEqual(['Makefile']);
    expect(fs.existsSync(path.join(tmpDir, 'no_extension'))).toBe(true);
  });
});
